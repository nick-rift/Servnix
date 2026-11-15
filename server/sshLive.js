'use strict';

/**
 * sshLive.js - Echtzeit-Auswertung der SSH-Logs fuer das Dashboard.
 *
 * Liest ECHTE Logzeilen (journalctl, Fallback /var/log/auth.log bzw. /var/log/secure)
 * und wandelt sie in strukturierte Ereignisse um:
 *   - accepted : erfolgreicher Login (publickey/password), inkl. Benutzer + IP
 *   - failed   : fehlgeschlagener Login-Versuch
 *   - invalid  : Login-Versuch mit nicht existierendem Benutzer
 *   - closed   : Verbindung ohne Login beendet (Pre-Auth, haeufig Scanner)
 *
 * Zusaetzlich:
 *   - aktive SSH-Sitzungen ueber `who`
 *   - optionale Geolokalisierung oeffentlicher IPs ueber ip-api.com
 *     (abschaltbar mit GEO_LOOKUP=false, Ergebnisse werden gecacht)
 *
 * Keine Demo-/Beispieldaten: ohne lesbare Logquelle liefert das Modul leere
 * Listen und eine Warnung in `source`.
 */

const net = require('net');
const https = require('https');
const http = require('http');
const { run } = require('./exec');

const AUTH_LOG_CANDIDATES = ['/var/log/auth.log', '/var/log/secure'];
const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

function normalizeIp(ip) {
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip || '');
  return m ? m[1] : ip;
}

function isPrivateIp(ip) {
  if (!net.isIP(ip)) return true;
  if (net.isIP(ip) === 6) return /^(::1$|fe80:|fc|fd)/i.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return (
    a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) || a === 0
  );
}

/* ---------- Zeitstempel ---------- */

function parseTimestamp(line, now = new Date()) {
  let m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))/.exec(line);
  if (m) {
    const t = Date.parse(m[1]);
    return Number.isNaN(t) ? null : t;
  }
  m = /^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})/.exec(line);
  if (m && MONTHS[m[1]] !== undefined) {
    const d = new Date(now.getFullYear(), MONTHS[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
    if (d.getTime() > now.getTime() + 86400000) d.setFullYear(now.getFullYear() - 1);
    return d.getTime();
  }
  return null;
}

/* ---------- Zeilen -> Ereignisse ---------- */

const RE_ACCEPTED = /Accepted (\S+) for (\S+) from (\S+) port (\d+)/;
const RE_FAILED = /Failed (\S+) for (?:invalid user )?(\S+) from (\S+) port (\d+)/;
const RE_INVALID = /Invalid user (\S*) from (\S+) port (\d+)/;
const RE_CLOSED = /(?:Connection closed by|Disconnected from) (?:(?:invalid|authenticating) user (\S+) )?(\S+) port (\d+)(?: \[preauth\])?/;
const RE_MAXAUTH = /maximum authentication attempts exceeded for (?:invalid user )?(\S+) from (\S+) port (\d+)/;

function parseLine(line, now) {
  const ts = parseTimestamp(line, now);
  if (ts === null) return null;
  let m;
  if ((m = RE_ACCEPTED.exec(line))) {
    return { ts, type: 'accepted', method: m[1], user: m[2], ip: normalizeIp(m[3]), port: Number(m[4]) };
  }
  if ((m = RE_MAXAUTH.exec(line))) {
    return { ts, type: 'failed', method: 'max-auth', user: m[1], ip: normalizeIp(m[2]), port: Number(m[3]) };
  }
  if ((m = RE_FAILED.exec(line))) {
    return { ts, type: 'failed', method: m[1], user: m[2], ip: normalizeIp(m[3]), port: Number(m[4]) };
  }
  if ((m = RE_INVALID.exec(line))) {
    return { ts, type: 'invalid', method: null, user: m[1] || '(leer)', ip: normalizeIp(m[2]), port: Number(m[3]) };
  }
  if ((m = RE_CLOSED.exec(line))) {
    // Nur Pre-Auth-Abbrueche zaehlen; normale Logouts sind kein Sicherheitsereignis.
    if (!/preauth|invalid|authenticating/.test(line)) return null;
    return { ts, type: 'closed', method: null, user: m[1] || null, ip: normalizeIp(m[2]), port: Number(m[3]) };
  }
  return null;
}

function parseLines(lines, now = new Date()) {
  const events = [];
  for (const line of lines) {
    const ev = parseLine(line, now);
    if (ev && net.isIP(ev.ip)) events.push(ev);
  }
  return events;
}

/* ---------- Logquellen ---------- */

function journalUsable(res) {
  if (!res.ok) return false;
  return !/not seeing messages from other users|No journal files were opened/i.test(res.stderr || '');
}

/**
 * Liefert rohe SSH-Logzeilen der letzten `minutes` Minuten.
 * Mit -o short-iso bekommen wir pro Zeile einen RFC3339-Zeitstempel.
 */
async function collectLines(minutes) {
  const journal = await run('journalctl', [
    '-q', '--no-pager', '-o', 'short-iso',
    '-t', 'sshd', '-t', 'sshd-session',
    '--since', `-${minutes}min`,
  ], { timeout: 15000 });
  const journalOk = journalUsable(journal);
  if (journalOk && journal.stdout.trim()) {
    return { lines: journal.stdout.split('\n'), source: 'journalctl' };
  }
  // Journal leer oder nicht lesbar (z. B. rsyslog-only-Systeme, Container):
  // klassische Logdateien probieren.
  for (const file of AUTH_LOG_CANDIDATES) {
    const res = await run('tail', ['-n', '50000', file]);
    if (res.ok) return { lines: res.stdout.split('\n'), source: file };
  }
  if (journalOk) return { lines: [], source: 'journalctl' };
  return { lines: [], source: 'none', warning: `Keine SSH-Logquelle lesbar (journalctl, ${AUTH_LOG_CANDIDATES.join(', ')}) - Dashboard-Benutzer in die Gruppe "adm"/"systemd-journal" aufnehmen.` };
}

/**
 * Ereignisse der letzten `minutes` Minuten, neueste zuerst.
 */
async function readEvents(minutes = 1440, limit = 500) {
  const { lines, source, warning } = await collectLines(minutes);
  const cutoff = Date.now() - minutes * 60000;
  const events = parseLines(lines)
    .filter((e) => e.ts >= cutoff)
    .sort((a, b) => b.ts - a.ts)
    .slice(0, limit);
  return { events, source, warning: warning || null };
}

/* ---------- Statistik ---------- */

function buildStats(events, now = Date.now()) {
  const counts = { accepted: 0, failed: 0, invalid: 0, closed: 0 };
  const byIp = {};
  const byUser = {};
  const hours = new Array(24).fill(0).map(() => ({ failed: 0, accepted: 0 }));
  const hourStart = now - 23 * 3600000;
  const uniqueIps = new Set();

  for (const e of events) {
    counts[e.type] = (counts[e.type] || 0) + 1;
    uniqueIps.add(e.ip);
    if (e.type !== 'accepted') {
      const ipEntry = byIp[e.ip] || (byIp[e.ip] = { ip: e.ip, attempts: 0, users: new Set(), last: 0, first: Infinity });
      ipEntry.attempts++;
      if (e.user) ipEntry.users.add(e.user);
      ipEntry.last = Math.max(ipEntry.last, e.ts);
      ipEntry.first = Math.min(ipEntry.first, e.ts);
      if (e.user) byUser[e.user] = (byUser[e.user] || 0) + 1;
    }
    const idx = Math.floor((e.ts - hourStart) / 3600000);
    if (idx >= 0 && idx < 24) {
      if (e.type === 'accepted') hours[idx].accepted++;
      else hours[idx].failed++;
    }
  }

  const topIps = Object.values(byIp)
    .map((x) => ({ ...x, users: [...x.users].slice(0, 8), userCount: x.users.size }))
    .sort((a, b) => b.attempts - a.attempts)
    .slice(0, 15);
  const topUsers = Object.entries(byUser)
    .map(([user, n]) => ({ user, attempts: n }))
    .sort((a, b) => b.attempts - a.attempts)
    .slice(0, 10);

  return {
    counts,
    uniqueIps: uniqueIps.size,
    topIps,
    topUsers,
    timeline: hours.map((h, i) => ({ hourStart: hourStart + i * 3600000, ...h })),
  };
}

/* ---------- Aktive Sitzungen ---------- */

async function activeSessions() {
  const res = await run('who', []);
  if (!res.ok) return { available: false, sessions: [] };
  const sessions = res.stdout
    .split('\n')
    .filter(Boolean)
    .map((l) => {
      // user  pts/0  2026-11-15 13:02 (203.0.113.5)
      const m = /^(\S+)\s+(\S+)\s+(\S+ \S+)\s*(?:\(([^)]+)\))?/.exec(l);
      if (!m) return null;
      return { user: m[1], tty: m[2], since: m[3], from: normalizeIp(m[4] || 'lokal') };
    })
    .filter(Boolean);
  return { available: true, sessions };
}

/* ---------- Geolokalisierung (optional, gecacht) ---------- */

const geoCache = new Map();
const GEO_TTL = 6 * 3600000;

function geoEnabled() {
  return (process.env.GEO_LOOKUP || 'true').toLowerCase() !== 'false';
}

function fetchJson(url, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch (e) {
          reject(e);
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
  });
}

/**
 * Lookup fuer bis zu 100 IPs auf einmal (ip-api.com Batch, kostenlos, nur HTTP).
 * Private IPs werden nie nach aussen geschickt.
 */
async function geoLookup(ips) {
  const result = {};
  if (!geoEnabled()) return result;
  const now = Date.now();
  const missing = [];
  for (const ip of new Set(ips)) {
    if (isPrivateIp(ip)) {
      result[ip] = { country: 'Privat/LAN', countryCode: null, city: null, org: null };
      continue;
    }
    const cached = geoCache.get(ip);
    if (cached && now - cached.at < GEO_TTL) result[ip] = cached.data;
    else missing.push(ip);
  }
  if (missing.length === 0) return result;
  try {
    const batch = missing.slice(0, 100);
    const res = await new Promise((resolve, reject) => {
      const payload = JSON.stringify(batch.map((q) => ({ query: q, fields: 'query,status,country,countryCode,city,org,as,lat,lon' })));
      const req = http.request(
        { host: 'ip-api.com', path: '/batch', method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }, timeout: 6000 },
        (r) => {
          let body = '';
          r.on('data', (c) => (body += c));
          r.on('end', () => {
            try {
              resolve(JSON.parse(body));
            } catch (e) {
              reject(e);
            }
          });
        },
      );
      req.on('timeout', () => req.destroy(new Error('timeout')));
      req.on('error', reject);
      req.write(payload);
      req.end();
    });
    if (Array.isArray(res)) {
      for (const r of res) {
        const data =
          r.status === 'success'
            ? { country: r.country, countryCode: r.countryCode, city: r.city, org: r.org || r.as, lat: r.lat, lon: r.lon }
            : { country: null, countryCode: null, city: null, org: null };
        geoCache.set(r.query, { at: now, data });
        result[r.query] = data;
      }
    }
  } catch {
    /* Netzwerk nicht erreichbar oder Rate-Limit: Frontend zeigt dann einfach "–" */
  }
  return result;
}

/* ---------- Kurzer System-Puls fuer den Live-Stream ---------- */

const os = require('os');

function pulse() {
  const load = os.loadavg();
  return {
    load1: Number(load[0].toFixed(2)),
    load5: Number(load[1].toFixed(2)),
    cpus: os.cpus().length,
    memUsedPct: Math.round(((os.totalmem() - os.freemem()) / os.totalmem()) * 100),
    uptimeSec: Math.round(os.uptime()),
    hostname: os.hostname(),
  };
}

module.exports = {
  readEvents,
  buildStats,
  activeSessions,
  geoLookup,
  geoEnabled,
  pulse,
  isPrivateIp,
  // fuer Tests
  parseLine,
  parseLines,
  fetchJson,
};
