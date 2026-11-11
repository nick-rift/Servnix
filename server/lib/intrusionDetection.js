'use strict';

/**
 * intrusionDetection.js - regelbasierte Angriffserkennung ("Servnix Guard").
 *
 * Wichtig fuer Ehrlichkeit: Das ist KEINE KI/ML-Anomalieerkennung, sondern
 * transparente, nachvollziehbare Schwellenwert-Regeln auf echten Log-Daten:
 *   - SSH-Bruteforce: X fehlgeschlagene Logins von derselben IP in Y Minuten
 *     (ausgelesen aus journalctl, auth.log/secure als Fallback)
 *   - Portscan: X verschiedene Ports von derselben IP in Y Minuten angefragt,
 *     die NICHT auf der Allow-Liste stehen (ausgelesen aus dem nftables-Log,
 *     das scripts/servnix-firewall.sh fuer genau diesen Zweck schreibt)
 * Jede Regel/Schwelle ist hier im Code sichtbar und per .env einstellbar.
 *
 * Ebenfalls Teil der Ehrlichkeit: Wenn keine Logquelle lesbar ist (z. B. ohne
 * Root/adm-Gruppe), wird das in `warnings`/`sources` gemeldet, statt stumm
 * "keine Bedrohung" zu liefern.
 */

const net = require('net');
const { run } = require('./exec');

const SCAN_TAG = 'servnix-scan-attempt';
const AUTH_LOG_CANDIDATES = ['/var/log/auth.log', '/var/log/secure'];
const AUTH_LOG_TAIL_LINES = 20000;

function getEnvInt(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

/* ---------- IP-Hilfsfunktionen (IPv4 + IPv6, CIDR) ---------- */

/** "::ffff:1.2.3.4" -> "1.2.3.4", sonst unveraendert. */
function normalizeIp(ip) {
  const m = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(ip);
  return m ? m[1] : ip;
}

function expandIpv6(ip) {
  let s = ip;
  const v4 = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (v4) {
    const o = v4[1].split('.').map(Number);
    s = s.slice(0, -v4[1].length) + ((o[0] << 8) | o[1]).toString(16) + ':' + ((o[2] << 8) | o[3]).toString(16);
  }
  const [headStr, tailStr] = s.split('::');
  const head = headStr ? headStr.split(':') : [];
  const tail = tailStr ? tailStr.split(':') : [];
  const fill = s.includes('::') ? new Array(8 - head.length - tail.length).fill('0') : [];
  return [...head, ...fill, ...tail];
}

function ipToBigInt(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) {
    return { bits: 32, value: ip.split('.').reduce((acc, o) => (acc << 8n) + BigInt(o), 0n) };
  }
  if (fam === 6) {
    return { bits: 128, value: expandIpv6(ip).reduce((acc, h) => (acc << 16n) + BigInt(parseInt(h, 16)), 0n) };
  }
  return null;
}

/** Prueft, ob `ip` einem Allowlist-Eintrag entspricht (einzelne IP oder CIDR). */
function ipMatches(ip, entry) {
  const [base, prefixStr] = entry.split('/');
  const a = ipToBigInt(normalizeIp(ip));
  const b = ipToBigInt(normalizeIp(base));
  if (!a || !b || a.bits !== b.bits) return false;
  const prefix = prefixStr === undefined ? a.bits : Number(prefixStr);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > a.bits) return false;
  const shift = BigInt(a.bits - prefix);
  return a.value >> shift === b.value >> shift;
}

function getAllowlist(warnings = []) {
  return (process.env.GUARD_ALLOWLIST || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .filter((entry) => {
      const [base, prefix] = entry.split('/');
      const ok = net.isIP(base) && (prefix === undefined || /^\d{1,3}$/.test(prefix));
      if (!ok) warnings.push(`Allowlist-Eintrag "${entry}" ignoriert (keine gueltige IP/CIDR)`);
      return ok;
    });
}

function isAllowed(ip, allowlist) {
  return allowlist.some((entry) => ipMatches(ip, entry));
}

/* ---------- Zeitstempel & Zeitfenster ---------- */

const MONTHS = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };

/** Syslog-Zeilen: RFC3339 ("2026-11-11T14:23:01.123+01:00") oder klassisch ("Nov 11 14:23:01", ohne Jahr). */
function parseSyslogTimestamp(line, now) {
  let m = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2}))/.exec(line);
  if (m) {
    const t = Date.parse(m[1]);
    return Number.isNaN(t) ? null : t;
  }
  m = /^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2})/.exec(line);
  if (m && MONTHS[m[1]] !== undefined) {
    const d = new Date(now.getFullYear(), MONTHS[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5]));
    // Kein Jahr im Log: liegt das Datum "in der Zukunft", stammt es aus dem Vorjahr (Jahreswechsel).
    if (d.getTime() > now.getTime() + 86400000) d.setFullYear(now.getFullYear() - 1);
    return d.getTime();
  }
  return null;
}

/** dmesg -T: "[Wed Nov 11 14:23:01 2026] ..." */
function parseDmesgTimestamp(line) {
  const m = /^\[\w{3} (\w{3}) +(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\d{4})\]/.exec(line);
  if (!m || MONTHS[m[1]] === undefined) return null;
  return new Date(Number(m[6]), MONTHS[m[1]], Number(m[2]), Number(m[3]), Number(m[4]), Number(m[5])).getTime();
}

/**
 * Behaelt nur Zeilen innerhalb des Zeitfensters. Zeilen ohne lesbaren Zeitstempel
 * werden NICHT gezaehlt (lieber eine Warnung als eine Sperre auf Basis alter Daten).
 */
function filterByWindow(lines, windowMinutes, parseTs, now = new Date()) {
  const cutoff = now.getTime() - windowMinutes * 60000;
  const kept = [];
  let skipped = 0;
  for (const line of lines) {
    if (!line) continue;
    const ts = parseTs(line, now);
    if (ts === null) {
      skipped++;
      continue;
    }
    if (ts >= cutoff) kept.push(line);
  }
  return { kept, skipped };
}

/** journalctl meldet fehlende Rechte nicht per Exit-Code, sondern mit leerem stdout + Hinweis auf stderr. */
function journalUsable(res) {
  if (!res.ok) return false;
  return !/not seeing messages from other users|No journal files were opened/i.test(res.stderr || '');
}

function newContext() {
  return { warnings: [], sources: { ssh: 'none', portscan: 'none' } };
}

/* ---------- SSH-Bruteforce ---------- */

// Harte Fehlversuche: jeder einzelne zaehlt.
const HARD_FAIL = /Failed (?:password|keyboard-interactive(?:\/pam)?|none) for .* (\S+) port (\d+)/;
// Weiche Indizien: zaehlen nur einmal pro Verbindung und nur, wenn die Verbindung
// keinen harten Fehlversuch hatte (verhindert Doppelzaehlung von
// "Invalid user X" + "Failed password for invalid user X").
const SOFT_FAIL =
  /(?:Invalid user .* from|Connection closed by (?:invalid|authenticating) user .*|Disconnected from (?:invalid|authenticating) user .*|maximum authentication attempts exceeded for .* from) (\S+) port (\d+)/;

async function collectSshLines(windowMinutes, ctx) {
  // -t (Syslog-Identifier) statt -u: deckt ssh.service, sshd.service und den
  // seit OpenSSH 9.8 getrennten Prozess "sshd-session" ab.
  const journal = await run('journalctl', [
    '-q', '--no-pager', '-o', 'cat',
    '-t', 'sshd', '-t', 'sshd-session',
    '--since', `-${windowMinutes}min`,
  ]);
  if (journalUsable(journal)) {
    ctx.sources.ssh = 'journalctl';
    return journal.stdout.split('\n');
  }
  if (journal.ok) ctx.warnings.push('journalctl liefert ohne Root/adm-Gruppe keine System-Logs; Fallback auf Logdatei');

  for (const file of AUTH_LOG_CANDIDATES) {
    const res = await run('tail', ['-n', String(AUTH_LOG_TAIL_LINES), file]);
    if (!res.ok) continue;
    const { kept, skipped } = filterByWindow(res.stdout.split('\n'), windowMinutes, parseSyslogTimestamp);
    ctx.sources.ssh = file;
    if (skipped) ctx.warnings.push(`${skipped} Zeilen in ${file} ohne lesbaren Zeitstempel uebersprungen`);
    return kept;
  }

  ctx.sources.ssh = 'none';
  ctx.warnings.push(`Keine SSH-Logquelle lesbar (journalctl, ${AUTH_LOG_CANDIDATES.join(', ')})`);
  return [];
}

function countSshFailures(lines) {
  const sessions = new Map();
  const session = (rawIp, port) => {
    const ip = normalizeIp(rawIp);
    if (!net.isIP(ip)) return null;
    const key = `${ip}|${port}`;
    if (!sessions.has(key)) sessions.set(key, { ip, hard: 0, soft: false });
    return sessions.get(key);
  };

  for (const line of lines) {
    let m = HARD_FAIL.exec(line);
    if (m) {
      const s = session(m[1], m[2]);
      if (s) s.hard++;
      continue;
    }
    m = SOFT_FAIL.exec(line);
    if (m) {
      const s = session(m[1], m[2]);
      if (s) s.soft = true;
    }
  }

  const counts = {};
  for (const s of sessions.values()) {
    const n = s.hard + (s.hard === 0 && s.soft ? 1 : 0);
    if (n > 0) counts[s.ip] = (counts[s.ip] || 0) + n;
  }
  return counts;
}

/** Liest fehlgeschlagene SSH-Logins im Zeitfenster aus und liefert { ip: anzahl }. */
async function readRecentSshFailures(windowMinutes, ctx = newContext()) {
  return countSshFailures(await collectSshLines(windowMinutes, ctx));
}

/* ---------- Portscan ---------- */

async function collectScanLines(windowMinutes, ctx) {
  // Filterung nach SCAN_TAG passiert in JS statt per "-g", damit es auch auf
  // journalctl-Builds ohne Pattern-Matching-Support funktioniert.
  const journal = await run('journalctl', ['-q', '--no-pager', '-o', 'cat', '-k', '--since', `-${windowMinutes}min`]);
  if (journalUsable(journal)) {
    ctx.sources.portscan = 'journalctl';
    return journal.stdout.split('\n').filter((l) => l.includes(SCAN_TAG));
  }
  if (journal.ok) ctx.warnings.push('journalctl -k liefert ohne Root/adm-Gruppe keine Kernel-Logs; Fallback auf dmesg');

  const dm = await run('dmesg', ['-T']);
  if (dm.ok) {
    const tagged = dm.stdout.split('\n').filter((l) => l.includes(SCAN_TAG));
    const { kept, skipped } = filterByWindow(tagged, windowMinutes, parseDmesgTimestamp);
    ctx.sources.portscan = 'dmesg';
    if (skipped) ctx.warnings.push(`${skipped} dmesg-Zeilen ohne lesbaren Zeitstempel uebersprungen`);
    return kept;
  }

  ctx.sources.portscan = 'none';
  ctx.warnings.push(
    `Kernel-Log nicht lesbar (${(dm.stderr || dm.error || 'dmesg fehlgeschlagen').trim()}); ggf. kernel.dmesg_restrict`
  );
  return [];
}

function countScanPorts(lines) {
  const ipPorts = {};
  for (const line of lines) {
    const src = /SRC=([0-9a-fA-F:.]+)/.exec(line);
    const dpt = /DPT=(\d+)/.exec(line);
    if (!src || !dpt) continue;
    const ip = normalizeIp(src[1]);
    if (!net.isIP(ip)) continue;
    if (!ipPorts[ip]) ipPorts[ip] = new Set();
    ipPorts[ip].add(dpt[1]);
  }
  return Object.fromEntries(Object.entries(ipPorts).map(([ip, ports]) => [ip, ports.size]));
}

/** Liest geloggte Scan-Versuche im Zeitfenster aus und liefert { ip: anzahlVerschiedenerPorts }. */
async function readRecentScanAttempts(windowMinutes, ctx = newContext()) {
  return countScanPorts(await collectScanLines(windowMinutes, ctx));
}

/* ---------- Auswertung ---------- */

/**
 * Vollstaendiger Erkennungsdurchlauf inkl. Datenquellen und Warnungen.
 * Sperrt NICHT selbst (das macht guard.js mit blocklist.js).
 */
async function analyzeThreats() {
  const ctx = newContext();
  const config = {
    sshWindow: getEnvInt('GUARD_SSH_WINDOW_MINUTES', 10),
    sshThreshold: getEnvInt('GUARD_SSH_MAX_FAILURES', 8),
    scanWindow: getEnvInt('GUARD_PORTSCAN_WINDOW_MINUTES', 5),
    scanThreshold: getEnvInt('GUARD_PORTSCAN_MAX_PORTS', 15),
  };
  const allowlist = getAllowlist(ctx.warnings);

  const safe = async (label, fn) => {
    try {
      return await fn();
    } catch (err) {
      ctx.warnings.push(`${label}: ${err && err.message ? err.message : err}`);
      return {};
    }
  };

  const [sshFailures, scanAttempts] = await Promise.all([
    safe('SSH-Auswertung fehlgeschlagen', () => readRecentSshFailures(config.sshWindow, ctx)),
    safe('Portscan-Auswertung fehlgeschlagen', () => readRecentScanAttempts(config.scanWindow, ctx)),
  ]);

  const threats = [];

  for (const [ip, count] of Object.entries(sshFailures)) {
    if (isAllowed(ip, allowlist) || count < config.sshThreshold) continue;
    threats.push({
      ip,
      count,
      reason: `SSH-Bruteforce: ${count} fehlgeschlagene Logins in ${config.sshWindow} Minuten`,
      source: 'guard-ssh',
    });
  }

  for (const [ip, distinctPorts] of Object.entries(scanAttempts)) {
    if (isAllowed(ip, allowlist) || distinctPorts < config.scanThreshold) continue;
    threats.push({
      ip,
      count: distinctPorts,
      reason: `Portscan: ${distinctPorts} verschiedene Ports in ${config.scanWindow} Minuten angefragt`,
      source: 'guard-portscan',
    });
  }

  threats.sort((a, b) => b.count - a.count);

  return { threats, sources: ctx.sources, warnings: ctx.warnings, config };
}

/** Kompatibilitaets-API: liefert nur die Liste der zu sperrenden IPs. */
async function detectThreats() {
  return (await analyzeThreats()).threats;
}

module.exports = {
  detectThreats,
  analyzeThreats,
  readRecentSshFailures,
  readRecentScanAttempts,
  // fuer Tests
  countSshFailures,
  countScanPorts,
  ipMatches,
  parseSyslogTimestamp,
  parseDmesgTimestamp,
};
