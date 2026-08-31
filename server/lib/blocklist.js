'use strict';

/**
 * blocklist.js - persistente IP-Blockliste. Zentrale Quelle der Wahrheit fuer
 * "wer ist gesperrt" - genutzt vom Dashboard (App-Ebene), vom Guard
 * (server/guard.js) und synchronisiert best-effort mit der Servnix-nftables-
 * Firewall (Set "blackhole_v4") sowie optional mit OPNsense.
 *
 * Wichtig fuer Ehrlichkeit: Ein Sperren auf App-Ebene (diese Datei) schuetzt
 * nur das Servnix-Dashboard selbst. Der eigentliche, wirksame Schutz fuer den
 * GESAMTEN Server (inkl. Webserver auf Port 80/443) passiert erst, wenn die
 * IP zusaetzlich in die nftables-"blackhole_v4"-Menge eingetragen wird - das
 * blockt den Traffic schon auf Netzwerkebene, bevor er irgendeinen Dienst
 * erreicht. Deshalb versucht blockIp() IMMER auch den nftables-Sync.
 */

const fs = require('fs');
const path = require('path');
const { run } = require('./exec');
const opnsense = require('./opnsense');

const DATA_DIR = path.join(__dirname, '..', 'data');
const BLOCKLIST_FILE = path.join(DATA_DIR, 'blocklist.json');
const EVENTS_FILE = path.join(DATA_DIR, 'security-events.log');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadBlocklist() {
  ensureDataDir();
  if (!fs.existsSync(BLOCKLIST_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(BLOCKLIST_FILE, 'utf8'));
  } catch {
    return {};
  }
}

function saveBlocklist(list) {
  ensureDataDir();
  fs.writeFileSync(BLOCKLIST_FILE, JSON.stringify(list, null, 2));
}

/** Normalisiert IPv4-in-IPv6-Notation ("::ffff:127.0.0.1") auf reines IPv4. */
function normalizeIp(ip) {
  if (!ip) return ip;
  const m = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  return m ? m[1] : ip;
}

function isPrivateOrLoopback(ip) {
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip)
  );
}

function logEvent(event) {
  ensureDataDir();
  const line = JSON.stringify({ timestamp: new Date().toISOString(), ...event });
  fs.appendFileSync(EVENTS_FILE, line + '\n');
}

function listEvents(limit = 100) {
  ensureDataDir();
  if (!fs.existsSync(EVENTS_FILE)) return [];
  const lines = fs.readFileSync(EVENTS_FILE, 'utf8').split('\n').filter(Boolean);
  return lines
    .slice(-limit)
    .reverse()
    .map((l) => {
      try {
        return JSON.parse(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function isBlocked(ip) {
  const list = loadBlocklist();
  return Boolean(list[normalizeIp(ip)]);
}

function listBlocked() {
  return loadBlocklist();
}

/** Prueft ob eine IP-Adresse syntaktisch plausibel ist (v4). Grobe Validierung reicht hier. */
function isValidIpv4(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip) && ip.split('.').every((o) => Number(o) <= 255);
}

async function syncNftBlock(ip) {
  // best effort: Tabelle existiert evtl. nicht (Firewall nicht installiert) oder
  // es fehlen root-Rechte - beides ist kein Fehler, wird nur reported.
  const res = await run('nft', ['add', 'element', 'inet', 'servnix_fw', 'blackhole_v4', `{ ${ip} }`]);
  return { ok: res.ok, error: res.ok ? null : res.stderr || res.error };
}

async function syncNftUnblock(ip) {
  const res = await run('nft', ['delete', 'element', 'inet', 'servnix_fw', 'blackhole_v4', `{ ${ip} }`]);
  return { ok: res.ok, error: res.ok ? null : res.stderr || res.error };
}

/**
 * Sperrt eine IP. Traegt sie in die App-Blockliste ein, versucht sie
 * zusaetzlich in die nftables-Firewall UND (falls konfiguriert) in OPNsense
 * einzutragen, und schreibt ein Security-Event. Gibt zurueck, welche der drei
 * Ebenen tatsaechlich erfolgreich waren - keine der Ebenen wird vorgetaeuscht.
 */
async function blockIp(ip, reason, source = 'manual') {
  const normalized = normalizeIp(ip);
  if (!isValidIpv4(normalized)) {
    return { ok: false, error: 'Ungueltige IPv4-Adresse' };
  }
  if (isPrivateOrLoopback(normalized)) {
    return { ok: false, error: 'Private/Loopback-Adressen werden nicht gesperrt (Selbstaussperr-Schutz)' };
  }

  const list = loadBlocklist();
  if (list[normalized]) {
    return { ok: true, alreadyBlocked: true };
  }

  const [nft, opn] = await Promise.all([
    syncNftBlock(normalized),
    opnsense.isConfigured() ? opnsense.blockIpViaAlias(normalized) : Promise.resolve({ ok: false, skipped: true }),
  ]);

  list[normalized] = {
    reason,
    source,
    blockedAt: new Date().toISOString(),
    nftSynced: nft.ok,
    opnsenseSynced: opn.ok === true,
  };
  saveBlocklist(list);
  logEvent({ type: 'block', ip: normalized, reason, source, nftSynced: nft.ok, opnsenseSynced: opn.ok === true });

  return { ok: true, nft, opnsense: opn };
}

async function unblockIp(ip) {
  const normalized = normalizeIp(ip);
  const list = loadBlocklist();
  if (!list[normalized]) return { ok: false, error: 'IP ist nicht gesperrt' };

  const nft = await syncNftUnblock(normalized);
  // Hinweis: Das automatische Entfernen aus einem OPNsense-Alias ist (noch)
  // nicht implementiert - dafuer muesste die Alias-Item-UUID aufgeloest
  // werden. Falls eine IP ueber OPNsense gesperrt wurde, muss sie dort
  // manuell aus dem Alias "servnix_blocklist" entfernt werden.
  const opn = { ok: false, skipped: true, note: 'OPNsense-Unblock manuell im Alias "servnix_blocklist" durchfuehren' };

  delete list[normalized];
  saveBlocklist(list);
  logEvent({ type: 'unblock', ip: normalized, nftSynced: nft.ok });

  return { ok: true, nft, opnsense: opn };
}

module.exports = {
  normalizeIp,
  isPrivateOrLoopback,
  isValidIpv4,
  isBlocked,
  listBlocked,
  blockIp,
  unblockIp,
  logEvent,
  listEvents,
};
