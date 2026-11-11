'use strict';

/**
 * firewall.js - liest den echten Firewall-Status des Hosts aus.
 * Unterstuetzt die Servnix-eigene nftables-Firewall (siehe scripts/servnix-firewall.sh),
 * ufw und rohes nftables/iptables als Fallback. Es wird NICHTS vorgetaeuscht:
 * wenn kein Regelwerk aktiv ist, wird das auch so gemeldet.
 *
 * Statuswerte:
 *   active: true   -> Regelwerk nachweislich geladen
 *   active: false  -> Regelwerk nachweislich NICHT geladen
 *   active: null   -> unbekannt (z. B. keine Berechtigung, Root erforderlich)
 */

const { run, commandExists } = require('./exec');

/** Erkennt typische Berechtigungsfehler in stderr/error eines run()-Ergebnisses. */
function isPermissionError(res) {
  const text = `${res.stderr || ''} ${res.error || ''}`;
  return /permission denied|operation not permitted|you need to be root|must be run as root|not permitted|EACCES|EPERM/i.test(
    text
  );
}

async function getServnixNftStatus() {
  const hasNft = await commandExists('nft');
  if (!hasNft) return { active: false, reason: 'nft nicht installiert' };

  const res = await run('nft', ['list', 'table', 'inet', 'servnix_fw']);
  if (!res.ok) {
    if (isPermissionError(res)) {
      return {
        active: null,
        permissionDenied: true,
        reason: 'Keine Berechtigung, nftables abzufragen (Root erforderlich)',
      };
    }
    return { active: false, reason: 'Servnix-Firewall-Tabelle "servnix_fw" nicht geladen' };
  }
  const rules = res.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  const hasDropPolicy = /policy drop/.test(res.stdout);
  const hasRateLimit = /limit rate/.test(res.stdout);
  const hasEstablished = /ct state established, related accept|ct state established,related accept/.test(res.stdout);
  return {
    active: true,
    defaultDeny: hasDropPolicy,
    rateLimiting: hasRateLimit,
    statefulFiltering: hasEstablished,
    ruleCount: rules.length,
    raw: res.stdout,
  };
}

async function getUfwStatus() {
  const hasUfw = await commandExists('ufw');
  if (!hasUfw) return { available: false };
  const res = await run('ufw', ['status', 'verbose']);
  if (!res.ok) {
    if (isPermissionError(res)) {
      return {
        available: true,
        active: null,
        permissionDenied: true,
        error: 'Keine Berechtigung, ufw abzufragen (Root erforderlich)',
      };
    }
    return { available: true, active: null, error: res.error || res.stderr };
  }
  const active = /Status:\s*active/i.test(res.stdout);
  const rules = res.stdout
    .split('\n')
    .filter((l) => /ALLOW|DENY|REJECT|LIMIT/.test(l))
    .map((l) => l.trim());
  return { available: true, active, rules, raw: res.stdout };
}

/**
 * Zerlegt eine ss-Lokaladresse in Host und Port.
 * Beispiele: "0.0.0.0:22", "[::]:443", "*:80", "127.0.0.1:3306",
 *            "[::1]:631", "127.0.0.53%lo:53" (systemd-resolved)
 */
function parseLocalAddress(localAddr) {
  const match = localAddr.match(/^(.*):(\d+)$/);
  if (!match) return null;
  return { host: match[1], port: Number(match[2]) };
}

/** True, wenn die Adresse nur auf Loopback lauscht und damit von aussen nicht erreichbar ist. */
function isLoopbackAddress(host) {
  const h = host.replace(/^\[|\]$/g, '').split('%')[0];
  return h === '::1' || h === 'localhost' || /^127\./.test(h);
}

async function getOpenPorts() {
  // ss ist der moderne Nachfolger von netstat und auf praktisch jedem Linux vorhanden.
  const res = await run('ss', ['-tulnH']);
  if (!res.ok) {
    return { available: false, error: res.error };
  }
  const ports = res.stdout
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const cols = line.split(/\s+/);
      const proto = cols[0];
      const localAddr = cols[4] || '';
      const parsed = parseLocalAddress(localAddr);
      if (!parsed) return null;
      return {
        proto,
        address: localAddr,
        port: parsed.port,
        loopback: isLoopbackAddress(parsed.host),
      };
    })
    .filter(Boolean);

  const expected = new Set([22, 80, 443]);

  // Nur extern erreichbare Sockets zaehlen als "unerwartet"; Loopback wird separat ausgewiesen.
  const external = ports.filter((p) => !p.loopback);
  const loopbackOnly = ports.filter((p) => p.loopback);

  // Dedupe: derselbe Port auf 0.0.0.0 und [::] soll nur einmal gemeldet werden.
  const seen = new Set();
  const unexpected = external.filter((p) => {
    if (expected.has(p.port)) return false;
    const key = `${p.proto}:${p.port}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    available: true,
    ports,
    external,
    loopbackOnly,
    unexpectedCount: unexpected.length,
    unexpected,
  };
}

async function getFail2banStatus() {
  const hasF2b = await commandExists('fail2ban-client');
  if (!hasF2b) return { available: false, reason: 'fail2ban-client nicht installiert' };
  const status = await run('fail2ban-client', ['status']);
  if (!status.ok) {
    if (isPermissionError(status)) {
      return {
        available: true,
        running: null,
        permissionDenied: true,
        error: 'Keine Berechtigung, fail2ban abzufragen (Root erforderlich)',
      };
    }
    return { available: true, running: false, error: status.stderr || status.error };
  }
  const jailsLine = status.stdout.split('\n').find((l) => l.includes('Jail list'));
  const jails = jailsLine
    ? jailsLine.split(':')[1].split(',').map((j) => j.trim()).filter(Boolean)
    : [];
  return { available: true, running: true, jails };
}

/** Prueft SYN-Flood-/DDoS-relevante Kernel-Parameter (sysctl). */
async function getDdosMitigationStatus() {
  const keys = [
    'net.ipv4.tcp_syncookies',
    'net.ipv4.tcp_max_syn_backlog',
    'net.ipv4.icmp_echo_ignore_broadcasts',
    'net.ipv4.conf.all.rp_filter',
    'net.ipv4.conf.all.accept_redirects',
    'net.ipv4.conf.all.send_redirects',
  ];
  const results = {};
  for (const key of keys) {
    const res = await run('sysctl', ['-n', key]);
    results[key] = res.ok ? res.stdout.trim() : null;
  }
  const synCookiesOn = results['net.ipv4.tcp_syncookies'] === '1';
  const rpFilterOn = results['net.ipv4.conf.all.rp_filter'] === '1' || results['net.ipv4.conf.all.rp_filter'] === '2';
  const redirectsOff = results['net.ipv4.conf.all.accept_redirects'] === '0';
  return { params: results, synCookiesOn, rpFilterOn, redirectsOff };
}

async function scanFirewall() {
  const [servnix, ufw, ports, fail2ban, ddos] = await Promise.all([
    getServnixNftStatus(),
    getUfwStatus(),
    getOpenPorts(),
    getFail2banStatus(),
    getDdosMitigationStatus(),
  ]);
  const permissionDenied = Boolean(
    servnix.permissionDenied || ufw.permissionDenied || fail2ban.permissionDenied
  );
  return { servnix, ufw, ports, fail2ban, ddos, permissionDenied };
}

module.exports = {
  scanFirewall,
  getServnixNftStatus,
  getUfwStatus,
  getOpenPorts,
  getFail2banStatus,
  getDdosMitigationStatus,
  isPermissionError,
  isLoopbackAddress,
};
