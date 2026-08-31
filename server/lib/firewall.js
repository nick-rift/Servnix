'use strict';

/**
 * firewall.js - liest den echten Firewall-Status des Hosts aus.
 * Unterstuetzt die Servnix-eigene nftables-Firewall (siehe scripts/servnix-firewall.sh),
 * ufw und rohes nftables/iptables als Fallback. Es wird NICHTS vorgetaeuscht:
 * wenn kein Regelwerk aktiv ist, wird das auch so gemeldet.
 */

const { run, commandExists } = require('./exec');

async function getServnixNftStatus() {
  const hasNft = await commandExists('nft');
  if (!hasNft) return { active: false, reason: 'nft nicht installiert' };

  const res = await run('nft', ['list', 'table', 'inet', 'servnix_fw']);
  if (!res.ok) {
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
  if (!res.ok) return { available: true, error: res.error || res.stderr };
  const active = /Status:\s*active/i.test(res.stdout);
  const rules = res.stdout
    .split('\n')
    .filter((l) => /ALLOW|DENY|REJECT|LIMIT/.test(l))
    .map((l) => l.trim());
  return { available: true, active, rules, raw: res.stdout };
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
      const match = localAddr.match(/:(\d+)$/);
      return {
        proto,
        address: localAddr,
        port: match ? Number(match[1]) : null,
      };
    })
    .filter((p) => p.port !== null);

  const expected = new Set([22, 80, 443]);
  const unexpected = ports.filter((p) => !expected.has(p.port));

  return { available: true, ports, unexpectedCount: unexpected.length, unexpected };
}

async function getFail2banStatus() {
  const hasF2b = await commandExists('fail2ban-client');
  if (!hasF2b) return { available: false, reason: 'fail2ban-client nicht installiert' };
  const status = await run('fail2ban-client', ['status']);
  if (!status.ok) return { available: true, running: false, error: status.stderr || status.error };
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
  return { servnix, ufw, ports, fail2ban, ddos };
}

module.exports = {
  scanFirewall,
  getServnixNftStatus,
  getUfwStatus,
  getOpenPorts,
  getFail2banStatus,
  getDdosMitigationStatus,
};
