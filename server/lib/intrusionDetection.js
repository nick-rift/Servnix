'use strict';

/**
 * intrusionDetection.js - regelbasierte Angriffserkennung ("Servnix Guard").
 *
 * Wichtig fuer Ehrlichkeit: Das ist KEINE KI/ML-Anomalieerkennung, sondern
 * transparente, nachvollziehbare Schwellenwert-Regeln auf echten Log-Daten:
 *   - SSH-Bruteforce: X fehlgeschlagene Logins von derselben IP in Y Minuten
 *     (ausgelesen aus journalctl/auth.log)
 *   - Portscan: X verschiedene Ports von derselben IP in Y Minuten angefragt,
 *     die NICHT auf der Allow-Liste stehen (ausgelesen aus dem nftables-Log,
 *     das scripts/servnix-firewall.sh fuer genau diesen Zweck schreibt)
 * Jede Regel/Schwelle ist hier im Code sichtbar und per .env einstellbar.
 */

const { run } = require('./exec');

function getEnvInt(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

function getAllowlist() {
  return (process.env.GUARD_ALLOWLIST || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

/** Liest die letzten fehlgeschlagenen SSH-Login-Versuche aus (journalctl bevorzugt, auth.log als Fallback). */
async function readRecentSshFailures(windowMinutes) {
  const lines = [];

  const journal = await run('journalctl', [
    '-u', 'ssh', '-u', 'sshd',
    '--since', `-${windowMinutes}min`,
    '--no-pager', '-o', 'cat',
  ]);
  if (journal.available && journal.stdout) {
    lines.push(...journal.stdout.split('\n'));
  } else {
    // Fallback fuer Systeme ohne systemd-journal
    const authLog = await run('tail', ['-n', '2000', '/var/log/auth.log']);
    if (authLog.ok) lines.push(...authLog.stdout.split('\n'));
  }

  const ipCounts = {};
  const failurePattern = /(?:Failed password|Invalid user).*from ((?:\d{1,3}\.){3}\d{1,3})/;
  for (const line of lines) {
    const m = line.match(failurePattern);
    if (m) {
      const ip = m[1];
      ipCounts[ip] = (ipCounts[ip] || 0) + 1;
    }
  }
  return ipCounts;
}

/** Liest die vom Servnix-Firewall-Ruleset geloggten Scan-Versuche aus dem Kernel-Log. */
async function readRecentScanAttempts(windowMinutes) {
  const lines = [];

  const journal = await run('journalctl', [
    '-k',
    '--since', `-${windowMinutes}min`,
    '--no-pager', '-o', 'cat',
    '-g', 'servnix-scan-attempt',
  ]);
  if (journal.available && journal.stdout) {
    lines.push(...journal.stdout.split('\n'));
  } else {
    const dmesgRes = await run('dmesg', ['-T']);
    if (dmesgRes.ok) {
      lines.push(...dmesgRes.stdout.split('\n').filter((l) => l.includes('servnix-scan-attempt')));
    }
  }

  // Pro Quell-IP die Menge unterschiedlicher angefragter Zielports sammeln.
  const ipPorts = {};
  for (const line of lines) {
    const srcMatch = line.match(/SRC=((?:\d{1,3}\.){3}\d{1,3})/);
    const dptMatch = line.match(/DPT=(\d+)/);
    if (srcMatch && dptMatch) {
      const ip = srcMatch[1];
      if (!ipPorts[ip]) ipPorts[ip] = new Set();
      ipPorts[ip].add(dptMatch[1]);
    }
  }
  return Object.fromEntries(Object.entries(ipPorts).map(([ip, ports]) => [ip, ports.size]));
}

/**
 * Fuehrt einen Erkennungsdurchlauf aus und gibt eine Liste von IPs zurueck,
 * die laut den konfigurierten Schwellenwerten gesperrt werden sollten -
 * inkl. Begruendung. Sperrt NICHT selbst (das macht guard.js mit blocklist.js).
 */
async function detectThreats() {
  const sshWindow = getEnvInt('GUARD_SSH_WINDOW_MINUTES', 10);
  const sshThreshold = getEnvInt('GUARD_SSH_MAX_FAILURES', 8);
  const scanWindow = getEnvInt('GUARD_PORTSCAN_WINDOW_MINUTES', 5);
  const scanThreshold = getEnvInt('GUARD_PORTSCAN_MAX_PORTS', 15);
  const allowlist = getAllowlist();

  const [sshFailures, scanAttempts] = await Promise.all([
    readRecentSshFailures(sshWindow),
    readRecentScanAttempts(scanWindow),
  ]);

  const threats = [];

  for (const [ip, count] of Object.entries(sshFailures)) {
    if (allowlist.includes(ip)) continue;
    if (count >= sshThreshold) {
      threats.push({
        ip,
        reason: `SSH-Bruteforce: ${count} fehlgeschlagene Logins in ${sshWindow} Minuten`,
        source: 'guard-ssh',
      });
    }
  }

  for (const [ip, distinctPorts] of Object.entries(scanAttempts)) {
    if (allowlist.includes(ip)) continue;
    if (distinctPorts >= scanThreshold) {
      threats.push({
        ip,
        reason: `Portscan: ${distinctPorts} verschiedene Ports in ${scanWindow} Minuten angefragt`,
        source: 'guard-portscan',
      });
    }
  }

  return threats;
}

module.exports = { detectThreats, readRecentSshFailures, readRecentScanAttempts };
