'use strict';

/**
 * system.js - Kernel-/OS-/Nutzer-Audit. Liest reale Systemdaten
 * (uname, /etc/os-release, /etc/passwd fuer UID-0-Accounts, letzte Logins).
 */

const os = require('os');
const fs = require('fs');
const { run } = require('./exec');

function readOsRelease() {
  try {
    const raw = fs.readFileSync('/etc/os-release', 'utf8');
    const map = {};
    raw.split('\n').forEach((line) => {
      const m = line.match(/^([A-Z_]+)="?([^"]*)"?$/);
      if (m) map[m[1]] = m[2];
    });
    return map;
  } catch {
    return null;
  }
}

/** Meldet alle Accounts mit UID 0 (root-aequivalent) - so, wie sie wirklich in /etc/passwd stehen. */
function findUidZeroAccounts() {
  try {
    const raw = fs.readFileSync('/etc/passwd', 'utf8');
    return raw
      .split('\n')
      .filter(Boolean)
      .map((line) => line.split(':'))
      .filter((cols) => cols[2] === '0')
      .map((cols) => cols[0]);
  } catch {
    return null;
  }
}

async function scanSystem() {
  const uname = await run('uname', ['-r']);
  const osRelease = readOsRelease();
  const uidZero = findUidZeroAccounts();
  const uptimeRes = await run('uptime', ['-p']);
  const lastLogins = await run('last', ['-n', '5']);

  return {
    hostname: os.hostname(),
    platform: os.platform(),
    kernelVersion: uname.ok ? uname.stdout.trim() : null,
    osRelease: osRelease ? osRelease.PRETTY_NAME : null,
    uptime: uptimeRes.ok ? uptimeRes.stdout.trim() : null,
    uidZeroAccounts: uidZero,
    unexpectedRootAccounts: uidZero ? uidZero.filter((u) => u !== 'root') : null,
    recentLogins: lastLogins.ok ? lastLogins.stdout.split('\n').filter(Boolean).slice(0, 5) : null,
    cpuCount: os.cpus().length,
    totalMemGB: Math.round((os.totalmem() / 1024 ** 3) * 10) / 10,
    freeMemGB: Math.round((os.freemem() / 1024 ** 3) * 10) / 10,
  };
}

module.exports = { scanSystem };
