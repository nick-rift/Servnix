#!/usr/bin/env node
'use strict';

/**
 * cli-scan.js - fuehrt einen vollstaendigen Security-Scan aus und druckt
 * einen lesbaren Report auf die Konsole. Wird von scripts/security-scan.sh
 * aufgerufen und kann auch direkt genutzt werden: `npm run scan`.
 */

require('dotenv').config();
const { runFullScan } = require('./lib/runScan');

function line(char = '─', len = 60) {
  return char.repeat(len);
}

function statusIcon(ok) {
  return ok ? '✅' : '❌';
}

async function main() {
  console.log(line('═'));
  console.log('  SERVNIX SECURITY SCAN');
  console.log(line('═'));

  const result = await runFullScan();

  console.log('\n[Netzwerk & Firewall]');
  const fw = result.firewall;
  if (fw.servnix.active) {
    console.log(`${statusIcon(true)} Servnix-Firewall aktiv (default-deny: ${fw.servnix.defaultDeny}, rate-limiting: ${fw.servnix.rateLimiting})`);
  } else if (fw.ufw.active) {
    console.log(`${statusIcon(true)} ufw aktiv (${fw.ufw.rules.length} Regeln)`);
  } else {
    console.log(`${statusIcon(false)} Keine aktive Firewall gefunden`);
  }
  if (fw.ports.available) {
    console.log(`${statusIcon(fw.ports.unexpectedCount === 0)} Offene Ports: ${fw.ports.ports.map((p) => p.port).join(', ') || 'keine'}`);
  }
  console.log(`${statusIcon(fw.ddos.synCookiesOn)} SYN-Cookies (DDoS-Schutz): ${fw.ddos.synCookiesOn ? 'aktiv' : 'INAKTIV'}`);
  console.log(`${statusIcon(fw.fail2ban.running && fw.fail2ban.jails?.length > 0)} fail2ban: ${fw.fail2ban.available ? (fw.fail2ban.running ? `${fw.fail2ban.jails.length} Jail(s) aktiv` : 'installiert, aber nicht aktiv') : 'nicht installiert'}`);

  console.log('\n[TLS/SSL]');
  if (result.ssl.reachable) {
    console.log(`${statusIcon(result.ssl.grade === 'A+' || result.ssl.grade === 'A')} ${result.target.sslHost}:443 -> Grade ${result.ssl.grade} (${result.ssl.protocol}, ${result.ssl.daysRemaining} Tage gueltig)`);
  } else {
    console.log(`⚠️  ${result.target.sslHost}:443 nicht erreichbar (${result.ssl.error})`);
  }

  console.log('\n[HTTP Security Header]');
  if (result.headers.reachable) {
    result.headers.findings.forEach((f) => console.log(`${statusIcon(f.present)} ${f.name}`));
  } else {
    console.log(`⚠️  ${result.target.targetUrl} nicht erreichbar (${result.headers.error})`);
  }

  console.log('\n[Dependencies]');
  const npmAudit = result.dependencies.npm;
  console.log(
    npmAudit.available
      ? `${statusIcon(npmAudit.total === 0)} npm audit: ${npmAudit.total} Vulnerabilities`
      : `⚠️  npm audit uebersprungen: ${npmAudit.reason}`,
  );
  const pipAudit = result.dependencies.pip;
  console.log(
    pipAudit.available
      ? `${statusIcon(pipAudit.total === 0)} pip-audit: ${pipAudit.total} Vulnerabilities`
      : `⚠️  pip-audit uebersprungen: ${pipAudit.reason}`,
  );

  console.log('\n[System]');
  console.log(`ℹ️  ${result.system.osRelease || result.system.platform}, Kernel ${result.system.kernelVersion}`);
  console.log(`${statusIcon(!result.system.unexpectedRootAccounts || result.system.unexpectedRootAccounts.length === 0)} UID-0-Accounts: ${(result.system.uidZeroAccounts || []).join(', ')}`);

  console.log(`\n${line()}`);
  console.log(`📊 Security Score: ${result.score.scoreOutOf10} / 10  (${result.score.totalPoints}/${result.score.totalMax} Punkte)`);
  if (result.score.findings.length) {
    console.log('\nOffene Punkte:');
    result.score.findings.forEach((f) => console.log(`  - ${f}`));
  } else {
    console.log('\nKeine offenen Punkte gefunden.');
  }
  console.log(line());
}

main().catch((err) => {
  console.error('Scan fehlgeschlagen:', err);
  process.exit(1);
});
