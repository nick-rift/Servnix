'use strict';

/**
 * score.js - berechnet einen nachvollziehbaren Security-Score (0-100) aus
 * den echten Scan-Ergebnissen. Jede Regel ist hier im Code sichtbar - keine
 * Blackbox, kein erfundener Wert.
 */

function scoreFirewall(fw) {
  const findings = [];
  let points = 0;
  const max = 40;

  if (fw.servnix && fw.servnix.active) {
    points += 15;
    if (fw.servnix.defaultDeny) points += 5;
    else findings.push('Servnix-Firewall hat keine default-deny Policy');
    if (fw.servnix.rateLimiting) points += 5;
    else findings.push('Kein Rate-Limiting in der Servnix-Firewall aktiv');
  } else if (fw.ufw && fw.ufw.active) {
    points += 15;
  } else {
    findings.push('Keine aktive Firewall gefunden (weder Servnix-nftables noch ufw)');
  }

  if (fw.ddos) {
    if (fw.ddos.synCookiesOn) points += 5;
    else findings.push('SYN-Cookies sind deaktiviert (anfaellig fuer SYN-Flood)');
    if (fw.ddos.rpFilterOn) points += 3;
    else findings.push('rp_filter deaktiviert (Spoofing-Schutz fehlt)');
    if (fw.ddos.redirectsOff) points += 2;
    else findings.push('ICMP-Redirects sind aktiviert');
  }

  if (fw.fail2ban && fw.fail2ban.running && fw.fail2ban.jails && fw.fail2ban.jails.length > 0) {
    points += 5;
  } else {
    findings.push('fail2ban laeuft nicht oder hat keine aktiven Jails (Brute-Force-Schutz fehlt)');
  }

  if (fw.ports && fw.ports.available) {
    if (fw.ports.unexpectedCount === 0) points += 0;
    else findings.push(`${fw.ports.unexpectedCount} unerwartete offene Port(s) gefunden`);
  }

  return { points: Math.min(points, max), max, findings };
}

function scoreSsl(ssl) {
  const findings = [];
  let points = 0;
  const max = 20;
  if (!ssl || !ssl.reachable) {
    findings.push('TLS-Endpunkt nicht erreichbar - konnte nicht bewertet werden');
    return { points: 0, max, findings };
  }
  const gradePoints = { 'A+': 20, A: 17, B: 13, C: 8, D: 4, F: 0 };
  points = gradePoints[ssl.grade] ?? 0;
  if (ssl.reasons) findings.push(...ssl.reasons.filter((r) => r !== 'Keine Auffaelligkeiten gefunden'));
  return { points, max, findings };
}

function scoreHeaders(headers) {
  const findings = [];
  let points = 0;
  const max = 15;
  if (!headers || !headers.reachable) {
    findings.push('HTTP-Endpunkt nicht erreichbar - Header konnten nicht geprueft werden');
    return { points: 0, max, findings };
  }
  const total = headers.findings.length;
  const present = headers.findings.filter((f) => f.present).length;
  points = Math.round((present / total) * max);
  headers.findings.filter((f) => !f.present).forEach((f) => findings.push(`Header fehlt: ${f.name}`));
  return { points, max, findings };
}

function scoreDependencies(deps) {
  const findings = [];
  let points = 15;
  const max = 15;
  if (deps.npm && deps.npm.available && typeof deps.npm.total === 'number') {
    if (deps.npm.total > 0) {
      points -= Math.min(15, deps.npm.total * 2);
      findings.push(`${deps.npm.total} npm-Vulnerabilities gefunden`);
    }
  }
  if (deps.pip && deps.pip.available && typeof deps.pip.total === 'number' && deps.pip.total > 0) {
    points -= Math.min(points, deps.pip.total * 2);
    findings.push(`${deps.pip.total} Python-Vulnerabilities gefunden`);
  }
  return { points: Math.max(0, points), max, findings };
}

function scoreSystem(system) {
  const findings = [];
  let points = 10;
  const max = 10;
  if (system.unexpectedRootAccounts && system.unexpectedRootAccounts.length > 0) {
    points -= 10;
    findings.push(`Unerwartete UID-0-Accounts: ${system.unexpectedRootAccounts.join(', ')}`);
  }
  return { points: Math.max(0, points), max, findings };
}

function computeScore({ firewall, ssl, headers, dependencies, system }) {
  const parts = {
    firewall: scoreFirewall(firewall || {}),
    ssl: scoreSsl(ssl),
    headers: scoreHeaders(headers),
    dependencies: scoreDependencies(dependencies || {}),
    system: scoreSystem(system || {}),
  };
  const totalPoints = Object.values(parts).reduce((sum, p) => sum + p.points, 0);
  const totalMax = Object.values(parts).reduce((sum, p) => sum + p.max, 0);
  const scoreOutOf10 = Math.round((totalPoints / totalMax) * 100) / 10;
  const findings = Object.values(parts).flatMap((p) => p.findings);

  return { scoreOutOf10, totalPoints, totalMax, parts, findings };
}

module.exports = { computeScore };
