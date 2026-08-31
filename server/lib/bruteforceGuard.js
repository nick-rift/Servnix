'use strict';

/**
 * bruteforceGuard.js - Login-Bruteforce-Schutz fuer das Dashboard selbst.
 *
 * Genau wie der Servnix Guard SSH-Bruteforce auf Betriebssystemebene erkennt,
 * schuetzt dieses Modul den Dashboard-Login (HTTP Basic Auth) auf App-Ebene:
 * Wer wiederholt ein falsches Passwort probiert, wird nach einer
 * konfigurierbaren Schwelle nicht nur mit 401 abgewiesen, sondern komplett
 * ueber die Blockliste vom gesamten Server gesperrt (nftables + optional
 * OPNsense) - identisch zur Behandlung eines SSH-Bruteforce-Versuchs.
 *
 * Die eigene IP (GUARD_ALLOWLIST) wird nie automatisch gesperrt, damit sich
 * niemand durch Tippfehler beim eigenen Login selbst aussperrt.
 */

const blocklist = require('./blocklist');

const attempts = new Map(); // ip -> { count, firstFailureAt }

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

function recordSuccess(ip) {
  attempts.delete(blocklist.normalizeIp(ip));
}

/** Zaehlt einen fehlgeschlagenen Login-Versuch und sperrt die IP bei Ueberschreiten der Schwelle. */
async function recordFailure(ip) {
  const normalized = blocklist.normalizeIp(ip);
  const maxFailures = getEnvInt('DASHBOARD_MAX_LOGIN_FAILURES', 5);
  const windowMs = getEnvInt('DASHBOARD_LOGIN_WINDOW_MINUTES', 10) * 60 * 1000;
  const now = Date.now();

  let entry = attempts.get(normalized);
  if (!entry || now - entry.firstFailureAt > windowMs) {
    entry = { count: 0, firstFailureAt: now };
  }
  entry.count += 1;
  attempts.set(normalized, entry);

  if (entry.count < maxFailures) return { blocked: false, count: entry.count };

  if (getAllowlist().includes(normalized)) {
    // Eigene/zugelassene IP: NICHT sperren, aber im Log sichtbar machen.
    blocklist.logEvent({
      type: 'login-bruteforce-allowlisted',
      ip: normalized,
      detail: `${entry.count} fehlgeschlagene Dashboard-Logins, aber auf GUARD_ALLOWLIST - nicht gesperrt`,
      source: 'dashboard-auth',
    });
    return { blocked: false, count: entry.count, allowlisted: true };
  }

  attempts.delete(normalized);
  const result = await blocklist.blockIp(
    normalized,
    `Dashboard-Login-Bruteforce: ${entry.count} fehlgeschlagene Versuche`,
    'dashboard-auth',
  );
  return { blocked: result.ok, count: entry.count, result };
}

module.exports = { recordSuccess, recordFailure };
