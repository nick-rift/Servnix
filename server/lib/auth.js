'use strict';

/**
 * auth.js - Passwort-Hashing (Node-Crypto scrypt, keine externe Dependency)
 * und HTTP-Basic-Auth-Middleware fuer das Dashboard.
 */

const crypto = require('crypto');

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const derived = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  if (!stored || !stored.includes(':')) return false;
  const [salt, hash] = stored.split(':');
  const derived = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(hash, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function timingSafeStringEqual(a, b) {
  const bufA = Buffer.from(a || '', 'utf8');
  const bufB = Buffer.from(b || '', 'utf8');
  // Auf gleiche Laenge padden, damit crypto.timingSafeEqual nicht wegen
  // Laengenunterschied wirft - das Ergebnis bleibt trotzdem korrekt falsch,
  // wenn die echten Laengen abweichen.
  const maxLen = Math.max(bufA.length, bufB.length, 1);
  const paddedA = Buffer.alloc(maxLen);
  const paddedB = Buffer.alloc(maxLen);
  bufA.copy(paddedA);
  bufB.copy(paddedB);
  return bufA.length === bufB.length && crypto.timingSafeEqual(paddedA, paddedB);
}

/**
 * @param {object} [opts]
 * @param {(ip: string) => void} [opts.onFailure] - wird bei falschem Login aufgerufen (z.B. fuer Bruteforce-Schutz).
 * @param {(ip: string) => void} [opts.onSuccess] - wird bei erfolgreichem Login aufgerufen (z.B. um den Fehlversuch-Zaehler zurueckzusetzen).
 */
function basicAuthMiddleware(opts = {}) {
  const { onFailure, onSuccess } = opts;
  return (req, res, next) => {
    const expectedUser = process.env.DASHBOARD_USER || 'admin';
    const expectedHash = process.env.DASHBOARD_PASSWORD_HASH || '';

    if (!expectedHash) {
      // Kein Passwort konfiguriert: Dashboard bleibt offen, aber der Server warnt deutlich.
      return next();
    }

    const header = req.headers.authorization || '';
    const [scheme, encoded] = header.split(' ');
    if (scheme === 'Basic' && encoded) {
      const decoded = Buffer.from(encoded, 'base64').toString('utf8');
      const sep = decoded.indexOf(':');
      const user = decoded.slice(0, sep);
      const pass = decoded.slice(sep + 1);
      if (timingSafeStringEqual(user, expectedUser) && verifyPassword(pass, expectedHash)) {
        if (onSuccess) onSuccess(req.socket.remoteAddress);
        return next();
      }
    }
    if (onFailure) onFailure(req.socket.remoteAddress);
    res.set('WWW-Authenticate', 'Basic realm="Servnix Dashboard"');
    return res.status(401).send('Authentifizierung erforderlich.');
  };
}

module.exports = { hashPassword, verifyPassword, basicAuthMiddleware };
