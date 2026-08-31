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

function basicAuthMiddleware() {
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
      if (user === expectedUser && verifyPassword(pass, expectedHash)) {
        return next();
      }
    }
    res.set('WWW-Authenticate', 'Basic realm="Servnix Dashboard"');
    return res.status(401).send('Authentifizierung erforderlich.');
  };
}

module.exports = { hashPassword, verifyPassword, basicAuthMiddleware };
