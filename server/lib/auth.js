'use strict';

/**
 * auth.js - Passwort-Hashing (Node-Crypto scrypt, keine externe Dependency)
 * und HTTP-Basic-Auth-Middleware fuer das Dashboard.
 */

const crypto = require('crypto');
const AUTH_COOKIE_NAME = 'servnix_auth';
const authRateState = new Map();

function getEnvInt(name, fallback) {
  const value = Number(process.env[name]);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

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

function parseCookies(header) {
  const raw = String(header || '');
  return raw
    .split(';')
    .map((part) => part.trim())
    .filter(Boolean)
    .reduce((acc, part) => {
      const idx = part.indexOf('=');
      if (idx <= 0) return acc;
      const key = part.slice(0, idx).trim();
      const value = part.slice(idx + 1).trim();
      acc[key] = value;
      return acc;
    }, {});
}

function buildAuthCookieValue(user, hash) {
  const secret = process.env.SESSION_SECRET || hash || 'servnix-auth-fallback';
  return crypto.createHmac('sha256', secret).update(`${user}:${hash}`).digest('hex');
}

function isAuthRateLimited(ip) {
  const now = Date.now();
  const maxAttempts = getEnvInt('DASHBOARD_AUTH_RATE_MAX_ATTEMPTS', 30);
  const windowMs = getEnvInt('DASHBOARD_AUTH_RATE_WINDOW_SECONDS', 60) * 1000;
  const bucket = authRateState.get(ip) || { count: 0, resetAt: now + windowMs };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + windowMs;
  }
  bucket.count += 1;
  authRateState.set(ip, bucket);
  return bucket.count > maxAttempts;
}

function clearAuthRateLimit(ip) {
  authRateState.delete(ip);
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
    const expectedHash = (process.env.DASHBOARD_PASSWORD_HASH || '').trim();
    const clientIp = req.socket.remoteAddress || 'unknown';

    if (!expectedHash) {
      // Kein Passwort konfiguriert: Dashboard bleibt offen, aber der Server warnt deutlich.
      return next();
    }

    if (isAuthRateLimited(clientIp)) {
      return res.status(429).send('Zu viele Login-Anfragen. Bitte kurz warten.');
    }

    const authCookie = parseCookies(req.headers.cookie)[AUTH_COOKIE_NAME];
    const expectedCookie = buildAuthCookieValue(expectedUser, expectedHash);
    if (timingSafeStringEqual(authCookie, expectedCookie)) {
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
        const secure = req.secure || req.headers['x-forwarded-proto'] === 'https';
        const maxAge = getEnvInt('DASHBOARD_AUTH_COOKIE_MAX_AGE_SECONDS', 900);
        const cookieParts = [
          `${AUTH_COOKIE_NAME}=${expectedCookie}`,
          'Path=/',
          'HttpOnly',
          'SameSite=Strict',
          `Max-Age=${maxAge}`,
        ];
        if (secure) cookieParts.push('Secure');
        res.setHeader('Set-Cookie', cookieParts.join('; '));
        clearAuthRateLimit(clientIp);
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
