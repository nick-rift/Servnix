'use strict';

/**
 * rateLimiter.js - einfacher, dependency-freier In-Memory-Rate-Limiter pro IP.
 *
 * Zweck: Verteidigung auf App-Ebene gegen Request-Fluten/DoS-Versuche gegen
 * das Dashboard selbst - zusaetzlich zum Rate-Limiting, das die
 * Servnix-Firewall bereits auf Netzwerkebene (nftables) macht. Zwei Ebenen,
 * weil die App-Ebene auch dann noch greift, wenn jemand ueber einen bereits
 * erlaubten Port (z.B. via SSH-Tunnel) das Dashboard mit Requests flutet.
 *
 * Wer wiederholt ueber das Limit kommt, gilt als Missbrauch und wird - nach
 * mehreren Verstoessen in Folge - zusaetzlich ueber die Blockliste komplett
 * vom Server gesperrt (nicht nur mit 429 abgewiesen).
 */

const buckets = new Map(); // ip -> { count, resetAt, violations }

function getEnvInt(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

function cleanupStale(now) {
  for (const [ip, entry] of buckets) {
    if (entry.resetAt < now - 5 * 60 * 1000) buckets.delete(ip);
  }
}

/**
 * Erzeugt die Rate-Limit-Middleware.
 * @param {object} opts
 * @param {(ip: string, violations: number) => void} [opts.onRepeatedViolation] - Callback, wenn eine IP wiederholt das Limit reisst (z.B. um sie zu sperren).
 */
function createRateLimiter({ onRepeatedViolation } = {}) {
  const windowMs = getEnvInt('RATE_LIMIT_WINDOW_SECONDS', 60) * 1000;
  const max = getEnvInt('RATE_LIMIT_MAX_REQUESTS', 120);
  const maxViolationsBeforeBlock = getEnvInt('RATE_LIMIT_MAX_VIOLATIONS_BEFORE_BLOCK', 5);

  return (req, res, next) => {
    const ip = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    if (buckets.size > 10000) cleanupStale(now);

    let entry = buckets.get(ip);
    if (!entry || entry.resetAt <= now) {
      entry = { count: 0, resetAt: now + windowMs, violations: entry ? entry.violations : 0 };
      buckets.set(ip, entry);
    }
    entry.count += 1;

    if (entry.count > max) {
      entry.violations += 1;
      res.set('Retry-After', Math.ceil((entry.resetAt - now) / 1000).toString());
      res.status(429).json({ error: 'Zu viele Anfragen. Bitte kurz warten.' });
      if (entry.violations >= maxViolationsBeforeBlock && onRepeatedViolation) {
        onRepeatedViolation(ip, entry.violations);
      }
      return;
    }
    next();
  };
}

module.exports = { createRateLimiter };
