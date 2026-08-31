'use strict';

/**
 * httpHeaders.js - prueft echte HTTP-Security-Header einer URL
 * (CSP, HSTS, X-Frame-Options, etc.) per nativer https/http-Anfrage.
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

const CHECKS = [
  { header: 'strict-transport-security', name: 'HSTS', severity: 'hoch' },
  { header: 'content-security-policy', name: 'Content-Security-Policy', severity: 'hoch' },
  { header: 'x-frame-options', name: 'X-Frame-Options', severity: 'mittel' },
  { header: 'x-content-type-options', name: 'X-Content-Type-Options', severity: 'mittel' },
  { header: 'referrer-policy', name: 'Referrer-Policy', severity: 'niedrig' },
  { header: 'permissions-policy', name: 'Permissions-Policy', severity: 'niedrig' },
];

function fetchHeaders(targetUrl) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(targetUrl);
    } catch {
      resolve({ reachable: false, error: 'Ungueltige URL' });
      return;
    }
    const lib = parsed.protocol === 'http:' ? http : https;
    const req = lib.request(
      parsed,
      { method: 'HEAD', timeout: 8000, rejectUnauthorized: false },
      (res) => {
        resolve({ reachable: true, statusCode: res.statusCode, headers: res.headers });
        res.resume();
      },
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ reachable: false, error: 'Timeout' });
    });
    req.on('error', (err) => resolve({ reachable: false, error: err.message }));
    req.end();
  });
}

async function scanHttpHeaders(targetUrl) {
  const result = await fetchHeaders(targetUrl);
  if (!result.reachable) return { url: targetUrl, reachable: false, error: result.error };

  const headers = result.headers || {};
  const findings = CHECKS.map((check) => ({
    ...check,
    present: Object.prototype.hasOwnProperty.call(headers, check.header),
    value: headers[check.header] || null,
  }));

  const missingHigh = findings.filter((f) => f.severity === 'hoch' && !f.present).length;
  const cookies = headers['set-cookie'] || [];
  const cookieList = Array.isArray(cookies) ? cookies : [cookies];
  const insecureCookies = cookieList.filter(
    (c) => (c && !/secure/i.test(c)) || (c && !/httponly/i.test(c)),
  ).length;

  return {
    url: targetUrl,
    reachable: true,
    statusCode: result.statusCode,
    findings,
    missingHigh,
    cookieCount: cookieList.filter(Boolean).length,
    insecureCookies,
  };
}

module.exports = { scanHttpHeaders };
