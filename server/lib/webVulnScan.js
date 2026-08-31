'use strict';

/**
 * webVulnScan.js - aktiver, echter Check der wichtigsten Website-Schwachstellen,
 * die von automatisierten Angriffs-Tools als Erstes ausprobiert werden. Es
 * werden nur GET/HEAD/OPTIONS-Anfragen an den eigenen, konfigurierten Host
 * gestellt - kein Exploit-Payload, kein Fremdzugriff.
 *
 * Kein Werkzeug findet "jede Schwachstelle, die es jemals gibt" - insbesondere
 * unbekannte Zero-Day-Luecken lassen sich per Definition nicht vorab scannen.
 * Was hier geprueft wird, sind die haeufigsten, bekannten Fehlkonfigurationen,
 * die in der Praxis fuer die meisten erfolgreichen Angriffe verantwortlich sind.
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');

// Pfade, die auf echten Servern niemals oeffentlich erreichbar sein sollten.
const SENSITIVE_PATHS = [
  '/.env',
  '/.git/config',
  '/.git/HEAD',
  '/wp-config.php.bak',
  '/config.php.bak',
  '/.DS_Store',
  '/backup.sql',
  '/.ssh/id_rsa',
  '/.aws/credentials',
];

function request(targetUrl, method, path) {
  return new Promise((resolve) => {
    let parsed;
    try {
      parsed = new URL(path ? new URL(path, targetUrl).toString() : targetUrl);
    } catch {
      resolve({ reachable: false, error: 'Ungueltige URL' });
      return;
    }
    const lib = parsed.protocol === 'http:' ? http : https;
    const req = lib.request(
      parsed,
      { method, timeout: 8000, rejectUnauthorized: false },
      (res) => {
        let body = '';
        res.on('data', (chunk) => {
          if (body.length < 2048) body += chunk;
        });
        res.on('end', () => {
          resolve({
            reachable: true,
            statusCode: res.statusCode,
            headers: res.headers,
            bodySample: body,
          });
        });
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

/** Prueft, ob sensible Dateipfade tatsaechlich ausgeliefert werden (kein generisches 404). */
async function checkExposedFiles(targetUrl) {
  const exposed = [];
  for (const path of SENSITIVE_PATHS) {
    const res = await request(targetUrl, 'GET', path);
    if (res.reachable && res.statusCode === 200 && res.bodySample && res.bodySample.trim().length > 0) {
      exposed.push(path);
    }
  }
  return exposed;
}

/** Prueft per OPTIONS, ob gefaehrliche HTTP-Methoden erlaubt sind. */
async function checkDangerousMethods(targetUrl) {
  const res = await request(targetUrl, 'OPTIONS', '/');
  if (!res.reachable) return { checked: false };
  const allow = (res.headers && res.headers.allow) || '';
  const methods = allow.split(',').map((m) => m.trim().toUpperCase()).filter(Boolean);
  const dangerous = methods.filter((m) => ['TRACE', 'CONNECT', 'PUT', 'DELETE'].includes(m));
  return { checked: true, methods, dangerous };
}

/** Prueft die Root-Antwort auf CORS-Fehlkonfiguration und Banner-Preisgabe. */
async function checkRootResponse(targetUrl) {
  const res = await request(targetUrl, 'GET', '/');
  if (!res.reachable) return { reachable: false, error: res.error };

  const headers = res.headers || {};
  const corsWildcardWithCredentials = headers['access-control-allow-origin'] === '*'
    && String(headers['access-control-allow-credentials'] || '').toLowerCase() === 'true';
  const serverBanner = headers.server || null;
  const poweredBy = headers['x-powered-by'] || null;
  const versionLeak = [serverBanner, poweredBy].filter(Boolean).some((v) => /\d+\.\d+/.test(v));
  const directoryListing = /Index of \//i.test(res.bodySample || '');

  return {
    reachable: true,
    statusCode: res.statusCode,
    corsWildcardWithCredentials,
    serverBanner,
    poweredBy,
    versionLeak,
    directoryListing,
  };
}

async function scanWebVulnerabilities(targetUrl) {
  const [exposedFiles, methodsCheck, rootCheck] = await Promise.all([
    checkExposedFiles(targetUrl).catch(() => []),
    checkDangerousMethods(targetUrl).catch(() => ({ checked: false })),
    checkRootResponse(targetUrl).catch((e) => ({ reachable: false, error: e.message })),
  ]);

  if (!rootCheck.reachable) {
    return { url: targetUrl, reachable: false, error: rootCheck.error };
  }

  const findings = [];
  if (exposedFiles.length > 0) {
    findings.push(`Sensible Dateien oeffentlich erreichbar: ${exposedFiles.join(', ')}`);
  }
  if (methodsCheck.checked && methodsCheck.dangerous && methodsCheck.dangerous.length > 0) {
    findings.push(`Gefaehrliche HTTP-Methoden erlaubt: ${methodsCheck.dangerous.join(', ')}`);
  }
  if (rootCheck.corsWildcardWithCredentials) {
    findings.push('CORS erlaubt "*" zusammen mit Credentials (Fehlkonfiguration)');
  }
  if (rootCheck.versionLeak) {
    findings.push(`Versionsangabe im Server-Header sichtbar: ${rootCheck.serverBanner || rootCheck.poweredBy}`);
  }
  if (rootCheck.directoryListing) {
    findings.push('Directory-Listing auf / aktiv');
  }

  return {
    url: targetUrl,
    reachable: true,
    exposedFiles,
    methods: methodsCheck,
    cors: { wildcardWithCredentials: rootCheck.corsWildcardWithCredentials },
    banner: { server: rootCheck.serverBanner, poweredBy: rootCheck.poweredBy, versionLeak: rootCheck.versionLeak },
    directoryListing: rootCheck.directoryListing,
    findings,
  };
}

module.exports = { scanWebVulnerabilities };
