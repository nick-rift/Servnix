'use strict';

/**
 * runScan.js - orchestriert alle Einzel-Scanner zu einem Gesamtergebnis.
 * Dient sowohl der API (server/index.js) als auch dem CLI-Report (cli-scan.js).
 */

const { scanFirewall } = require('./firewall');
const { scanSsl } = require('./ssl');
const { scanHttpHeaders } = require('./httpHeaders');
const { scanDependencies } = require('./dependencyAudit');
const { scanSystem } = require('./system');
const { computeScore } = require('./score');

async function runFullScan(options = {}) {
  const sslHost = options.sslHost || process.env.SCAN_TARGET_HOST || 'localhost';
  const targetUrl = options.targetUrl || process.env.SCAN_TARGET_URL || `https://${sslHost}`;
  const cwd = options.cwd || process.cwd();

  const [firewall, ssl, headers, dependencies, system] = await Promise.all([
    scanFirewall(),
    scanSsl(sslHost).catch((e) => ({ reachable: false, error: e.message })),
    scanHttpHeaders(targetUrl).catch((e) => ({ reachable: false, error: e.message })),
    scanDependencies(cwd),
    scanSystem(),
  ]);

  const score = computeScore({ firewall, ssl, headers, dependencies, system });

  return {
    timestamp: new Date().toISOString(),
    target: { sslHost, targetUrl },
    firewall,
    ssl,
    headers,
    dependencies,
    system,
    score,
  };
}

module.exports = { runFullScan };
