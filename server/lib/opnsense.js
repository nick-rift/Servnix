'use strict';

/**
 * opnsense.js - echter Client fuer die OPNsense REST API.
 * Nutzt HTTP Basic Auth mit API Key (Username) / API Secret (Passwort),
 * genau wie in der offiziellen OPNsense-API-Doku beschrieben:
 * https://docs.opnsense.org/development/api.html
 *
 * Es wird NICHTS simuliert: fehlen Zugangsdaten oder ist der Host nicht
 * erreichbar, wird das transparent als Fehler zurueckgegeben.
 */

const https = require('https');

function loadConfig() {
  return {
    host: process.env.OPNSENSE_HOST || '',
    key: process.env.OPNSENSE_API_KEY || '',
    secret: process.env.OPNSENSE_API_SECRET || '',
    verifyTls: process.env.OPNSENSE_VERIFY_TLS !== 'false',
  };
}

function isConfigured(cfg = loadConfig()) {
  return Boolean(cfg.host && cfg.key && cfg.secret);
}

function request(cfg, method, apiPath, body) {
  return new Promise((resolve) => {
    if (!isConfigured(cfg)) {
      resolve({ ok: false, error: 'OPNsense ist nicht konfiguriert (Host/API Key/Secret fehlen)' });
      return;
    }
    let host;
    try {
      host = new URL(cfg.host.startsWith('http') ? cfg.host : `https://${cfg.host}`);
    } catch {
      resolve({ ok: false, error: 'Ungueltiger OPNsense-Host' });
      return;
    }

    const auth = Buffer.from(`${cfg.key}:${cfg.secret}`).toString('base64');
    const payload = body ? JSON.stringify(body) : null;

    const req = https.request(
      {
        hostname: host.hostname,
        port: host.port || 443,
        path: apiPath,
        method,
        rejectUnauthorized: cfg.verifyTls,
        timeout: 10000,
        headers: {
          Authorization: `Basic ${auth}`,
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
        },
      },
      (res) => {
        let data = '';
        res.on('data', (chunk) => (data += chunk));
        res.on('end', () => {
          if (res.statusCode === 401 || res.statusCode === 403) {
            resolve({ ok: false, error: 'Authentifizierung bei OPNsense fehlgeschlagen (API Key/Secret pruefen)' });
            return;
          }
          try {
            resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, data: JSON.parse(data) });
          } catch {
            resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, data });
          }
        });
      },
    );
    req.on('timeout', () => {
      req.destroy();
      resolve({ ok: false, error: 'Timeout beim Verbinden mit OPNsense' });
    });
    req.on('error', (err) => resolve({ ok: false, error: err.message }));
    if (payload) req.write(payload);
    req.end();
  });
}

/** Verbindungstest: fragt die Firmware-Info ab (leichter, unkritischer Endpunkt). */
async function testConnection(cfg = loadConfig()) {
  const res = await request(cfg, 'GET', '/api/core/firmware/status');
  if (!res.ok) return { connected: false, error: res.error || `HTTP ${res.status}` };
  return { connected: true, info: res.data };
}

async function getFirewallRules(cfg = loadConfig()) {
  return request(cfg, 'GET', '/api/firewall/filter/search_rule');
}

async function getFirewallAliases(cfg = loadConfig()) {
  return request(cfg, 'GET', '/api/firewall/alias/search_item');
}

/** Fuegt eine IP zur Servnix-Blockliste (Alias) hinzu, z.B. um einen Angreifer sofort zu sperren. */
async function blockIpViaAlias(ip, aliasName = 'servnix_blocklist', cfg = loadConfig()) {
  const addRes = await request(cfg, 'POST', `/api/firewall/alias_util/add/${aliasName}`, { address: ip });
  return addRes;
}

async function getSystemHealth(cfg = loadConfig()) {
  return request(cfg, 'GET', '/api/diagnostics/system/system_information');
}

module.exports = {
  loadConfig,
  isConfigured,
  testConnection,
  getFirewallRules,
  getFirewallAliases,
  blockIpViaAlias,
  getSystemHealth,
};
