'use strict';

require('dotenv').config();
const path = require('path');
const fs = require('fs');
const express = require('express');
const helmet = require('helmet');

const { runFullScan } = require('./lib/runScan');
const { basicAuthMiddleware } = require('./lib/auth');
const opnsense = require('./lib/opnsense');
const { run } = require('./lib/exec');
const blocklist = require('./lib/blocklist');
const { recordFailure, recordSuccess } = require('./lib/bruteforceGuard');
const { createRateLimiter } = require('./lib/rateLimiter');

const app = express();
app.disable('x-powered-by');
// Eigene Security-Header setzen (Helmet) - das Dashboard soll bei den Checks,
// die es selbst bei anderen Servern durchfuehrt (HSTS, CSP, X-Frame-Options,
// ...), nicht schlechter dastehen als das, was es verlangt. CSP ist bewusst
// restriktiv: nur eigene Assets, keine Inline-Skripte/externe Quellen noetig.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
      },
    },
    // HSTS ergibt nur ueber HTTPS Sinn; das Dashboard laeuft standardmaessig
    // nur ueber localhost/SSH-Tunnel (kein TLS noetig) - daher deaktiviert,
    // sonst wuerde ein Browser faelschlich HTTPS erzwingen.
    hsts: false,
  }),
);
app.use(express.json({ limit: '64kb' }));

const PORT = process.env.PORT || 3000;
// Sicherheitsvorgabe: Das Dashboard bindet standardmaessig NUR an localhost,
// damit es nicht ungewollt ueber die oeffentliche Server-IP erreichbar ist.
// Zugriff von aussen erfolgt bewusst per SSH-Tunnel (siehe README/INSTALLATION.md).
// Nur wenn HOST explizit gesetzt wird (z.B. hinter einem eigenen Reverse-Proxy),
// bindet der Server auf ein anderes Interface.
const HOST = process.env.HOST || '127.0.0.1';
const DASHBOARD_PASSWORD_HASH = (process.env.DASHBOARD_PASSWORD_HASH || '').trim();
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const LATEST_SCAN_FILE = path.join(DATA_DIR, 'latest-scan.json');
const SECURITY_EVENTS_FILE = path.join(DATA_DIR, 'security-events.log');

function isLocalHostBinding(host) {
  return ['127.0.0.1', 'localhost', '::1', '::ffff:127.0.0.1'].includes(String(host || '').trim().toLowerCase());
}

if (!isLocalHostBinding(HOST) && !DASHBOARD_PASSWORD_HASH) {
  console.error(
    '❌ Unsichere HOST-Konfiguration blockiert: DASHBOARD_PASSWORD_HASH ist Pflicht,\n' +
    '   wenn HOST nicht localhost/127.0.0.1 ist. Bitte Passwort-Hash setzen,\n' +
    '   z.B. mit: node server/cli-hash-password.js "DeinPasswort"',
  );
  process.exit(1);
}

if (!DASHBOARD_PASSWORD_HASH) {
  console.warn(
    '⚠️  Kein DASHBOARD_PASSWORD_HASH gesetzt - das Dashboard ist ungeschuetzt erreichbar!\n' +
    '   Passwort setzen mit: node server/cli-hash-password.js "DeinPasswort"',
  );
}

const securityEventClients = new Set();
let securityEventsReadOffset = fs.existsSync(SECURITY_EVENTS_FILE) ? fs.statSync(SECURITY_EVENTS_FILE).size : 0;
let securityEventsPartial = '';

function sendSseEvent(client, eventName, payload) {
  client.write(`event: ${eventName}\n`);
  client.write(`data: ${JSON.stringify(payload)}\n\n`);
}

function broadcastSecurityEvent(payload) {
  for (const client of securityEventClients) {
    sendSseEvent(client, 'security-event', payload);
  }
}

function readNewSecurityEvents() {
  try {
    if (!fs.existsSync(SECURITY_EVENTS_FILE)) return [];
    const stat = fs.statSync(SECURITY_EVENTS_FILE);
    if (stat.size < securityEventsReadOffset) {
      securityEventsReadOffset = 0;
      securityEventsPartial = '';
    }
    if (stat.size === securityEventsReadOffset) return [];

    const fd = fs.openSync(SECURITY_EVENTS_FILE, 'r');
    const len = stat.size - securityEventsReadOffset;
    const buffer = Buffer.alloc(len);
    fs.readSync(fd, buffer, 0, len, securityEventsReadOffset);
    fs.closeSync(fd);
    securityEventsReadOffset = stat.size;

    const chunk = securityEventsPartial + buffer.toString('utf8');
    const lines = chunk.split('\n');
    securityEventsPartial = lines.pop() || '';

    return lines
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        try {
          return JSON.parse(line);
        } catch {
          return null;
        }
      })
      .filter(Boolean);
  } catch {
    return [];
  }
}

setInterval(() => {
  const events = readNewSecurityEvents();
  for (const event of events) {
    broadcastSecurityEvent(event);
  }
}, 1000).unref();

// Gesperrte IPs werden schon hier abgewiesen (vor Auth/Statics) - so sieht ein
// bereits gesperrter Angreifer noch nicht mal die Login-Abfrage.
app.use((req, res, next) => {
  const ip = blocklist.normalizeIp(req.socket.remoteAddress);
  if (blocklist.isBlocked(ip)) {
    return res.status(403).json({ error: 'Diese IP-Adresse wurde vom Servnix Guard gesperrt.' });
  }
  next();
});

// App-Ebene-Rate-Limiting: wer wiederholt in Folge ueber das Limit kommt,
// wird nicht nur mit 429 abgewiesen, sondern zusaetzlich komplett gesperrt -
// das faengt Request-Fluten/DoS-Versuche ab, die ueber einen erlaubten Port
// (z.B. den SSH-Tunnel-Port) an der Netzwerk-Firewall vorbeikommen.
app.use(
  createRateLimiter({
    onRepeatedViolation: (ip, violations) => {
      blocklist.blockIp(ip, `Wiederholtes Ueberschreiten des Rate-Limits (${violations}x)`, 'rate-limiter').catch(() => {});
    },
  }),
);

// Dashboard-Login-Bruteforce-Schutz: wer wiederholt ein falsches Passwort
// probiert, wird - wie bei SSH-Bruteforce ueber den Servnix Guard - komplett
// vom Server gesperrt, nicht nur mit 401 abgewiesen.
app.use(
  basicAuthMiddleware({
    onFailure: (ip) => recordFailure(ip).catch(() => {}),
    onSuccess: (ip) => recordSuccess(ip),
  }),
);
app.use(express.static(path.join(__dirname, '..', 'public')));

let scanInProgress = false;

async function performScan(options) {
  scanInProgress = true;
  try {
    const result = await runFullScan(options);
    fs.writeFileSync(LATEST_SCAN_FILE, JSON.stringify(result, null, 2));
    return result;
  } finally {
    scanInProgress = false;
  }
}

// --- API: Scans ---

app.get('/api/scan/latest', (req, res) => {
  if (fs.existsSync(LATEST_SCAN_FILE)) {
    res.json(JSON.parse(fs.readFileSync(LATEST_SCAN_FILE, 'utf8')));
  } else {
    res.status(404).json({ error: 'Noch kein Scan durchgefuehrt. POST /api/scan ausloesen.' });
  }
});

app.post('/api/scan', async (req, res) => {
  if (scanInProgress) {
    return res.status(409).json({ error: 'Ein Scan laeuft bereits' });
  }
  try {
    const result = await performScan(req.body || {});
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- API: Servnix-Firewall Steuerung ---

app.get('/api/firewall/status', async (req, res) => {
  const { scanFirewall } = require('./lib/firewall');
  res.json(await scanFirewall());
});

app.post('/api/firewall/servnix/:action', async (req, res) => {
  const action = req.params.action;
  const allowed = ['install', 'enable', 'disable', 'status'];
  if (!allowed.includes(action)) {
    return res.status(400).json({ error: `Unbekannte Aktion. Erlaubt: ${allowed.join(', ')}` });
  }
  const scriptPath = path.join(__dirname, '..', 'scripts', 'servnix-firewall.sh');
  const result = await run('sudo', [scriptPath, action], { timeout: 30000 });
  res.json({
    action,
    ok: result.ok,
    stdout: result.stdout,
    stderr: result.stderr,
    note: result.available ? undefined : 'sudo/Script nicht ausfuehrbar - lokal ggf. ohne sudo-Rechte',
  });
});

// --- API: OPNsense ---

app.get('/api/opnsense/config', (req, res) => {
  const cfg = opnsense.loadConfig();
  res.json({ configured: opnsense.isConfigured(cfg), host: cfg.host });
});

app.get('/api/opnsense/test', async (req, res) => {
  res.json(await opnsense.testConnection());
});

app.get('/api/opnsense/rules', async (req, res) => {
  res.json(await opnsense.getFirewallRules());
});

app.get('/api/opnsense/health', async (req, res) => {
  res.json(await opnsense.getSystemHealth());
});

app.post('/api/opnsense/block-ip', async (req, res) => {
  const { ip } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'ip fehlt im Body' });
  res.json(await opnsense.blockIpViaAlias(ip));
});

app.get('/api/health', (req, res) => res.json({ ok: true, uptime: process.uptime() }));

// --- API: Servnix Guard (Blockliste + Security-Events) ---

app.get('/api/blocklist', (req, res) => {
  res.json(blocklist.listBlocked());
});

app.post('/api/blocklist', async (req, res) => {
  const { ip, reason } = req.body || {};
  if (!ip) return res.status(400).json({ error: 'ip fehlt im Body' });
  const result = await blocklist.blockIp(ip, reason || 'Manuell ueber Dashboard gesperrt', 'manual');
  if (!result.ok) return res.status(400).json(result);
  res.json(result);
});

app.delete('/api/blocklist/:ip', async (req, res) => {
  const result = await blocklist.unblockIp(req.params.ip);
  if (!result.ok) return res.status(400).json(result);
  res.json(result);
});

app.get('/api/security-events', (req, res) => {
  const limit = Number(req.query.limit) || 100;
  res.json(blocklist.listEvents(limit));
});

app.get('/api/security-events/stream', basicAuthMiddleware(), (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Frame-Options', 'DENY');
  res.flushHeaders?.();
  res.write('retry: 3000\n\n');
  sendSseEvent(res, 'stream-status', { connected: true, timestamp: new Date().toISOString() });

  securityEventClients.add(res);
  const keepAlive = setInterval(() => {
    res.write(': keep-alive\n\n');
  }, 15000);

  req.on('close', () => {
    clearInterval(keepAlive);
    securityEventClients.delete(res);
  });
});

// --- API: Haertungsstatus (fuer die neue Dashboard-Karte, keine Fake-Werte) ---

app.get('/api/hardening/status', (req, res) => {
  res.json({
    securityHeaders: true, // helmet ist immer aktiv, siehe oben
    dashboardAuth: Boolean(DASHBOARD_PASSWORD_HASH),
    loginBruteforceProtection: {
      maxFailures: Number(process.env.DASHBOARD_MAX_LOGIN_FAILURES) || 5,
      windowMinutes: Number(process.env.DASHBOARD_LOGIN_WINDOW_MINUTES) || 10,
    },
    rateLimiting: {
      maxRequests: Number(process.env.RATE_LIMIT_MAX_REQUESTS) || 120,
      windowSeconds: Number(process.env.RATE_LIMIT_WINDOW_SECONDS) || 60,
    },
    guardAllowlistConfigured: Boolean(process.env.GUARD_ALLOWLIST),
    hostBinding: HOST,
    publicBinding: !isLocalHostBinding(HOST),
  });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`Servnix Dashboard laeuft auf http://${HOST}:${PORT}`);
  if (isLocalHostBinding(HOST)) {
    console.log('→ Nur lokal erreichbar (Sicherheitsvorgabe). Zugriff von deinem PC per SSH-Tunnel:');
    console.log(`   ssh -L ${PORT}:localhost:${PORT} <user>@<server-ip>`);
    console.log(`   Danach im Browser: http://localhost:${PORT}`);
  } else {
    console.log('⚠️  Oeffentliche Bindung aktiv. Stelle sicher, dass nur notwendige Ports in der Firewall freigegeben sind.');
  }
  console.log(`Ersten Scan ausloesen mit: curl -u <user>:<passwort> -X POST http://${HOST}:${PORT}/api/scan`);
});

// Haertung gegen Slowloris/Slow-POST-artige Verbindungs-Erschoepfungsangriffe:
// Verbindungen, die Header/Requests kuenstlich in die Laenge ziehen, werden
// nach kurzer Zeit hart getrennt statt Worker-Kapazitaet zu blockieren.
server.headersTimeout = 15000; // Zeit fuer vollstaendige Header
server.requestTimeout = 30000; // Zeit fuer die gesamte Anfrage
server.keepAliveTimeout = 5000; // wie lange Keep-Alive-Verbindungen offen bleiben
