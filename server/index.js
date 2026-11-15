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
const sshLive = require('./lib/sshLive');

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
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const LATEST_SCAN_FILE = path.join(DATA_DIR, 'latest-scan.json');

if (!process.env.DASHBOARD_PASSWORD_HASH) {
  console.warn(
    '⚠️  Kein DASHBOARD_PASSWORD_HASH gesetzt - das Dashboard ist ungeschuetzt erreichbar!\n' +
    '   Passwort setzen mit: node server/cli-hash-password.js "DeinPasswort"',
  );
}

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

// --- API: Haertungsstatus (fuer die neue Dashboard-Karte, keine Fake-Werte) ---

app.get('/api/hardening/status', (req, res) => {
  res.json({
    securityHeaders: true, // helmet ist immer aktiv, siehe oben
    dashboardAuth: Boolean(process.env.DASHBOARD_PASSWORD_HASH),
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
  });
});

// --- API: SSH-Echtzeit (echte Logs, kein Demo-Material) ---

const SSH_WINDOW_MINUTES = Number(process.env.SSH_LIVE_WINDOW_MINUTES) || 1440;

async function buildSshSnapshot(limit = 300) {
  const { events, source, warning } = await sshLive.readEvents(SSH_WINDOW_MINUTES, 5000);
  const stats = sshLive.buildStats(events);
  const recent = events.slice(0, limit);
  const geo = await sshLive.geoLookup([...recent.map((e) => e.ip), ...stats.topIps.map((t) => t.ip)]);
  return { events: recent, stats, geo, source, warning, geoEnabled: sshLive.geoEnabled(), windowMinutes: SSH_WINDOW_MINUTES };
}

app.get('/api/ssh/events', async (req, res) => {
  try {
    res.json(await buildSshSnapshot(Math.min(Number(req.query.limit) || 300, 2000)));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/ssh/sessions', async (req, res) => {
  res.json(await sshLive.activeSessions());
});

app.get('/api/ssh/geo', async (req, res) => {
  const ips = String(req.query.ips || '').split(',').map((s) => s.trim()).filter(Boolean).slice(0, 100);
  res.json(await sshLive.geoLookup(ips));
});

/**
 * Server-Sent-Events: pusht alle paar Sekunden neue SSH-Ereignisse, die
 * Blockliste, Security-Events, aktive Sitzungen und einen System-Puls.
 * Der Browser haelt eine einzige Verbindung offen - kein Polling-Gewitter.
 */
app.get('/api/live', async (req, res) => {
  res.set({
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
    'X-Accel-Buffering': 'no',
  });
  res.flushHeaders();
  const send = (event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

  let lastTs = 0;
  let lastEventCount = -1;
  let lastBlockKey = '';
  let closed = false;
  req.on('close', () => {
    closed = true;
    clearInterval(timer);
  });

  const tick = async (initial) => {
    if (closed) return;
    try {
      const { events, source, warning } = await sshLive.readEvents(initial ? SSH_WINDOW_MINUTES : 15, initial ? 5000 : 500);
      const fresh = initial ? events : events.filter((e) => e.ts > lastTs);
      if (events.length) lastTs = Math.max(lastTs, events[0].ts);
      if (fresh.length) {
        const geo = await sshLive.geoLookup(fresh.map((e) => e.ip));
        send('ssh', { events: fresh.slice(0, initial ? 300 : 100), geo, source, warning, initial });
      }
      if (initial || fresh.length) {
        const all = initial ? events : (await sshLive.readEvents(SSH_WINDOW_MINUTES, 5000)).events;
        send('stats', sshLive.buildStats(all));
      }

      const blocked = blocklist.listBlocked();
      const blockKey = Object.keys(blocked).sort().join(',');
      const evs = blocklist.listEvents(50);
      if (blockKey !== lastBlockKey || evs.length !== lastEventCount) {
        lastBlockKey = blockKey;
        lastEventCount = evs.length;
        send('blocklist', { blocked, events: evs });
      }

      send('pulse', { ...sshLive.pulse(), sessions: await sshLive.activeSessions(), ts: Date.now() });
    } catch (err) {
      send('error', { message: err.message });
    }
  };

  await tick(true);
  const timer = setInterval(() => tick(false), Number(process.env.SSH_LIVE_INTERVAL_SECONDS) * 1000 || 4000);
});

const server = app.listen(PORT, HOST, () => {
  console.log(`Servnix Dashboard laeuft auf http://${HOST}:${PORT}`);
  if (HOST === '127.0.0.1' || HOST === 'localhost') {
    console.log('→ Nur lokal erreichbar (Sicherheitsvorgabe). Zugriff von deinem PC per SSH-Tunnel:');
    console.log(`   ssh -L ${PORT}:localhost:${PORT} <user>@<server-ip>`);
    console.log(`   Danach im Browser: http://localhost:${PORT}`);
  }
  console.log(`Ersten Scan ausloesen mit: curl -u <user>:<passwort> -X POST http://${HOST}:${PORT}/api/scan`);
});

// Haertung gegen Slowloris/Slow-POST-artige Verbindungs-Erschoepfungsangriffe:
// Verbindungen, die Header/Requests kuenstlich in die Laenge ziehen, werden
// nach kurzer Zeit hart getrennt statt Worker-Kapazitaet zu blockieren.
server.headersTimeout = 15000; // Zeit fuer vollstaendige Header
server.requestTimeout = 30000; // Zeit fuer die gesamte Anfrage
server.keepAliveTimeout = 5000; // wie lange Keep-Alive-Verbindungen offen bleiben
