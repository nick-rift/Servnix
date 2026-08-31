#!/usr/bin/env node
'use strict';

/**
 * guard.js - "Servnix Guard": laeuft als eigener Prozess (empfohlen: root via
 * systemd, siehe scripts/servnix-guard.sh) und sperrt Angreifer automatisch.
 *
 * Ablauf pro Durchlauf:
 *   1. server/lib/intrusionDetection.js liest echte Logs aus und ermittelt
 *      IPs, die die konfigurierten Schwellenwerte ueberschreiten.
 *   2. server/lib/blocklist.js sperrt diese IPs: App-Blockliste + Eintrag in
 *      die nftables-Menge "blackhole_v4" (blockt den GESAMTEN Server-Traffic
 *      dieser IP, nicht nur das Dashboard) + optional OPNsense-Alias.
 *   3. Jede Aktion wird als Security-Event protokolliert (Dashboard zeigt sie an).
 *
 * Nutzung:
 *   node server/guard.js --once     # einmaliger Durchlauf (fuer Tests/Cron)
 *   node server/guard.js            # Dauerbetrieb (Endlosschleife, fuer systemd)
 */

require('dotenv').config();
const { detectThreats } = require('./lib/intrusionDetection');
const { detectWebThreats } = require('./lib/webAttackDetection');
const { blockIp, isBlocked, logEvent } = require('./lib/blocklist');
const { checkForNewUsbDevices } = require('./lib/usbMonitor');

function getEnvInt(name, fallback) {
  const v = Number(process.env[name]);
  return Number.isFinite(v) && v > 0 ? v : fallback;
}

async function runOnce() {
  const threats = await detectThreats();

  if (process.env.WEBGUARD_ENABLE !== 'false') {
    // Web-Angriffserkennung ist synchron (liest nur lokale Logdateien),
    // deshalb kein await noetig - Fehler beim Log-Lesen duerfen den Guard
    // aber trotzdem nicht abstuerzen lassen.
    try {
      threats.push(...detectWebThreats());
    } catch (err) {
      console.error('Web-Angriffserkennung fehlgeschlagen:', err.message);
    }
  }

  for (const threat of threats) {
    if (isBlocked(threat.ip)) continue;
    const result = await blockIp(threat.ip, threat.reason, threat.source);
    if (result.ok && !result.alreadyBlocked) {
      console.log(`🚫 Gesperrt: ${threat.ip} - ${threat.reason} (nftables: ${result.nft?.ok ? 'ok' : 'fehlgeschlagen'})`);
    }
  }

  if (process.env.GUARD_ENABLE_USB_MONITOR !== 'false') {
    const newDevices = await checkForNewUsbDevices();
    for (const dev of newDevices) {
      console.log(`🔌 Neues USB-Geraet erkannt: ${dev}`);
      logEvent({ type: 'usb-detected', detail: dev, source: 'guard-usb' });
    }
  }

  if (threats.length === 0) {
    console.log(`✅ Kein Angriffsmuster erkannt (${new Date().toISOString()})`);
  }
}

async function main() {
  const once = process.argv.includes('--once');
  const intervalSeconds = getEnvInt('GUARD_POLL_INTERVAL_SECONDS', 60);

  console.log('🛡️  Servnix Guard gestartet');
  console.log(`   SSH-Bruteforce-Schwelle: ${getEnvInt('GUARD_SSH_MAX_FAILURES', 8)} Fehlversuche / ${getEnvInt('GUARD_SSH_WINDOW_MINUTES', 10)} Minuten`);
  console.log(`   Portscan-Schwelle:       ${getEnvInt('GUARD_PORTSCAN_MAX_PORTS', 15)} Ports / ${getEnvInt('GUARD_PORTSCAN_WINDOW_MINUTES', 5)} Minuten`);
  if (process.env.WEBGUARD_ENABLE !== 'false') {
    console.log(`   Web-Angriffs-Schwelle:   ${getEnvInt('WEBGUARD_MAX_HITS', 3)} Treffer aus ${process.env.WEBGUARD_ACCESS_LOGS || '/var/log/nginx/access.log,/var/log/apache2/access.log'}`);
  }

  if (once) {
    await runOnce();
    return;
  }

  // Dauerbetrieb: einfache Poll-Schleife statt Cron, damit ein einzelner
  // systemd-Service (servnix-guard.service) genuegt.
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      await runOnce();
    } catch (err) {
      console.error('Guard-Durchlauf fehlgeschlagen:', err.message);
    }
    await new Promise((resolve) => setTimeout(resolve, intervalSeconds * 1000));
  }
}

main().catch((err) => {
  console.error('Servnix Guard abgestuerzt:', err);
  process.exit(1);
});
