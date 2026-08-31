'use strict';

/**
 * usbMonitor.js - erkennt neu angeschlossene USB-Geraete durch Abgleich mit
 * dem letzten bekannten Stand (`lsusb`).
 *
 * Ehrlicher Hinweis: Das ist eine Erkennung/Alarmierung, KEIN "Auto-Lock".
 * Ein neu eingestecktes USB-Geraet ueber Software automatisch zu sperren,
 * ist auf normalem Linux ohne zusaetzliche Kernel-/USBGuard-Policies nicht
 * seriös moeglich. Wer USB-Geraete tatsaechlich blockieren will, sollte
 * zusaetzlich `usbguard` installieren und konfigurieren - Servnix meldet
 * hier nur, dass sich der USB-Geraetebestand veraendert hat, und schreibt
 * das als Security-Event mit, damit es im Dashboard sichtbar ist.
 */

const fs = require('fs');
const path = require('path');
const { run, commandExists } = require('./exec');

const DATA_DIR = path.join(__dirname, '..', 'data');
const SNAPSHOT_FILE = path.join(DATA_DIR, 'usb-snapshot.json');

function loadSnapshot() {
  if (!fs.existsSync(SNAPSHOT_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(SNAPSHOT_FILE, 'utf8'));
  } catch {
    return [];
  }
}

function saveSnapshot(devices) {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(SNAPSHOT_FILE, JSON.stringify(devices, null, 2));
}

async function listUsbDevices() {
  const hasLsusb = await commandExists('lsusb');
  if (!hasLsusb) return { available: false, devices: [] };
  const res = await run('lsusb');
  if (!res.ok) return { available: false, devices: [] };
  const devices = res.stdout.split('\n').map((l) => l.trim()).filter(Boolean);
  return { available: true, devices };
}

/** Vergleicht den aktuellen USB-Geraetebestand mit dem letzten bekannten Stand. */
async function checkForNewUsbDevices() {
  const { available, devices } = await listUsbDevices();
  if (!available) return [];

  const previous = new Set(loadSnapshot());
  const current = new Set(devices);
  const newDevices = [...current].filter((d) => !previous.has(d));

  saveSnapshot([...current]);
  return newDevices;
}

module.exports = { checkForNewUsbDevices, listUsbDevices };
