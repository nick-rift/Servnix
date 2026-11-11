'use strict';

/**
 * usbMonitor.js - erkennt neu angeschlossene (und entfernte) USB-Geraete durch
 * Abgleich mit dem letzten bekannten Stand.
 *
 * Ehrlicher Hinweis: Das ist eine Erkennung/Alarmierung, KEIN "Auto-Lock".
 * Ein neu eingestecktes USB-Geraet ueber Software automatisch zu sperren,
 * ist auf normalem Linux ohne zusaetzliche Kernel-/USBGuard-Policies nicht
 * serioes moeglich. Wer USB-Geraete tatsaechlich blockieren will, sollte
 * zusaetzlich `usbguard` installieren und konfigurieren - Servnix meldet
 * hier nur, dass sich der USB-Geraetebestand veraendert hat, und schreibt
 * das als Security-Event mit, damit es im Dashboard sichtbar ist.
 *
 * Identitaet eines Geraets: Vendor-ID:Product-ID plus Seriennummer (falls
 * vorhanden). Bus-/Device-Nummern aus `lsusb` eignen sich NICHT, weil die
 * Device-Nummer bei jedem Neuanstecken hochzaehlt. Primaere Quelle ist daher
 * sysfs (/sys/bus/usb/devices, ohne Root lesbar), `lsusb` nur als Fallback.
 * Baugleiche Geraete ohne Seriennummer werden gezaehlt, nicht dedupliziert.
 */

const fs = require('fs');
const path = require('path');
const { run, commandExists } = require('./exec');

const DATA_DIR = path.join(__dirname, '..', 'data');
const SNAPSHOT_FILE = path.join(DATA_DIR, 'usb-snapshot.json');
const SNAPSHOT_VERSION = 2;
const SYSFS_USB = '/sys/bus/usb/devices';

/** USB-Klassencodes (bDeviceClass / bInterfaceClass), hex, klein geschrieben. */
const CLASS_NAMES = {
  '01': 'Audio',
  '02': 'Kommunikation',
  '03': 'HID (Tastatur/Maus)',
  '06': 'Bildgeraet',
  '07': 'Drucker',
  '08': 'Massenspeicher',
  '09': 'Hub',
  '0a': 'CDC-Daten',
  '0e': 'Video',
  e0: 'Drahtlos',
  ef: 'Verschiedenes',
  fe: 'Anwendungsspezifisch',
  ff: 'Herstellerspezifisch',
};

/* ---------- Geraetebeschreibung ---------- */

function describeDevice(d) {
  const classes = [...new Set(d.classes || [])].sort();
  const serial = d.serial || null;
  const name = [d.manufacturer, d.product].filter(Boolean).join(' ') || 'Unbekanntes Geraet';
  return {
    key: `${d.vendorId}:${d.productId}${serial ? `/${serial}` : ''}`,
    vendorId: d.vendorId,
    productId: d.productId,
    manufacturer: d.manufacturer || null,
    product: d.product || null,
    serial,
    port: d.port || null,
    classes,
    classNames: classes.map((c) => CLASS_NAMES[c] || `Klasse 0x${c}`),
    isHid: classes.includes('03'),
    isStorage: classes.includes('08'),
    label: `${name} [${d.vendorId}:${d.productId}${serial ? `, SN ${serial}` : ''}]`,
  };
}

/* ---------- Quelle 1: sysfs ---------- */

function readSysfsAttr(dir, file) {
  try {
    return fs.readFileSync(path.join(dir, file), 'utf8').trim();
  } catch {
    return null;
  }
}

function listViaSysfs() {
  let entries;
  try {
    entries = fs.readdirSync(SYSFS_USB);
  } catch {
    return null;
  }

  const devices = [];
  for (const name of entries) {
    // "1-1", "1-1.2": Geraete. "usb1": Root-Hubs (Teil des Hosts, uebersprungen).
    // "1-1:1.0": Interfaces eines Geraets (liefern die Klassen).
    if (!/^\d+-[\d.]+$/.test(name)) continue;
    const dir = path.join(SYSFS_USB, name);
    const vendorId = readSysfsAttr(dir, 'idVendor');
    const productId = readSysfsAttr(dir, 'idProduct');
    if (!vendorId || !productId) continue;

    const classes = [];
    const devClass = readSysfsAttr(dir, 'bDeviceClass');
    if (devClass && devClass !== '00') classes.push(devClass.toLowerCase());
    for (const iface of entries) {
      if (!iface.startsWith(`${name}:`)) continue;
      const c = readSysfsAttr(path.join(SYSFS_USB, iface), 'bInterfaceClass');
      if (c) classes.push(c.toLowerCase());
    }

    devices.push(
      describeDevice({
        vendorId: vendorId.toLowerCase(),
        productId: productId.toLowerCase(),
        manufacturer: readSysfsAttr(dir, 'manufacturer'),
        product: readSysfsAttr(dir, 'product'),
        serial: readSysfsAttr(dir, 'serial'),
        port: name,
        classes,
      }),
    );
  }
  return devices;
}

/* ---------- Quelle 2: lsusb (Fallback, ohne Seriennummern/Klassen) ---------- */

async function listViaLsusb() {
  if (!(await commandExists('lsusb'))) return null;
  const res = await run('lsusb');
  if (!res.ok) return null;

  const devices = [];
  for (const raw of res.stdout.split('\n')) {
    // "Bus 001 Device 005: ID 046d:c52b Logitech, Inc. Unifying Receiver"
    const m = /^Bus \d+ Device \d+: ID ([0-9a-f]{4}):([0-9a-f]{4})\s*(.*)$/i.exec(raw.trim());
    if (!m) continue;
    const desc = m[3].trim();
    if (/root hub/i.test(desc)) continue;
    devices.push(
      describeDevice({
        vendorId: m[1].toLowerCase(),
        productId: m[2].toLowerCase(),
        product: desc || null,
        classes: [],
      }),
    );
  }
  return devices;
}

async function listUsbDevices() {
  const viaSysfs = listViaSysfs();
  if (viaSysfs) return { available: true, source: 'sysfs', devices: viaSysfs };
  const viaLsusb = await listViaLsusb();
  if (viaLsusb) return { available: true, source: 'lsusb', devices: viaLsusb };
  return { available: false, source: 'none', devices: [] };
}

/* ---------- Snapshot ---------- */

/** Liefert { devices, reason }. devices === null heisst: keine brauchbare Baseline. */
function loadSnapshot() {
  let raw;
  try {
    raw = fs.readFileSync(SNAPSHOT_FILE, 'utf8');
  } catch (err) {
    return {
      devices: null,
      reason: err.code === 'ENOENT' ? 'Kein Snapshot vorhanden (erster Lauf)' : `Snapshot nicht lesbar: ${err.message}`,
    };
  }
  try {
    const parsed = JSON.parse(raw);
    if (parsed && parsed.version === SNAPSHOT_VERSION && Array.isArray(parsed.devices)) {
      return { devices: parsed.devices, reason: null };
    }
    return { devices: null, reason: 'Snapshot in altem Format' };
  } catch {
    return { devices: null, reason: 'Snapshot beschaedigt' };
  }
}

/** Atomar: erst Temp-Datei, dann rename - ein Absturz hinterlaesst nie eine halbe JSON. */
function saveSnapshot(devices) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${SNAPSHOT_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify({ version: SNAPSHOT_VERSION, savedAt: new Date().toISOString(), devices }, null, 2));
  fs.renameSync(tmp, SNAPSHOT_FILE);
}

/* ---------- Vergleich ---------- */

function countByKey(devices) {
  const map = new Map();
  for (const d of devices) {
    const entry = map.get(d.key);
    if (entry) entry.count++;
    else map.set(d.key, { device: d, count: 1 });
  }
  return map;
}

/** Multimengen-Vergleich: zweites baugleiches Geraet ohne Seriennummer zaehlt als neu. */
function diffDevices(previous, current) {
  const prev = countByKey(previous);
  const curr = countByKey(current);
  const added = [];
  const removed = [];
  for (const [key, { device, count }] of curr) {
    const before = prev.has(key) ? prev.get(key).count : 0;
    for (let i = before; i < count; i++) added.push(device);
  }
  for (const [key, { device, count }] of prev) {
    const now = curr.has(key) ? curr.get(key).count : 0;
    for (let i = now; i < count; i++) removed.push(device);
  }
  return { added, removed };
}

/* ---------- Oeffentliche API ---------- */

/**
 * Vollstaendiger Durchlauf: aktueller Bestand, Aenderungen seit dem letzten
 * Lauf, Datenquelle und Warnungen. Beim ersten Lauf (oder nach beschaedigtem
 * Snapshot) wird nur die Baseline gespeichert und NICHTS als neu gemeldet.
 */
async function inspectUsbDevices() {
  const warnings = [];
  const { available, source, devices } = await listUsbDevices();
  if (!available) {
    return {
      available: false,
      source,
      baseline: false,
      added: [],
      removed: [],
      devices: [],
      warnings: [`Weder ${SYSFS_USB} noch lsusb verfuegbar - USB-Ueberwachung inaktiv`],
    };
  }

  const snapshot = loadSnapshot();
  const baseline = snapshot.devices === null;
  if (baseline) {
    warnings.push(`${snapshot.reason}; aktueller Bestand (${devices.length} Geraete) wird als Baseline gespeichert`);
  }
  const { added, removed } = baseline ? { added: [], removed: [] } : diffDevices(snapshot.devices, devices);

  try {
    saveSnapshot(devices);
  } catch (err) {
    warnings.push(`Snapshot konnte nicht gespeichert werden: ${err.message}`);
  }

  return { available: true, source, baseline, added, removed, devices, warnings };
}

/** Kompatibilitaets-API: liefert nur die Labels neu hinzugekommener Geraete. */
async function checkForNewUsbDevices() {
  return (await inspectUsbDevices()).added.map((d) => d.label);
}

module.exports = {
  checkForNewUsbDevices,
  inspectUsbDevices,
  listUsbDevices,
  // fuer Tests
  diffDevices,
  describeDevice,
};
