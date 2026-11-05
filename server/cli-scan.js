#!/usr/bin/env node
'use strict';

/**
 * cli-scan.js – fuehrt einen vollstaendigen Security-Scan aus und gibt einen
 * lesbaren Report aus. Wird von scripts/security-scan.sh aufgerufen und kann
 * direkt genutzt werden: `npm run scan`.
 *
 * Grundregel dieses Reports: "nicht geprueft" ist NICHT dasselbe wie "in Ordnung".
 * Fehlende oder fehlerhafte Daten erscheinen als ?? / WARN, nie als OK.
 *
 * Exit-Codes (fuer Cron/CI):
 *   0  Scan gelaufen, keine Beanstandung oberhalb der Schwelle
 *   1  Scan konnte nicht ausgefuehrt werden (Abbruch, Exception)
 *   2  Scan gelaufen, aber Funde: FAIL vorhanden oder Score unter --fail-under
 *   3  Scan gelaufen, aber Pruefungen nicht auswertbar (nur mit --fail-on-unknown)
 *
 * Optionen: --help
 */

const os = require('node:os');
const path = require('node:path');

// .env relativ zum Projekt laden, nicht relativ zum aktuellen Arbeitsverzeichnis.
try {
  require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
} catch (e) {
  // dotenv ist optional – ohne laufen wir mit den vorhandenen Umgebungsvariablen.
}

const EXIT = { OK: 0, ERROR: 1, FINDINGS: 2, UNKNOWN: 3 };

const OK = 'ok';
const FAIL = 'fail';
const WARN = 'warn';
const UNKNOWN = 'unknown';
const INFO = 'info';

/* ------------------------------------------------------------------ *
 * Argumente
 * ------------------------------------------------------------------ */
function parseArgs(argv) {
  const opts = {
    json: false,
    plain: !process.stdout.isTTY, // in Cron/Pipes automatisch ohne Emoji
    verbose: false,
    failUnder: null,
    failOnUnknown: false,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--json') opts.json = true;
    else if (a === '--plain') opts.plain = true;
    else if (a === '--emoji') opts.plain = false;
    else if (a === '--verbose' || a === '-v') opts.verbose = true;
    else if (a === '--fail-on-unknown') opts.failOnUnknown = true;
    else if (a === '--fail-under') {
      const v = Number(argv[i + 1]);
      i += 1;
      if (!Number.isFinite(v)) {
        process.stderr.write('--fail-under erwartet eine Zahl (Score 0-10).\n');
        process.exit(EXIT.ERROR);
      }
      opts.failUnder = v;
    } else if (a === '-h' || a === '--help') {
      printUsage();
      process.exit(0);
    } else {
      process.stderr.write(`Unbekannte Option: ${a}\nHilfe: --help\n`);
      process.exit(EXIT.ERROR);
    }
  }
  return opts;
}

function printUsage() {
  process.stdout.write(`
Servnix Security Scan

  node server/cli-scan.js [Optionen]

Optionen:
  --json               Maschinenlesbare Ausgabe auf stdout (Report nach stderr)
  --plain              Ohne Emoji: [ OK ] / [FAIL] / [WARN] / [ ?? ]
                       (ist automatisch aktiv, wenn stdout kein Terminal ist)
  --emoji              Emoji erzwingen, auch in Pipes
  --fail-under <n>     Exit 2, wenn der Score unter n liegt (0-10)
  --fail-on-unknown    Exit 3, wenn Pruefungen nicht auswertbar waren
  -v, --verbose        Stacktraces statt nur Fehlermeldungen
  -h, --help           Diese Hilfe

Exit-Codes: 0 sauber · 1 Scan-Abbruch · 2 Funde · 3 nicht auswertbar
`.trimStart());
}

/* ------------------------------------------------------------------ *
 * Fehler-Sanitisierung
 *
 * Fehlerobjekte enthalten gern die komplette Request-URL – bei OPNsense also
 * key/secret. Das landet sonst in Cron-Mails und CI-Logs.
 * ------------------------------------------------------------------ */
const SECRET_KEYS = /(key|secret|token|password|passwd|pass|apikey|api_key|auth|authorization|credential)/i;

function sanitize(input) {
  let s = typeof input === 'string' ? input : String(input);
  // Zuerst die Header-Formen: sonst schwaerzt die generische Regel unten nur bis
  // zum ersten Leerzeichen ("Authorization: ***" – Token bliebe stehen).
  s = s.replace(/\b(proxy-authorization|authorization)\s*:\s*\S+(?:[ \t]+\S+)?/gi, '$1: ***');
  s = s.replace(/\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{8,}/g, '$1 ***');
  // Query-Parameter: ?key=abc&secret=def
  s = s.replace(/([?&#][^=&\s]*)=([^&\s"']*)/g, (m, k, v) =>
    SECRET_KEYS.test(k) ? `${k}=***` : m);
  // Basic-Auth in URLs: https://user:pass@host
  s = s.replace(/(\w+:\/\/)[^/\s:@]+:[^/\s@]+@/g, '$1***:***@');
  // key: "abc" / "secret":"def" / Authorization: Bearer xyz
  // `&` bewusst ausgeschlossen, sonst frisst der gierige Teil den Rest der URL.
  s = s.replace(/(["']?\b\w*(?:key|secret|token|password|auth\w*)\b["']?\s*[:=]\s*)(["']?)[^\s,&"'}]+\2/gi,
    (m, head, q) => `${head}${q}***${q}`);
  return s;
}

function errorText(err, verbose) {
  if (!err) return 'unbekannter Fehler';
  const base = err instanceof Error ? (verbose && err.stack ? err.stack : err.message) : String(err);
  return sanitize(base);
}

/* ------------------------------------------------------------------ *
 * Status-Helfer
 * ------------------------------------------------------------------ */

/**
 * Tri-State: true -> ok, false -> fail, null/undefined -> unknown.
 * Genau hier lag der Fehler der alten Fassung: `!x || x.length === 0` machte
 * aus "Feld fehlt" ein gruenes Haekchen.
 */
function state(value) {
  if (value === true) return OK;
  if (value === false) return FAIL;
  return UNKNOWN;
}

/** Liste leer -> ok, Liste gefuellt -> fail, kein Array -> unknown. */
function stateFromList(list, { emptyIs = OK, filledIs = FAIL } = {}) {
  if (!Array.isArray(list)) return UNKNOWN;
  return list.length === 0 ? emptyIs : filledIs;
}

function listText(list, emptyText = 'keine') {
  if (!Array.isArray(list)) return 'nicht ermittelbar';
  return list.length ? list.join(', ') : emptyText;
}

const ICONS = {
  emoji: { ok: '✅', fail: '❌', warn: '⚠️ ', unknown: '❔', info: 'ℹ️ ' },
  plain: { ok: '[ OK ]', fail: '[FAIL]', warn: '[WARN]', unknown: '[ ?? ]', info: '[INFO]' },
};

/* ------------------------------------------------------------------ *
 * Report-Sammler
 * ------------------------------------------------------------------ */
class Report {
  constructor() {
    this.sections = [];
    this.current = null;
  }

  section(title) {
    this.current = { title, items: [] };
    this.sections.push(this.current);
    return this;
  }

  add(status, label, detail) {
    this.current.items.push({ status, label, detail: detail === undefined ? null : detail });
    return this;
  }

  ok(label, detail) { return this.add(OK, label, detail); }
  fail(label, detail) { return this.add(FAIL, label, detail); }
  warn(label, detail) { return this.add(WARN, label, detail); }
  unknown(label, detail) { return this.add(UNKNOWN, label, detail); }
  info(label, detail) { return this.add(INFO, label, detail); }

  counts() {
    const c = { ok: 0, fail: 0, warn: 0, unknown: 0, info: 0 };
    for (const s of this.sections) for (const i of s.items) c[i.status] += 1;
    return c;
  }

  render(plain) {
    const icons = plain ? ICONS.plain : ICONS.emoji;
    const out = [];
    for (const s of this.sections) {
      out.push('');
      out.push(`[${s.title}]`);
      for (const i of s.items) {
        out.push(`${icons[i.status]} ${i.label}${i.detail ? `: ${i.detail}` : ''}`);
      }
    }
    return out.join('\n');
  }
}

const rule = (char = '-', len = 64) => char.repeat(len);

/* ------------------------------------------------------------------ *
 * Abschnitte
 * ------------------------------------------------------------------ */

function sectionFirewall(r, result) {
  r.section('Netzwerk & Firewall');
  const fw = result.firewall;
  if (!fw) {
    r.unknown('Firewall-Status', 'keine Daten vom Scan erhalten');
    return;
  }

  if (fw.servnix?.active) {
    r.ok('Servnix-Firewall aktiv',
      `default-deny: ${fw.servnix.defaultDeny ?? '?'}, rate-limiting: ${fw.servnix.rateLimiting ?? '?'}`);
  } else if (fw.ufw?.active) {
    r.ok('ufw aktiv', `${fw.ufw.rules?.length ?? '?'} Regeln`);
  } else if (fw.servnix?.active === false && fw.ufw?.active === false) {
    r.fail('Keine aktive Firewall gefunden');
  } else {
    r.unknown('Firewall-Status nicht ermittelbar', fw.error ? sanitize(fw.error) : 'Status unbekannt');
  }

  if (fw.ports?.available) {
    const unexpected = fw.ports.unexpectedCount;
    r.add(
      typeof unexpected === 'number' ? (unexpected === 0 ? OK : FAIL) : UNKNOWN,
      'Offene Ports',
      `${listText((fw.ports.ports || []).map((p) => p.port))}` +
        (typeof unexpected === 'number' ? ` (${unexpected} unerwartet)` : ''),
    );
  } else {
    r.unknown('Offene Ports', fw.ports?.reason ? sanitize(fw.ports.reason) : 'nicht geprueft');
  }

  r.add(state(fw.ddos?.synCookiesOn), 'SYN-Cookies (DDoS-Schutz)',
    fw.ddos?.synCookiesOn === undefined ? 'nicht ermittelbar'
      : (fw.ddos.synCookiesOn ? 'aktiv' : 'INAKTIV'));

  const f2b = fw.fail2ban;
  if (!f2b || f2b.available === undefined) {
    r.unknown('fail2ban', 'nicht geprueft');
  } else if (!f2b.available) {
    // Kein Fehler: der Servnix Guard kann den Bruteforce-Schutz selbst uebernehmen.
    r.warn('fail2ban nicht installiert',
      'unkritisch, solange der Servnix Guard den Bruteforce-Schutz uebernimmt');
  } else if (!f2b.running) {
    r.fail('fail2ban installiert, aber nicht aktiv');
  } else {
    const jails = f2b.jails?.length ?? 0;
    r.add(jails > 0 ? OK : FAIL, 'fail2ban', `${jails} Jail(s) aktiv`);
  }
}

function sectionTls(r, result) {
  r.section('TLS/SSL');
  const ssl = result.ssl;
  const host = result.target?.sslHost ?? '?';
  if (!ssl) {
    r.unknown(`${host}:443`, 'keine Daten vom Scan erhalten');
    return;
  }
  if (!ssl.reachable) {
    r.warn(`${host}:443 nicht erreichbar`, ssl.error ? sanitize(ssl.error) : 'Grund unbekannt');
    return;
  }
  const goodGrade = ssl.grade ? ['A+', 'A'].includes(ssl.grade) : undefined;
  r.add(state(goodGrade), `${host}:443`,
    `Grade ${ssl.grade ?? '?'} (${ssl.protocol ?? '?'})`);

  const days = ssl.daysRemaining;
  if (typeof days !== 'number') {
    r.unknown('Zertifikatslaufzeit', 'nicht ermittelbar');
  } else if (days <= 0) {
    r.fail('Zertifikat abgelaufen', `seit ${Math.abs(days)} Tagen`);
  } else if (days <= 14) {
    r.fail('Zertifikat laeuft bald ab', `noch ${days} Tage`);
  } else if (days <= 30) {
    r.warn('Zertifikat laeuft in unter 30 Tagen ab', `noch ${days} Tage`);
  } else {
    r.ok('Zertifikatslaufzeit', `noch ${days} Tage`);
  }
}

function sectionHeaders(r, result) {
  r.section('HTTP Security Header');
  const h = result.headers;
  if (!h) {
    r.unknown('Header-Check', 'keine Daten vom Scan erhalten');
    return;
  }
  if (!h.reachable) {
    r.warn(`${result.target?.targetUrl ?? 'Ziel'} nicht erreichbar`,
      h.error ? sanitize(h.error) : 'Grund unbekannt');
    return;
  }
  if (!Array.isArray(h.findings) || h.findings.length === 0) {
    r.unknown('Header-Check', 'keine Einzelergebnisse geliefert');
    return;
  }
  for (const f of h.findings) r.add(state(f.present), f.name);
}

function sectionDependencies(r, result) {
  r.section('Dependencies');
  for (const [key, label] of [['npm', 'npm audit'], ['pip', 'pip-audit']]) {
    const a = result.dependencies?.[key];
    if (!a || a.available === undefined) {
      r.unknown(label, 'nicht geprueft');
    } else if (!a.available) {
      r.warn(`${label} uebersprungen`, a.reason ? sanitize(a.reason) : 'kein Grund angegeben');
    } else if (typeof a.total !== 'number') {
      r.unknown(label, 'kein Ergebnis geliefert');
    } else {
      r.add(a.total === 0 ? OK : FAIL, label, `${a.total} Vulnerabilities`);
    }
  }
}

function sectionSystem(r, result) {
  r.section('System');
  const sys = result.system || {};
  r.info('System', `${sys.osRelease || sys.platform || 'unbekannt'}, Kernel ${sys.kernelVersion || '?'}`);

  if (!Array.isArray(sys.uidZeroAccounts)) {
    r.unknown('UID-0-Accounts', 'nicht ermittelbar (z. B. /etc/passwd nicht lesbar)');
  } else {
    const unexpected = sys.unexpectedRootAccounts;
    r.add(
      Array.isArray(unexpected) ? (unexpected.length === 0 ? OK : FAIL) : UNKNOWN,
      'UID-0-Accounts',
      listText(sys.uidZeroAccounts) +
        (Array.isArray(unexpected) && unexpected.length
          ? ` – unerwartet: ${unexpected.join(', ')}`
          : ''),
    );
  }
}

function sectionWeb(r, result) {
  r.section('Website-Sicherheit');
  const web = result.webVulnerabilities;
  if (!web) {
    r.unknown('Website-Scan', 'nicht ausgefuehrt');
    return;
  }
  if (web.reachable === false) {
    r.warn(`${result.target?.targetUrl ?? 'Ziel'} nicht erreichbar`,
      web.error ? sanitize(web.error) : 'Grund unbekannt');
    return;
  }

  r.add(stateFromList(web.exposedFiles), 'Sensible Dateien oeffentlich erreichbar',
    listText(web.exposedFiles));

  // PUT/DELETE sind bei einer REST-API normal -> WARN statt FAIL.
  r.add(stateFromList(web.methods?.dangerous, { filledIs: WARN }),
    'Laut Allow-Header angekuendigte Methoden',
    listText(web.methods?.dangerous) +
      (web.methods?.dangerous?.length ? ' (bei einer REST-API ggf. erwartet)' : ''));

  const cors = web.cors?.wildcardWithCredentials;
  r.add(cors === undefined ? UNKNOWN : (cors ? FAIL : OK),
    'CORS (Wildcard + Credentials)',
    cors === undefined ? 'nicht ermittelbar' : (cors ? 'JA' : 'nein'));

  const dir = web.directoryListing;
  r.add(dir === undefined ? UNKNOWN : (dir ? FAIL : OK),
    'Directory-Listing',
    dir === undefined ? 'nicht ermittelbar' : (dir ? 'aktiv' : 'inaktiv'));

  if (typeof web.score === 'number') {
    r.info('Website-Teilscore', `${web.score}/100 (entspricht ${(web.score / 10).toFixed(1)}/10)`);
  }
}

/* ------------------------------------------------------------------ *
 * Hauptablauf
 * ------------------------------------------------------------------ */
async function main() {
  const opts = parseArgs(process.argv.slice(2));
  const startedAt = new Date();

  let runFullScan;
  try {
    ({ runFullScan } = require('./lib/runScan'));
  } catch (e) {
    process.stderr.write(`Konnte server/lib/runScan.js nicht laden: ${errorText(e, opts.verbose)}\n`);
    process.exit(EXIT.ERROR);
  }

  let result;
  try {
    result = await runFullScan();
  } catch (e) {
    process.stderr.write(`Scan fehlgeschlagen: ${errorText(e, opts.verbose)}\n`);
    if (!opts.verbose) process.stderr.write('(Details mit --verbose)\n');
    process.exit(EXIT.ERROR);
  }
  if (!result || typeof result !== 'object') {
    process.stderr.write('Scan lieferte kein Ergebnis zurueck.\n');
    process.exit(EXIT.ERROR);
  }

  const r = new Report();
  sectionFirewall(r, result);
  sectionTls(r, result);
  sectionHeaders(r, result);
  sectionDependencies(r, result);
  sectionSystem(r, result);
  sectionWeb(r, result);

  const counts = r.counts();
  const score = result.score || {};
  const scoreValue = typeof score.scoreOutOf10 === 'number' ? score.scoreOutOf10 : null;

  const belowThreshold =
    opts.failUnder !== null && scoreValue !== null && scoreValue < opts.failUnder;

  let exitCode = EXIT.OK;
  if (counts.fail > 0 || belowThreshold) exitCode = EXIT.FINDINGS;
  else if (opts.failOnUnknown && counts.unknown > 0) exitCode = EXIT.UNKNOWN;

  /* ---------------- JSON ---------------- */
  if (opts.json) {
    const payload = {
      generatedAt: startedAt.toISOString(),
      host: os.hostname(),
      target: result.target ?? null,
      score: {
        outOf10: scoreValue,
        points: score.totalPoints ?? null,
        max: score.totalMax ?? null,
        findings: score.findings ?? [],
      },
      counts,
      sections: r.sections,
      exitCode,
    };
    process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
    process.exit(exitCode);
  }

  /* ---------------- Text ---------------- */
  const out = [];
  out.push(rule('='));
  out.push('  SERVNIX SECURITY SCAN');
  out.push(`  ${os.hostname()} · ${startedAt.toLocaleString('de-DE')}`);
  if (result.target?.targetUrl) out.push(`  Ziel: ${sanitize(result.target.targetUrl)}`);
  out.push(rule('='));
  out.push(r.render(opts.plain));
  out.push('');
  out.push(rule());
  out.push(
    `Security Score: ${scoreValue ?? '?'} / 10` +
    (score.totalPoints !== undefined ? `  (${score.totalPoints}/${score.totalMax} Punkte)` : ''),
  );
  out.push(
    `Ergebnis: ${counts.ok} ok · ${counts.fail} Fehler · ${counts.warn} Warnungen · ` +
    `${counts.unknown} nicht auswertbar`,
  );

  if (Array.isArray(score.findings) && score.findings.length) {
    out.push('');
    out.push('Offene Punkte:');
    for (const f of score.findings) out.push(`  - ${sanitize(f)}`);
  } else if (counts.fail === 0) {
    out.push('');
    out.push('Keine offenen Punkte gefunden.');
  }

  if (counts.unknown > 0) {
    out.push('');
    out.push(
      `Hinweis: ${counts.unknown} Pruefung(en) konnten nicht ausgewertet werden. ` +
      'Das ist NICHT dasselbe wie "in Ordnung" – bitte einzeln nachsehen.',
    );
  }
  if (belowThreshold) {
    out.push('');
    out.push(`Score ${scoreValue} liegt unter der Schwelle ${opts.failUnder}.`);
  }
  out.push(rule());

  // Bei --json geht der Report nach stderr; hier nach stdout.
  process.stdout.write(`${out.join('\n')}\n`);
  process.exit(exitCode);
}

main().catch((e) => {
  process.stderr.write(`Unerwarteter Fehler: ${errorText(e, process.argv.includes('--verbose'))}\n`);
  process.exit(EXIT.ERROR);
});
