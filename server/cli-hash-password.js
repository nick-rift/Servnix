#!/usr/bin/env node
'use strict';

/**
 * cli-hash-password.js – erzeugt einen Passwort-Hash fuer DASHBOARD_PASSWORD_HASH in .env
 *
 * Das Passwort wird bewusst NICHT als Argument entgegengenommen: Argumente stehen
 * in der Shell-History und sind waehrend der Laufzeit fuer jeden Nutzer auf dem
 * System in `ps aux` bzw. /proc/<pid>/cmdline lesbar.
 *
 * Verwendung:
 *   node server/cli-hash-password.js                 # interaktiver Prompt (empfohlen)
 *   node server/cli-hash-password.js --env >> .env   # fertige .env-Zeile anhaengen
 *   echo "$PW" | node server/cli-hash-password.js --stdin
 *
 * Alle Hinweise gehen nach stderr, damit stdout ausschliesslich den Hash enthaelt
 * und sich umleiten laesst.
 */

const readline = require('node:readline');
const { Writable } = require('node:stream');

const MIN_LENGTH = Number(process.env.DASHBOARD_PASSWORD_MIN_LENGTH || 12);

const COMMON_PASSWORDS = new Set([
  'password', 'passwort', 'admin', 'administrator', 'dashboard', 'servnix',
  'changeme', 'letmein', 'qwertz', 'qwerty', 'iloveyou', 'willkommen',
  'password1', 'passwort1', '12345678', '123456789', '1234567890',
]);

/* ------------------------------------------------------------------ *
 * Ausgabe-Helfer (alles Nicht-Hash nach stderr)
 * ------------------------------------------------------------------ */
const err = (msg = '') => process.stderr.write(`${msg}\n`);

function fail(msg, code = 1) {
  err(msg);
  process.exit(code);
}

function usage() {
  err(`
cli-hash-password.js – Hash fuer DASHBOARD_PASSWORD_HASH erzeugen

  node server/cli-hash-password.js [Optionen]

Optionen:
  --env                   Komplette .env-Zeile ausgeben statt nur den Hash
  --stdin                 Passwort von stdin lesen (eine Zeile, keine Bestaetigung)
  --unsafe-password-arg P Passwort als Argument (NICHT empfohlen: landet in
                          Shell-History und ist in \`ps aux\` sichtbar)
  -h, --help              Diese Hilfe
`.trim());
}

/* ------------------------------------------------------------------ *
 * Argumente
 * ------------------------------------------------------------------ */
function parseArgs(argv) {
  const opts = { env: false, stdin: false, unsafe: null };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === '--env') opts.env = true;
    else if (a === '--stdin') opts.stdin = true;
    else if (a === '--unsafe-password-arg') {
      opts.unsafe = argv[i + 1];
      i += 1;
      if (opts.unsafe === undefined) fail('--unsafe-password-arg erwartet einen Wert.');
    } else if (a === '-h' || a === '--help') {
      usage();
      process.exit(0);
    } else if (a.startsWith('-')) {
      fail(`Unbekannte Option: ${a}\nHilfe: --help`);
    } else {
      // Frueheres Verhalten: Passwort als erstes Argument.
      fail(
        'Das Passwort wird nicht mehr als Argument akzeptiert – es waere in der\n' +
        'Shell-History und in `ps aux` fuer andere Nutzer sichtbar.\n\n' +
        'Stattdessen einfach ohne Argument starten:\n' +
        '  node server/cli-hash-password.js\n\n' +
        '(Wenn es wirklich nicht anders geht: --unsafe-password-arg "..." )'
      );
    }
  }
  return opts;
}

/* ------------------------------------------------------------------ *
 * Eingabe
 * ------------------------------------------------------------------ */

/** Liest eine Zeile vom TTY, ohne sie anzuzeigen. */
function readSecret(promptText) {
  return new Promise((resolve, reject) => {
    const muted = new Writable({
      write(chunk, enc, cb) {
        if (!muted.silent) process.stderr.write(chunk, enc);
        cb();
      },
    });
    muted.silent = false;

    const rl = readline.createInterface({
      input: process.stdin,
      output: muted,
      terminal: true,
    });

    rl.on('SIGINT', () => {
      muted.silent = false;
      rl.close();
      err('\nAbgebrochen.');
      process.exit(130);
    });
    rl.on('error', reject);

    rl.question(promptText, (answer) => {
      muted.silent = false;
      process.stderr.write('\n');
      rl.close();
      resolve(answer);
    });

    // Erst nach question() stummschalten, damit der Prompt noch sichtbar ist.
    muted.silent = true;
  });
}

/** Liest eine einzelne Zeile von stdin (Pipe). */
function readFromStdin() {
  return new Promise((resolve, reject) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => resolve(data.split(/\r?\n/)[0]));
    process.stdin.on('error', reject);
  });
}

/* ------------------------------------------------------------------ *
 * Pruefungen (Warnungen blockieren nicht, Fehler schon)
 * ------------------------------------------------------------------ */
function validate(password) {
  if (password.length === 0) fail('Kein Passwort eingegeben.');

  if (password !== password.trim()) {
    err('! Hinweis: Das Passwort beginnt oder endet mit Leerzeichen. Beim Login muessen');
    err('  diese exakt mit eingegeben werden – meist ein Versehen beim Kopieren.');
  }

  if (password.trim().length < MIN_LENGTH) {
    fail(
      `Passwort ist zu kurz (${password.trim().length} Zeichen, mindestens ${MIN_LENGTH}).\n` +
      'Dieses Dashboard steuert Firewall-Regeln – eine laengere Passphrase ist das Minimum.'
    );
  }

  const lower = password.toLowerCase();
  if (COMMON_PASSWORDS.has(lower)) {
    fail('Dieses Passwort steht in jeder Wortliste. Bitte ein anderes waehlen.');
  }

  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  if (classes < 3 && password.length < 20) {
    err('! Hinweis: wenig Zeichenvielfalt. Entweder deutlich laenger (20+) oder');
    err('  Gross-/Kleinbuchstaben, Ziffern und Sonderzeichen mischen.');
  }

  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(password)) {
    fail('Passwort enthaelt Steuerzeichen – vermutlich ein Kopierfehler.');
  }
}

/* ------------------------------------------------------------------ *
 * Hauptablauf
 * ------------------------------------------------------------------ */
async function main() {
  const opts = parseArgs(process.argv.slice(2));

  let hashPassword;
  try {
    ({ hashPassword } = require('./lib/auth'));
  } catch (e) {
    fail(`Konnte server/lib/auth.js nicht laden: ${e.message}`);
  }
  if (typeof hashPassword !== 'function') {
    fail('server/lib/auth.js exportiert keine Funktion hashPassword(password).');
  }

  let password;

  if (opts.unsafe !== null) {
    err('! WARNUNG: Passwort wurde als Argument uebergeben. Es steht jetzt in der');
    err('  Shell-History und war waehrend des Aufrufs in `ps aux` sichtbar.');
    err('  Danach: `history -d <nr>` bzw. History-Eintrag loeschen.');
    password = opts.unsafe;
  } else if (opts.stdin || !process.stdin.isTTY) {
    password = await readFromStdin();
    if (!opts.stdin) {
      err('(Passwort von stdin gelesen – keine Bestaetigungsabfrage moeglich.)');
    }
  } else {
    password = await readSecret('Passwort: ');
    const repeat = await readSecret('Wiederholen: ');
    if (password !== repeat) {
      fail('Die Eingaben stimmen nicht ueberein. Nichts geaendert.');
    }
  }

  validate(password);

  let hash;
  try {
    // Deckt sync (scrypt/bcrypt.hashSync) und async (argon2/bcrypt) gleichermassen ab.
    hash = await Promise.resolve(hashPassword(password));
  } catch (e) {
    fail(`Hashing fehlgeschlagen: ${e && e.message ? e.message : e}`);
  }

  if (typeof hash !== 'string' || hash.length === 0) {
    fail(`hashPassword() lieferte keinen String zurueck (${typeof hash}).`);
  }

  // Einfache Anfuehrungszeichen: Hashes beginnen mit $ ($2b$, $argon2id$ ...).
  // dotenv expandiert zwar nicht, aber docker-compose und `set -a; source .env` tun es.
  if (opts.env) {
    process.stdout.write(`DASHBOARD_PASSWORD_HASH='${hash}'\n`);
  } else {
    process.stdout.write(`${hash}\n`);
  }

  err('');
  err('In die .env eintragen (einfache Anfuehrungszeichen beibehalten):');
  err(`  DASHBOARD_PASSWORD_HASH='${hash}'`);
  if (hash.includes('$')) {
    err('');
    err('Achtung bei docker-compose: dort unter `environment:` jedes $ zu $$ verdoppeln,');
    err('sonst wird der Hash stillschweigend veraendert und der Login schlaegt fehl.');
    err('Sauberer ist `env_file: .env` – dort findet keine Expansion statt.');
  }
  err('');
  err('Danach Dashboard neu starten und den Login einmal testen, bevor die alte');
  err('Zugangsmoeglichkeit entfernt wird.');
}

main().catch((e) => {
  fail(`Unerwarteter Fehler: ${e && e.stack ? e.stack : e}`);
});
