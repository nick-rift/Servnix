#!/usr/bin/env node
'use strict';

/**
 * cli-hash-password.js - erzeugt einen Passwort-Hash fuer DASHBOARD_PASSWORD_HASH in .env
 * Usage: node server/cli-hash-password.js "DeinPasswort"
 */

const { hashPassword } = require('./lib/auth');

const password = process.argv[2];
if (!password) {
  console.error('Usage: node server/cli-hash-password.js "DeinPasswort"');
  process.exit(1);
}
if (password.length < 8) {
  console.error('Passwort sollte mindestens 8 Zeichen haben.');
  process.exit(1);
}

console.log(hashPassword(password));
