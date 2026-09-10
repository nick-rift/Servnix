'use strict';

const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildOpnsenseViewModel, getFirewallActionPath } = require('./app.js');

test('buildOpnsenseViewModel renders unconfigured state with visible hint', () => {
  const view = buildOpnsenseViewModel({ configured: false }, null, null);

  assert.match(view.statusHtml, /Nicht konfiguriert/);
  assert.equal(view.showHint, true);
  assert.match(view.hintHtml, /API-Key/);
  assert.equal(view.rulesHtml, '');
});

test('buildOpnsenseViewModel renders connected state with rule count', () => {
  const view = buildOpnsenseViewModel(
    { configured: true, host: 'https://fw.example.local' },
    { connected: true },
    { ok: true, data: { rows: [{ id: 1 }, { id: 2 }] } },
  );

  assert.match(view.statusHtml, /Verbunden mit https:\/\/fw\.example\.local/);
  assert.equal(view.showHint, false);
  assert.match(view.rulesHtml, /2 Regel\(n\)/);
});

test('buildOpnsenseViewModel renders failed state honestly', () => {
  const view = buildOpnsenseViewModel(
    { configured: true, host: 'https://fw.example.local' },
    { connected: false, error: 'timeout' },
    null,
  );

  assert.match(view.statusHtml, /Verbindung fehlgeschlagen: timeout/);
  assert.equal(view.showHint, true);
  assert.match(view.hintHtml, /kein Erfolg vorgetaeuscht/);
  assert.equal(view.rulesHtml, '');
});

test('buildOpnsenseViewModel renders fallback note when rules cannot be read', () => {
  const view = buildOpnsenseViewModel(
    { configured: true, host: 'https://fw.example.local' },
    { connected: true },
    { ok: false },
  );

  assert.ok(view.statusHtml.includes('Verbunden mit https://fw.example.local'));
  assert.equal(view.showHint, false);
  assert.match(view.rulesHtml, /keine Regelobjekte gelesen werden/);
});

test('buildOpnsenseViewModel renders fallback note when rules rows are missing', () => {
  const view = buildOpnsenseViewModel(
    { configured: true, host: 'https://fw.example.local' },
    { connected: true },
    { ok: true, data: {} },
  );

  assert.ok(view.statusHtml.includes('Verbunden mit https://fw.example.local'));
  assert.equal(view.showHint, false);
  assert.match(view.rulesHtml, /keine Regelobjekte gelesen werden/);
});

test('getFirewallActionPath uses the Nick Firewall route and encodes values', () => {
  assert.equal(getFirewallActionPath('enable'), '/api/firewall/nick/enable');
  assert.equal(getFirewallActionPath('allow custom'), '/api/firewall/nick/allow%20custom');
});

test('dashboard entry HTML wires branded favicon and logo assets', () => {
  const html = fs.readFileSync(path.join(__dirname, 'index.html'), 'utf8');

  assert.match(html, /<link rel="icon" type="image\/svg\+xml" href="favicon\.svg"/);
  assert.match(html, /<img src="logo\.svg" alt="Nick Firewall Logo" class="brand-logo"/);
  assert.match(html, /<h1>Nick Firewall<\/h1>/);
});
