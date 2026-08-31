'use strict';

/**
 * app.js - Frontend-Logik des Servnix-Dashboards. Reine Vanilla-JS-Anwendung,
 * die ausschliesslich die Servnix-API (server/index.js) konsumiert - keine
 * Fake-/Demo-Daten.
 */

const $ = (sel) => document.querySelector(sel);

function icon(ok) {
  if (ok === true) return '<span class="status-ok">✅</span>';
  if (ok === false) return '<span class="status-bad">❌</span>';
  return '<span class="status-warn">⚠️</span>';
}

function kv(label, value) {
  return `<div class="kv"><span>${label}</span><span>${value}</span></div>`;
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok && res.status !== 404) {
    throw new Error(`API-Fehler ${res.status}`);
  }
  return res.json();
}

function renderFirewall(fw) {
  const el = $('#card-firewall .body');
  const active = fw.servnix.active || (fw.ufw && fw.ufw.active);
  const parts = [];
  if (fw.servnix.active) {
    parts.push(kv('Servnix-Firewall', `${icon(true)} aktiv`));
    parts.push(kv('Default-Deny', icon(fw.servnix.defaultDeny)));
    parts.push(kv('Rate-Limiting', icon(fw.servnix.rateLimiting)));
    parts.push(kv('Regeln', fw.servnix.ruleCount));
  } else if (fw.ufw.active) {
    parts.push(kv('ufw', `${icon(true)} aktiv (${fw.ufw.rules.length} Regeln)`));
  } else {
    parts.push(kv('Firewall', `${icon(false)} keine aktiv`));
  }
  parts.push(kv('fail2ban', fw.fail2ban.available ? (fw.fail2ban.running ? `${icon(true)} ${fw.fail2ban.jails.length} Jail(s)` : icon(false)) : '<span class="muted">nicht installiert</span>'));
  el.innerHTML = parts.join('');
}

function renderDdos(fw) {
  const d = fw.ddos;
  const el = $('#card-ddos .body');
  el.innerHTML = [
    kv('SYN-Cookies', icon(d.synCookiesOn)),
    kv('rp_filter (Anti-Spoofing)', icon(d.rpFilterOn)),
    kv('ICMP-Redirects deaktiviert', icon(d.redirectsOff)),
  ].join('');
}

function renderPorts(fw) {
  const el = $('#card-ports .body');
  if (!fw.ports.available) {
    el.innerHTML = '<p class="muted">Nicht verfügbar</p>';
    return;
  }
  const rows = fw.ports.ports.map((p) => `<div class="kv"><span>${p.proto} ${p.address}</span><span>${p.port}</span></div>`).join('');
  el.innerHTML = rows + kv('Unerwartete Ports', fw.ports.unexpectedCount);
}

function renderSsl(ssl) {
  const el = $('#card-ssl .body');
  if (!ssl.reachable) {
    el.innerHTML = `<p class="muted">Nicht erreichbar: ${ssl.error}</p>`;
    return;
  }
  el.innerHTML = [
    kv('Grade', ssl.grade),
    kv('Protokoll', ssl.protocol),
    kv('Läuft ab in', `${ssl.daysRemaining} Tagen`),
    kv('Aussteller', ssl.issuer || '–'),
  ].join('');
}

function renderHeaders(headers) {
  const el = $('#card-headers .body');
  if (!headers.reachable) {
    el.innerHTML = `<p class="muted">Nicht erreichbar: ${headers.error}</p>`;
    return;
  }
  el.innerHTML = headers.findings.map((f) => kv(f.name, icon(f.present))).join('');
}

function renderDeps(deps) {
  const el = $('#card-deps .body');
  const parts = [];
  parts.push(kv('npm audit', deps.npm.available ? `${icon(deps.npm.total === 0)} ${deps.npm.total} Vulns` : '<span class="muted">n/a</span>'));
  parts.push(kv('pip-audit', deps.pip.available ? `${icon(deps.pip.total === 0)} ${deps.pip.total} Vulns` : '<span class="muted">n/a</span>'));
  el.innerHTML = parts.join('');
}

function renderSystem(system) {
  const el = $('#card-system .body');
  el.innerHTML = [
    kv('OS', system.osRelease || system.platform),
    kv('Kernel', system.kernelVersion),
    kv('Uptime', system.uptime || '–'),
    kv('RAM frei/gesamt', `${system.freeMemGB} / ${system.totalMemGB} GB`),
    kv('UID-0-Accounts', (system.uidZeroAccounts || []).join(', ')),
  ].join('');
}

function renderScore(score) {
  $('#scoreValue').textContent = score.scoreOutOf10;
  const ring = document.querySelector('.score-ring');
  ring.style.borderColor = score.scoreOutOf10 >= 8 ? '#3ddc97' : score.scoreOutOf10 >= 5 ? '#ffb84d' : '#ff5d5d';
  const list = $('#findingsList');
  if (score.findings.length === 0) {
    list.innerHTML = '<li class="status-ok">Keine offenen Punkte 🎉</li>';
  } else {
    list.innerHTML = score.findings.map((f) => `<li>${f}</li>`).join('');
  }
}

function renderScan(result) {
  $('#lastScan').textContent = `Letzter Scan: ${new Date(result.timestamp).toLocaleString('de-DE')}`;
  renderFirewall(result.firewall);
  renderDdos(result.firewall);
  renderPorts(result.firewall);
  renderSsl(result.ssl);
  renderHeaders(result.headers);
  renderDeps(result.dependencies);
  renderSystem(result.system);
  renderScore(result.score);
}

async function loadLatest() {
  try {
    const data = await api('/api/scan/latest');
    if (data && !data.error) renderScan(data);
  } catch {
    /* noch kein Scan vorhanden - kein Problem */
  }
}

async function triggerScan() {
  const btn = $('#scanBtn');
  btn.disabled = true;
  btn.textContent = '⏳ Scan läuft…';
  try {
    const data = await api('/api/scan', { method: 'POST' });
    renderScan(data);
  } catch (err) {
    alert('Scan fehlgeschlagen: ' + err.message);
  } finally {
    btn.disabled = false;
    btn.textContent = '🔍 Scan jetzt ausführen';
  }
}

async function loadOpnsense() {
  const cfg = await api('/api/opnsense/config');
  const statusEl = $('#opnsenseStatus');
  const hintEl = $('#opnsenseHint');
  if (!cfg.configured) {
    statusEl.innerHTML = `${icon(false)} Nicht konfiguriert`;
    hintEl.style.display = 'block';
    return;
  }
  const test = await api('/api/opnsense/test');
  if (test.connected) {
    statusEl.innerHTML = `${icon(true)} Verbunden mit ${cfg.host}`;
    hintEl.style.display = 'none';
    const rules = await api('/api/opnsense/rules');
    const el = $('#opnsenseRules');
    if (rules.ok && rules.data && Array.isArray(rules.data.rows)) {
      el.innerHTML = `<p>${rules.data.rows.length} Firewall-Regeln auf OPNsense gefunden.</p>`;
    }
  } else {
    statusEl.innerHTML = `${icon(false)} Verbindung fehlgeschlagen: ${test.error}`;
    hintEl.style.display = 'block';
  }
}

function bindFirewallActions() {
  document.querySelectorAll('[data-fw-action]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const action = btn.dataset.fwAction;
      const out = $('#fwActionOutput');
      out.textContent = `Führe "${action}" aus…`;
      try {
        const res = await api(`/api/firewall/servnix/${action}`, { method: 'POST' });
        out.textContent = (res.stdout || '') + (res.stderr || '') + (res.note ? `\n\nHinweis: ${res.note}` : '');
      } catch (err) {
        out.textContent = 'Fehler: ' + err.message;
      }
    });
  });
}

$('#scanBtn').addEventListener('click', triggerScan);
bindFirewallActions();
loadLatest();
loadOpnsense();
setInterval(loadLatest, 30000);
