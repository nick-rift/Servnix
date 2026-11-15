'use strict';

/**
 * app.js - Frontend des Servnix Security Operations Centers.
 * Reines Vanilla-JS (CSP: keine Inline-Skripte, keine externen Quellen).
 * Alle Daten kommen live aus der Servnix-API; der Echtzeit-Teil laeuft ueber
 * einen Server-Sent-Events-Stream (/api/live). Keine Demo-Daten.
 */

const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtTime = (ts) => new Date(ts).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
const fmtDateTime = (ts) => new Date(ts).toLocaleString('de-DE');

function icon(ok) {
  if (ok === true) return '<span class="status-ok">●</span>';
  if (ok === false) return '<span class="status-bad">●</span>';
  return '<span class="status-warn">●</span>';
}
function kv(label, value) {
  return `<div class="kv"><span>${label}</span><span>${value}</span></div>`;
}
function flag(cc) {
  if (!cc || cc.length !== 2) return '';
  const base = 0x1f1e6;
  return String.fromCodePoint(base + cc.charCodeAt(0) - 65, base + cc.charCodeAt(1) - 65);
}
function geoLabel(ip) {
  const g = state.geo[ip];
  if (!g) return '';
  if (!g.country) return '';
  const parts = [g.city, g.country].filter(Boolean).join(', ');
  return `${flag(g.countryCode)}${esc(parts)}${g.org ? ' · ' + esc(g.org) : ''}`;
}
// CSP erlaubt keine Inline-style-Attribute -> Groessen per CSSOM setzen.
function applySizes(root) {
  root.querySelectorAll('[data-h]').forEach((el) => (el.style.height = `${el.dataset.h}%`));
  root.querySelectorAll('[data-w]').forEach((el) => (el.style.width = `${el.dataset.w}%`));
}
function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $('#toasts').appendChild(el);
  setTimeout(() => el.remove(), 4500);
}

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok && res.status !== 404) throw new Error(`API-Fehler ${res.status}`);
  return res.json();
}

/* =========================================================================
   State
   ========================================================================= */
const state = {
  geo: {},
  blocked: {},
  seenKeys: new Set(),
  feedCount: 0,
  stats: null,
  paused: false,
  pending: [],
};
const FEED_MAX = 400;

/* =========================================================================
   Uhr
   ========================================================================= */
setInterval(() => {
  $('#clock').textContent = new Date().toLocaleTimeString('de-DE');
}, 1000);

/* =========================================================================
   Live-Feed (SSH)
   ========================================================================= */
const TYPE_LABEL = { failed: 'Fehlversuch', invalid: 'Ungültig', closed: 'Abbruch', accepted: 'Login OK' };

function eventKey(e) {
  return `${e.ts}|${e.type}|${e.ip}|${e.port}|${e.user}`;
}

function feedVisible(e) {
  if (e.type === 'accepted') return $('#filterAccepted').checked;
  return $('#filterFailed').checked;
}

function renderFeedRow(e, fresh) {
  const row = document.createElement('div');
  row.className = `feed-row${fresh ? ' fresh' : ''}`;
  row.dataset.type = e.type;
  row.dataset.ip = e.ip;
  const blocked = Boolean(state.blocked[e.ip]);
  row.innerHTML = `
    <span title="${esc(fmtDateTime(e.ts))}">${fmtTime(e.ts)}</span>
    <span><span class="badge badge-${e.type}">${TYPE_LABEL[e.type] || e.type}</span></span>
    <span><span class="ip">${esc(e.ip)}</span><span class="ip-geo" data-geo="${esc(e.ip)}">${geoLabel(e.ip)}</span></span>
    <span class="user" title="${esc(e.user || '')}">${esc(e.user || '–')}</span>
    <span class="method">${esc(e.method || '–')}${e.port ? ' :' + e.port : ''}</span>
    <span class="row-act">${
      e.type === 'accepted'
        ? ''
        : blocked
          ? '<span class="badge badge-blocked">gesperrt</span>'
          : `<button class="btn btn-danger btn-sm" data-block-ip="${esc(e.ip)}">Sperren</button>`
    }</span>`;
  if (!feedVisible(e)) row.classList.add('hidden');
  return row;
}

function pushEvents(events, initial) {
  const feed = $('#feed');
  const empty = $('#feedEmpty');
  // Neueste zuerst: sortiert absteigend einfuegen.
  const sorted = [...events].sort((a, b) => a.ts - b.ts); // aelteste zuerst -> prepend nacheinander
  let added = 0;
  for (const e of sorted) {
    const key = eventKey(e);
    if (state.seenKeys.has(key)) continue;
    state.seenKeys.add(key);
    feed.prepend(renderFeedRow(e, !initial));
    added++;
    state.feedCount++;
  }
  if (added) empty.classList.add('hidden');
  while (feed.children.length > FEED_MAX + 1) feed.lastElementChild.remove();
  if (!initial && added) {
    const tile = $('#statFailed');
    tile.classList.remove('bump');
    void tile.offsetWidth;
    tile.classList.add('bump');
  }
}

function applyFeedFilter() {
  document.querySelectorAll('.feed-row').forEach((row) => {
    const type = row.dataset.type;
    const show = type === 'accepted' ? $('#filterAccepted').checked : $('#filterFailed').checked;
    row.classList.toggle('hidden', !show);
  });
}

function refreshGeoLabels() {
  document.querySelectorAll('[data-geo]').forEach((el) => {
    if (!el.textContent) el.innerHTML = geoLabel(el.dataset.geo);
  });
}

/* =========================================================================
   Statistik / Chart / Top-Listen
   ========================================================================= */
function renderStats(stats) {
  state.stats = stats;
  const c = stats.counts;
  const failedTotal = (c.failed || 0) + (c.invalid || 0) + (c.closed || 0);
  $('#statFailed').textContent = failedTotal.toLocaleString('de-DE');
  $('#statFailedRate').textContent = (failedTotal / 24).toFixed(1).replace('.', ',');
  $('#statIps').textContent = stats.uniqueIps.toLocaleString('de-DE');
  $('#statAccepted').textContent = (c.accepted || 0).toLocaleString('de-DE');

  const countries = new Set();
  for (const t of stats.topIps) {
    const g = state.geo[t.ip];
    if (g && g.countryCode) countries.add(g.countryCode);
  }
  $('#statCountries').textContent = countries.size ? `≥ ${countries.size}` : '–';

  // Sparkline (Fehlversuche je Stunde)
  const spark = $('#sparkFailed');
  const max = Math.max(1, ...stats.timeline.map((h) => h.failed));
  spark.innerHTML = stats.timeline.map((h) => `<i data-h="${Math.round((h.failed / max) * 100)}"></i>`).join('');
  applySizes(spark);

  renderChart(stats.timeline);
  renderTopIps(stats.topIps);
  renderTopUsers(stats.topUsers);
}

function renderChart(timeline) {
  const bars = $('#chartBars');
  const axis = $('#chartAxis');
  const max = Math.max(1, ...timeline.map((h) => h.failed + h.accepted));
  bars.innerHTML = timeline
    .map((h, i) => {
      const f = (h.failed / max) * 100;
      const a = (h.accepted / max) * 100;
      return `<div class="bar-group" data-i="${i}">
        <div class="bar bar-accepted" data-h="${a}"></div>
        <div class="bar bar-failed" data-h="${f}"></div>
      </div>`;
    })
    .join('');
  applySizes(bars);
  axis.innerHTML = timeline
    .filter((_, i) => i % 4 === 0 || i === 23)
    .map((h) => `<span>${new Date(h.hourStart).getHours().toString().padStart(2, '0')}h</span>`)
    .join('');

  const tip = $('#chartTip');
  bars.querySelectorAll('.bar-group').forEach((g) => {
    g.addEventListener('mouseenter', () => {
      const h = timeline[Number(g.dataset.i)];
      const d = new Date(h.hourStart);
      tip.innerHTML = `<b>${d.getHours().toString().padStart(2, '0')}:00 – ${((d.getHours() + 1) % 24).toString().padStart(2, '0')}:00</b><br>
        <span class="status-bad">●</span> ${h.failed} fehlgeschlagen<br>
        <span class="status-ok">●</span> ${h.accepted} erfolgreich`;
      tip.classList.remove('hidden');
      const r = g.getBoundingClientRect();
      const cr = $('#chart').getBoundingClientRect();
      tip.style.left = `${r.left - cr.left + r.width / 2}px`;
      tip.style.top = `${Math.max(40, r.top - cr.top + (r.height - (Math.max(h.failed + h.accepted, 0) / max) * r.height))}px`;
    });
    g.addEventListener('mouseleave', () => tip.classList.add('hidden'));
  });
}

function renderTopIps(top) {
  const el = $('#topIps');
  if (!top.length) {
    el.innerHTML = '<div class="muted">Keine Angriffe im Zeitfenster. 🎉</div>';
    return;
  }
  const max = top[0].attempts;
  el.innerHTML = top
    .slice(0, 10)
    .map((t) => {
      const blocked = Boolean(state.blocked[t.ip]);
      return `<div class="top-row">
        <div class="top-ip">
          <span class="ip">${esc(t.ip)}</span>
          <span class="top-meta" data-geo="${esc(t.ip)}">${geoLabel(t.ip)}</span>
          <span class="top-meta">${t.userCount} Benutzernamen · zuletzt ${fmtTime(t.last)}</span>
        </div>
        <div class="top-actions">
          <span class="count">${t.attempts}</span>
          ${blocked ? '<span class="badge badge-blocked">gesperrt</span>' : `<button class="btn btn-danger btn-sm" data-block-ip="${esc(t.ip)}">Sperren</button>`}
        </div>
        <div class="bar-wrap"><div class="bar-fill" data-w="${Math.round((t.attempts / max) * 100)}"></div></div>
      </div>`;
    })
    .join('');
  applySizes(el);
}

function renderTopUsers(users) {
  const el = $('#topUsers');
  if (!users.length) {
    el.innerHTML = '<span class="muted">–</span>';
    return;
  }
  el.innerHTML = users.map((u) => `<span class="chip">${esc(u.user)}<b>${u.attempts}</b></span>`).join('');
}

function renderSessions(s) {
  const el = $('#sessions');
  $('#statSessions').textContent = s.available ? s.sessions.length : '–';
  if (!s.available) {
    el.innerHTML = '<span class="muted">`who` nicht verfügbar</span>';
    return;
  }
  if (!s.sessions.length) {
    el.innerHTML = '<span class="muted">Keine aktiven Sitzungen</span>';
    return;
  }
  el.innerHTML = s.sessions
    .map((x) => `<div class="session"><span>👤 ${esc(x.user)} <span class="muted">${esc(x.tty)}</span></span><span>${esc(x.from)} <span class="muted">seit ${esc(x.since)}</span></span></div>`)
    .join('');
}

function renderPulse(p) {
  $('#hostName').textContent = p.hostname || '–';
  $('#pulseLoad').textContent = `${p.load1} / ${p.cpus} Kerne`;
  const loadPct = Math.min(100, Math.round((p.load1 / Math.max(1, p.cpus)) * 100));
  const ml = $('#meterLoad');
  ml.style.width = `${loadPct}%`;
  ml.classList.toggle('hot', loadPct > 80);
  $('#pulseMem').textContent = `${p.memUsedPct} % belegt`;
  const mm = $('#meterMem');
  mm.style.width = `${p.memUsedPct}%`;
  mm.classList.toggle('hot', p.memUsedPct > 85);
  const d = Math.floor(p.uptimeSec / 86400);
  const h = Math.floor((p.uptimeSec % 86400) / 3600);
  const m = Math.floor((p.uptimeSec % 3600) / 60);
  $('#pulseUptime').textContent = `${d}d ${h}h ${m}m`;
  $('#pulseStream').textContent = `live · ${fmtTime(p.ts)}`;
  renderSessions(p.sessions);
}

/* =========================================================================
   SSE-Verbindung
   ========================================================================= */
let es = null;
let reconnectDelay = 2000;

function connectLive() {
  if (es) es.close();
  es = new EventSource('/api/live');
  const pill = $('#livePill');

  es.onopen = () => {
    pill.classList.remove('off');
    $('#liveLabel').textContent = 'LIVE';
    reconnectDelay = 2000;
  };
  es.onerror = () => {
    pill.classList.add('off');
    $('#liveLabel').textContent = 'Verbindung verloren – neu verbinden…';
    $('#pulseStream').textContent = 'getrennt';
    es.close();
    setTimeout(connectLive, reconnectDelay);
    reconnectDelay = Math.min(reconnectDelay * 1.5, 20000);
  };

  es.addEventListener('ssh', (ev) => {
    const data = JSON.parse(ev.data);
    Object.assign(state.geo, data.geo || {});
    const warn = $('#feedWarning');
    warn.textContent = data.warning ? `⚠️ ${data.warning}` : '';
    $('#pulseSource').textContent = data.source || '–';
    if (data.initial) {
      pushEvents(data.events, true);
      if (!data.events.length && !data.warning) $('#feedEmpty').textContent = 'Keine SSH-Ereignisse im Zeitfenster.';
    } else if (state.paused) {
      state.pending.push(...data.events);
      $('#liveLabel').textContent = `PAUSE · ${state.pending.length} neu`;
    } else {
      pushEvents(data.events, false);
    }
    refreshGeoLabels();
  });
  es.addEventListener('stats', (ev) => renderStats(JSON.parse(ev.data)));
  es.addEventListener('blocklist', (ev) => {
    const data = JSON.parse(ev.data);
    state.blocked = data.blocked || {};
    renderBlocklist(data.blocked);
    renderSecurityEvents(data.events);
    if (state.stats) renderTopIps(state.stats.topIps);
  });
  es.addEventListener('pulse', (ev) => renderPulse(JSON.parse(ev.data)));
  es.addEventListener('error', (ev) => {
    try {
      const d = JSON.parse(ev.data);
      if (d && d.message) toast(`Stream-Fehler: ${d.message}`, 'danger');
    } catch {
      /* natives Verbindungs-Event, wird von onerror behandelt */
    }
  });
}

/* =========================================================================
   Blockliste / Security-Events
   ========================================================================= */
function renderBlocklist(list) {
  const body = $('#blocklistBody');
  const entries = Object.entries(list || {});
  $('#statBlocked').textContent = entries.length;
  const dayStart = new Date();
  dayStart.setHours(0, 0, 0, 0);
  $('#statBlockedToday').textContent = entries.filter(([, i]) => i.blockedAt && new Date(i.blockedAt) >= dayStart).length;

  if (!entries.length) {
    body.innerHTML = '<tr><td colspan="6" class="status-ok">Keine gesperrten IPs 🎉</td></tr>';
    return;
  }
  // Geo fuer gesperrte IPs nachladen (gecacht serverseitig)
  const missing = entries.map(([ip]) => ip).filter((ip) => !state.geo[ip]);
  if (missing.length) {
    api(`/api/ssh/geo?ips=${encodeURIComponent(missing.join(','))}`)
      .then((g) => {
        Object.assign(state.geo, g);
        refreshGeoLabels();
      })
      .catch(() => {});
  }
  body.innerHTML = entries
    .sort((a, b) => new Date(b[1].blockedAt || 0) - new Date(a[1].blockedAt || 0))
    .map(
      ([ip, info]) => `
      <tr>
        <td><span class="ip">${esc(ip)}</span><br><span class="muted small">${info.blockedAt ? fmtDateTime(info.blockedAt) : ''}</span></td>
        <td><span class="ip-geo" data-geo="${esc(ip)}">${geoLabel(ip)}</span></td>
        <td>${esc(info.reason || '–')}</td>
        <td>${esc(info.source || '–')}</td>
        <td>${icon(info.nftSynced)} nft${info.opnsenseSynced ? ' + OPN' : ''}</td>
        <td><button data-unblock-ip="${esc(ip)}" class="btn btn-sm">Entsperren</button></td>
      </tr>`,
    )
    .join('');
}

function renderSecurityEvents(events) {
  const list = $('#securityEventsList');
  if (!events || !events.length) {
    list.innerHTML = '<li class="muted">Noch keine Ereignisse.</li>';
    return;
  }
  const label = { block: '🚫 Gesperrt', unblock: '✅ Entsperrt', 'usb-detected': '🔌 USB-Gerät erkannt' };
  list.innerHTML = events
    .map((e) => {
      const detail = e.ip ? `${e.ip} – ${e.reason || ''}` : e.detail || '';
      return `<li><time title="${esc(fmtDateTime(e.timestamp))}">${fmtTime(e.timestamp)}</time><div><div class="ev-title">${label[e.type] || esc(e.type)}</div><div class="ev-detail">${esc(detail)}</div></div></li>`;
    })
    .join('');
}

async function blockIp(ip, reason) {
  try {
    const res = await api('/api/blocklist', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, reason }),
    });
    if (!res.ok) {
      toast(`Sperren fehlgeschlagen: ${res.error || 'unbekannter Fehler'}`, 'danger');
      return false;
    }
    toast(`${ip} gesperrt${res.nft && res.nft.ok === false ? ' (nftables-Sync fehlgeschlagen!)' : ''}`, 'ok');
    return true;
  } catch (err) {
    toast(`Sperren fehlgeschlagen: ${err.message}`, 'danger');
    return false;
  }
}

// Delegation fuer alle Sperren/Entsperren-Buttons (Feed, Top-Liste, Tabelle)
document.addEventListener('click', async (ev) => {
  const b = ev.target.closest('[data-block-ip]');
  if (b) {
    b.disabled = true;
    await blockIp(b.dataset.blockIp, 'Manuell über Dashboard gesperrt (Live-Feed)');
    return;
  }
  const u = ev.target.closest('[data-unblock-ip]');
  if (u) {
    const ip = u.dataset.unblockIp;
    if (!confirm(`IP ${ip} wirklich entsperren?`)) return;
    try {
      await api(`/api/blocklist/${encodeURIComponent(ip)}`, { method: 'DELETE' });
      toast(`${ip} entsperrt`, 'ok');
    } catch (err) {
      toast(`Entsperren fehlgeschlagen: ${err.message}`, 'danger');
    }
  }
});

$('#blockIpBtn').addEventListener('click', async () => {
  const input = $('#blockIpInput');
  const ip = input.value.trim();
  if (!ip) return;
  if (await blockIp(ip, 'Manuell über Dashboard gesperrt')) input.value = '';
});
$('#blockIpInput').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') $('#blockIpBtn').click();
});

$('#filterFailed').addEventListener('change', applyFeedFilter);
$('#filterAccepted').addEventListener('change', applyFeedFilter);
$('#filterPause').addEventListener('change', (e) => {
  state.paused = e.target.checked;
  if (!state.paused) {
    pushEvents(state.pending, false);
    state.pending = [];
    $('#liveLabel').textContent = 'LIVE';
  } else {
    $('#liveLabel').textContent = 'PAUSE';
  }
});

/* =========================================================================
   Scan-Karten (bestehende Funktionen)
   ========================================================================= */
function setCardState(id, ok) {
  const card = $(id);
  card.classList.toggle('pulse-ok', ok === true);
  card.classList.toggle('pulse-bad', ok === false);
}

function renderFirewall(fw) {
  const el = $('#card-firewall .body');
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
  parts.push(
    kv(
      'fail2ban',
      fw.fail2ban.available
        ? fw.fail2ban.running
          ? `${icon(true)} ${fw.fail2ban.jails.length} Jail(s)`
          : icon(false)
        : '<span class="muted">nicht installiert</span>',
    ),
  );
  el.innerHTML = parts.join('');
  setCardState('#card-firewall', Boolean(fw.servnix.active || fw.ufw.active));
}

function renderDdos(fw) {
  const d = fw.ddos;
  $('#card-ddos .body').innerHTML = [
    kv('SYN-Cookies', icon(d.synCookiesOn)),
    kv('rp_filter (Anti-Spoofing)', icon(d.rpFilterOn)),
    kv('ICMP-Redirects deaktiviert', icon(d.redirectsOff)),
  ].join('');
  setCardState('#card-ddos', Boolean(d.synCookiesOn && d.rpFilterOn && d.redirectsOff));
}

function renderPorts(fw) {
  const el = $('#card-ports .body');
  if (!fw.ports.available) {
    el.innerHTML = '<p class="muted">Nicht verfügbar</p>';
    return;
  }
  const rows = fw.ports.ports.map((p) => kv(`${esc(p.proto)} ${esc(p.address)}`, p.port)).join('');
  el.innerHTML = rows + kv('Unerwartete Ports', fw.ports.unexpectedCount);
  setCardState('#card-ports', fw.ports.unexpectedCount === 0);
}

function renderSsl(ssl) {
  const el = $('#card-ssl .body');
  if (!ssl.reachable) {
    el.innerHTML = `<p class="muted">Nicht erreichbar: ${esc(ssl.error)}</p>`;
    setCardState('#card-ssl', null);
    return;
  }
  el.innerHTML = [
    kv('Grade', ssl.grade),
    kv('Protokoll', ssl.protocol),
    kv('Läuft ab in', `${ssl.daysRemaining} Tagen`),
    kv('Aussteller', esc(ssl.issuer || '–')),
  ].join('');
  setCardState('#card-ssl', ssl.daysRemaining > 14);
}

function renderHeaders(headers) {
  const el = $('#card-headers .body');
  if (!headers.reachable) {
    el.innerHTML = `<p class="muted">Nicht erreichbar: ${esc(headers.error)}</p>`;
    return;
  }
  el.innerHTML = headers.findings.map((f) => kv(esc(f.name), icon(f.present))).join('');
  setCardState('#card-headers', headers.findings.every((f) => f.present));
}

function renderWebVuln(web) {
  const el = $('#card-webvuln .body');
  if (!web || !web.reachable) {
    el.innerHTML = `<p class="muted">Nicht erreichbar: ${esc((web && web.error) || 'unbekannt')}</p>`;
    return;
  }
  const checks = [
    ['Sensible Dateien öffentlich', !web.exposedFiles || web.exposedFiles.length === 0],
    ['Gefährliche HTTP-Methoden', !web.methods || !web.methods.dangerous || web.methods.dangerous.length === 0],
    ['CORS-Fehlkonfiguration', !(web.cors && web.cors.wildcardWithCredentials)],
    ['Directory-Listing', !web.directoryListing],
    ['Versionsangabe im Header', !(web.banner && web.banner.versionLeak)],
  ];
  const parts = checks.map(([l, ok]) => kv(l, icon(ok)));
  if (web.exposedFiles && web.exposedFiles.length) parts.splice(1, 0, kv('Gefundene Pfade', esc(web.exposedFiles.join(', '))));
  el.innerHTML = parts.join('');
  setCardState('#card-webvuln', checks.every(([, ok]) => ok));
}

function renderDeps(deps) {
  $('#card-deps .body').innerHTML = [
    kv('npm audit', deps.npm.available ? `${icon(deps.npm.total === 0)} ${deps.npm.total} Vulns` : '<span class="muted">n/a</span>'),
    kv('pip-audit', deps.pip.available ? `${icon(deps.pip.total === 0)} ${deps.pip.total} Vulns` : '<span class="muted">n/a</span>'),
  ].join('');
  setCardState('#card-deps', (deps.npm.total || 0) + (deps.pip.total || 0) === 0);
}

function renderSystem(system) {
  $('#card-system .body').innerHTML = [
    kv('OS', esc(system.osRelease || system.platform)),
    kv('Kernel', esc(system.kernelVersion)),
    kv('Uptime', esc(system.uptime || '–')),
    kv('RAM frei/gesamt', `${system.freeMemGB} / ${system.totalMemGB} GB`),
    kv('UID-0-Accounts', esc((system.uidZeroAccounts || []).join(', '))),
  ].join('');
}

function renderScore(score) {
  const v = Number(score.scoreOutOf10) || 0;
  $('#scoreValue').textContent = score.scoreOutOf10;
  const ring = $('#ringFg');
  const circ = 2 * Math.PI * 52;
  ring.style.strokeDashoffset = circ - (v / 10) * circ;
  const color = v >= 8 ? 'var(--ok)' : v >= 5 ? 'var(--warn)' : 'var(--danger)';
  ring.style.stroke = color;
  ring.style.color = color;
  $('#scoreValue').style.color = color;
  const list = $('#findingsList');
  list.innerHTML = score.findings.length
    ? score.findings.map((f) => `<li>${esc(f)}</li>`).join('')
    : '<li class="status-ok">Keine offenen Punkte 🎉</li>';
}

function renderScan(result) {
  $('#lastScan').textContent = `Letzter Scan: ${fmtDateTime(result.timestamp)}`;
  renderFirewall(result.firewall);
  renderDdos(result.firewall);
  renderPorts(result.firewall);
  renderSsl(result.ssl);
  renderHeaders(result.headers);
  renderWebVuln(result.webVulnerabilities);
  renderDeps(result.dependencies);
  renderSystem(result.system);
  renderScore(result.score);
}

async function loadLatest() {
  try {
    const data = await api('/api/scan/latest');
    if (data && !data.error) renderScan(data);
  } catch {
    /* noch kein Scan vorhanden */
  }
}

async function triggerScan() {
  const btn = $('#scanBtn');
  btn.disabled = true;
  btn.classList.add('busy');
  try {
    const data = await api('/api/scan', { method: 'POST' });
    if (data.error) throw new Error(data.error);
    renderScan(data);
    toast('Scan abgeschlossen', 'ok');
  } catch (err) {
    toast('Scan fehlgeschlagen: ' + err.message, 'danger');
  } finally {
    btn.disabled = false;
    btn.classList.remove('busy');
  }
}

async function loadOpnsense() {
  try {
    const cfg = await api('/api/opnsense/config');
    const statusEl = $('#opnsenseStatus');
    const hintEl = $('#opnsenseHint');
    if (!cfg.configured) {
      statusEl.innerHTML = `${icon(false)} Nicht konfiguriert`;
      hintEl.classList.remove('hidden');
      return;
    }
    const test = await api('/api/opnsense/test');
    if (test.connected) {
      statusEl.innerHTML = `${icon(true)} Verbunden mit ${esc(cfg.host)}`;
      hintEl.classList.add('hidden');
      setCardState('#card-opnsense', true);
      const rules = await api('/api/opnsense/rules');
      if (rules.ok && rules.data && Array.isArray(rules.data.rows)) {
        $('#opnsenseRules').innerHTML = kv('Firewall-Regeln', rules.data.rows.length);
      }
    } else {
      statusEl.innerHTML = `${icon(false)} Verbindung fehlgeschlagen: ${esc(test.error)}`;
      hintEl.classList.remove('hidden');
      setCardState('#card-opnsense', false);
    }
  } catch (err) {
    $('#opnsenseStatus').textContent = `Fehler: ${err.message}`;
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

async function loadHardeningStatus() {
  const el = $('#hardeningBody');
  try {
    const s = await api('/api/hardening/status');
    el.innerHTML =
      [
        kv('Security-Header (Helmet)', icon(s.securityHeaders)),
        kv('Dashboard-Passwort gesetzt', icon(s.dashboardAuth)),
        kv('Login-Bruteforce-Schutz', `${icon(true)} ${s.loginBruteforceProtection.maxFailures} Versuche / ${s.loginBruteforceProtection.windowMinutes} Min.`),
        kv('App-Rate-Limiting', `${icon(true)} ${s.rateLimiting.maxRequests} Req. / ${s.rateLimiting.windowSeconds}s`),
        kv('Guard-Allowlist gesetzt', icon(s.guardAllowlistConfigured)),
        kv('Host-Bindung', esc(s.hostBinding)),
      ].join('') +
      (s.hostBinding === '127.0.0.1' || s.hostBinding === 'localhost'
        ? '<p class="hint hint-spaced">Über den SSH-Tunnel sieht das Dashboard jeden Zugriff als 127.0.0.1 – die Login-Bruteforce-Sperre schützt daher primär bei abweichender HOST-Konfiguration (z. B. hinter einem Reverse-Proxy). Den SSH-Zugang selbst schützt der Servnix Guard / fail2ban.</p>'
        : '');
    setCardState('#card-hardening', Boolean(s.dashboardAuth && s.guardAllowlistConfigured));
  } catch (err) {
    el.innerHTML = `<p class="muted">Fehler: ${esc(err.message)}</p>`;
  }
}

/* =========================================================================
   Start
   ========================================================================= */
$('#scanBtn').addEventListener('click', triggerScan);
bindFirewallActions();
loadLatest();
loadOpnsense();
loadHardeningStatus();
connectLive();
setInterval(loadLatest, 60000);
