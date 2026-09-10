"use strict";

const THEME_KEY = "nick-firewall-theme";
const $ = (sel) => document.querySelector(sel);

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function statusTone(ok) {
  if (ok === true) return "ok";
  if (ok === false) return "bad";
  return "warn";
}

function statusChip(label, tone = "neutral") {
  return `<span class="status-chip status-chip-${tone}">${escapeHtml(label)}</span>`;
}

function metricRow(label, value) {
  return `<div class="metric-row"><strong>${escapeHtml(label)}</strong><span class="metric-value">${value}</span></div>`;
}

function note(text) {
  return `<div class="muted-note">${escapeHtml(text)}</div>`;
}

function skeletonMarkup(lines = 4) {
  const widths = ["long", "medium", "short", "long", "medium"];
  return `<div class="skeleton-group">${Array.from({ length: lines }, (_, i) => `<div class="skeleton-line ${widths[i % widths.length]}"></div>`).join("")}</div>`;
}

function setLoadingStates() {
  [
    "#card-firewall .body",
    "#card-ddos .body",
    "#card-ssl .body",
    "#card-headers .body",
    "#card-deps .body",
    "#card-webvuln .body",
    "#card-system .body",
    "#hardeningBody",
    "#opnsenseStatus",
    "#blocklistBody",
    "#securityEventsList",
  ].forEach((selector) => {
    const el = $(selector);
    if (!el) return;
    if (selector === "#blocklistBody") {
      el.innerHTML = `<tr><td colspan="5">${skeletonMarkup(3)}</td></tr>`;
      return;
    }
    if (selector === "#securityEventsList") {
      el.innerHTML = `<li>${skeletonMarkup(3)}</li>`;
      return;
    }
    el.innerHTML = skeletonMarkup();
  });
}

async function api(path, options) {
  const res = await fetch(path, options);
  const data = await res.json().catch(() => ({}));
  if (!res.ok && res.status !== 404) {
    throw new Error(data.error || `API-Fehler ${res.status}`);
  }
  return data;
}

function toast(title, message, type = "info") {
  const region = $("#toastRegion");
  const el = document.createElement("div");
  el.className = `toast ${type}`;
  el.innerHTML = `<strong>${escapeHtml(title)}</strong><span>${escapeHtml(message)}</span>`;
  region.appendChild(el);
  setTimeout(() => el.remove(), 4200);
}

function scoreColor(score) {
  if (score >= 8) return "var(--success)";
  if (score >= 5) return "var(--warn)";
  return "var(--danger)";
}

function scoreSummary(score) {
  if (score >= 8) return "Starke Basis. Jetzt die restlichen Details sauber halten.";
  if (score >= 5) return "Solider Start, aber mehrere Schutzluecken sollten zeitnah geschlossen werden.";
  return "Hoher Handlungsbedarf: wichtige Schutzmechanismen fehlen oder schlagen fehl.";
}

function renderFirewall(fw) {
  const el = $("#card-firewall .body");
  const active = fw.servnix.active || (fw.ufw && fw.ufw.active);
  const rows = [];
  if (fw.servnix.active) {
    rows.push(metricRow("Aktive Engine", `${statusChip("Nick Firewall aktiv", "ok")} <span class="muted">(${escapeHtml(fw.servnix.tableName || "n/a")})</span>`));
    rows.push(metricRow("Default-Deny", statusChip(fw.servnix.defaultDeny ? "aktiv" : "fehlt", statusTone(fw.servnix.defaultDeny))));
    rows.push(metricRow("Stateful Filtering", statusChip(fw.servnix.statefulFiltering ? "aktiv" : "fehlt", statusTone(fw.servnix.statefulFiltering))));
    rows.push(metricRow("Rate-Limiting", statusChip(fw.servnix.rateLimiting ? "aktiv" : "fehlt", statusTone(fw.servnix.rateLimiting))));
    rows.push(metricRow("Geladene Regeln", escapeHtml(fw.servnix.ruleCount)));
  } else if (fw.ufw.active) {
    rows.push(metricRow("Aktive Engine", `${statusChip("ufw aktiv", "warn")} <span class="muted">(${escapeHtml(fw.ufw.rules.length)} Regel(n))</span>`));
    rows.push(metricRow("Einordnung", escapeHtml("Servnix/Nick-Regelwerk ist nicht geladen, aber ufw schuetzt den Host.")));
  } else {
    rows.push(metricRow("Aktive Engine", statusChip("keine aktive Firewall gefunden", "bad")));
    rows.push(metricRow("Risiko", escapeHtml("Eingehender Traffic wird aktuell nicht durch Nick Firewall oder ufw gefiltert.")));
  }
  rows.push(metricRow("fail2ban", fw.fail2ban.available ? statusChip(fw.fail2ban.running ? `${fw.fail2ban.jails.length} Jail(s) aktiv` : "installiert, aber nicht aktiv", fw.fail2ban.running ? "ok" : "warn") : statusChip("nicht installiert", "warn")));
  if (!active) rows.push(note("Wenn das Dashboard auf einem oeffentlichen Server laeuft, sollte mindestens eine echte Host-Firewall aktiv sein."));
  el.innerHTML = `<div class="metric-list">${rows.join("")}</div>`;
}

function renderDdos(fw) {
  const d = fw.ddos;
  const el = $("#card-ddos .body");
  el.innerHTML = `<div class="metric-list">${[
    metricRow("SYN-Cookies", statusChip(d.synCookiesOn ? "aktiv" : "aus", statusTone(d.synCookiesOn))),
    metricRow("Anti-Spoofing (rp_filter)", statusChip(d.rpFilterOn ? "aktiv" : "aus", statusTone(d.rpFilterOn))),
    metricRow("ICMP-Redirects", statusChip(d.redirectsOff ? "deaktiviert" : "noch aktiv", statusTone(d.redirectsOff))),
    metricRow("Warum wichtig?", escapeHtml("Diese Schalter helfen gegen einfache Floods, Spoofing und riskante Routing-Umleitungen.")),
  ].join("")}</div>`;
}

function renderSsl(ssl) {
  const el = $("#card-ssl .body");
  if (!ssl.reachable) {
    el.innerHTML = note(`TLS-Check nicht erreichbar: ${ssl.error || "unbekannt"}`);
    return;
  }
  el.innerHTML = `<div class="metric-list">${[
    metricRow("Bewertung", statusChip(ssl.grade || "unbekannt", ssl.daysRemaining > 30 ? "ok" : "warn")),
    metricRow("Protokoll", escapeHtml(ssl.protocol || "–")),
    metricRow("Restlaufzeit", `${escapeHtml(ssl.daysRemaining)} Tage`),
    metricRow("Aussteller", escapeHtml(ssl.issuer || "–")),
  ].join("")}</div>`;
}

function renderHeaders(headers) {
  const el = $("#card-headers .body");
  if (!headers.reachable) {
    el.innerHTML = note(`Header-Check nicht erreichbar: ${headers.error || "unbekannt"}`);
    return;
  }
  el.innerHTML = `<div class="metric-list">${headers.findings.map((f) => metricRow(f.name, statusChip(f.present ? "gesetzt" : "fehlt", statusTone(f.present)))).join("")}</div>`;
}

function renderWebVuln(web) {
  const el = $("#card-webvuln .body");
  if (!web || !web.reachable) {
    el.innerHTML = note(`Website-Scan nicht erreichbar: ${(web && web.error) || "unbekannt"}`);
    return;
  }
  const exposed = web.exposedFiles || [];
  const dangerousMethods = (web.methods && web.methods.dangerous) || [];
  el.innerHTML = `<div class="metric-list">${[
    metricRow("Sensible Dateien", statusChip(exposed.length === 0 ? "nichts offen gefunden" : `${exposed.length} Fund(e)`, exposed.length === 0 ? "ok" : "bad")),
    exposed.length ? metricRow("Gefundene Pfade", escapeHtml(exposed.join(", "))) : "",
    metricRow("Gefaehrliche Methoden", statusChip(dangerousMethods.length === 0 ? "keine erkannt" : dangerousMethods.join(", "), dangerousMethods.length === 0 ? "ok" : "warn")),
    metricRow("CORS mit Credentials", statusChip(web.cors && web.cors.wildcardWithCredentials ? "riskant konfiguriert" : "kein auffaelliger Wildcard-Fall", web.cors && web.cors.wildcardWithCredentials ? "bad" : "ok")),
    metricRow("Directory Listing", statusChip(web.directoryListing ? "sichtbar" : "nicht offen", web.directoryListing ? "warn" : "ok")),
    metricRow("Versions-Banner", statusChip(web.banner && web.banner.versionLeak ? "gibt Versionsinfo preis" : "keine klare Leak-Anzeige", web.banner && web.banner.versionLeak ? "warn" : "ok")),
  ].filter(Boolean).join("")}</div>`;
}

function renderDeps(deps) {
  const el = $("#card-deps .body");
  el.innerHTML = `<div class="metric-list">${[
    metricRow("npm audit", deps.npm.available ? statusChip(`${deps.npm.total} Fund(e)`, deps.npm.total === 0 ? "ok" : "warn") : statusChip("nicht verfuegbar", "warn")),
    metricRow("pip-audit", deps.pip.available ? statusChip(`${deps.pip.total} Fund(e)`, deps.pip.total === 0 ? "ok" : "warn") : statusChip("nicht verfuegbar", "warn")),
    metricRow("Praxis-Hinweis", escapeHtml("Viele bekannte Angriffe starten ueber veraltete Pakete statt ueber spektakulaere 0-Days.")),
  ].join("")}</div>`;
}

function renderSystem(system) {
  const el = $("#card-system .body");
  el.innerHTML = `<div class="metric-list">${[
    metricRow("Betriebssystem", escapeHtml(system.osRelease || system.platform || "–")),
    metricRow("Kernel", escapeHtml(system.kernelVersion || "–")),
    metricRow("Uptime", escapeHtml(system.uptime || "–")),
    metricRow("RAM frei / gesamt", escapeHtml(`${system.freeMemGB} / ${system.totalMemGB} GB`)),
    metricRow("UID-0-Accounts", escapeHtml((system.uidZeroAccounts || []).join(", ") || "–")),
  ].join("")}</div>`;
}

function renderScore(score) {
  const numericScore = Number(score.scoreOutOf10 || 0);
  const ring = $("#scoreRing");
  ring.style.setProperty("--score-angle", `${Math.max(0, Math.min(360, numericScore * 36))}deg`);
  ring.style.setProperty("--score-color", scoreColor(numericScore));
  $("#scoreValue").textContent = numericScore.toFixed(1).replace(/\.0$/, "");
  $("#scoreSummary").textContent = scoreSummary(numericScore);

  const pills = [
    statusChip(numericScore >= 8 ? "Stabile Basis" : numericScore >= 5 ? "Ausbau noetig" : "Kritischer Zustand", statusTone(numericScore >= 8 ? true : numericScore >= 5 ? null : false)),
    statusChip(`${score.findings.length} offene Punkte`, score.findings.length === 0 ? "ok" : score.findings.length < 4 ? "warn" : "bad"),
  ];
  $("#heroPills").innerHTML = pills.join("");

  const list = $("#findingsList");
  if (!score.findings.length) {
    list.innerHTML = `<li>${statusChip("Keine offenen Punkte", "ok")} <span class="muted">Starke Ausgangslage.</span></li>`;
    return;
  }
  list.innerHTML = score.findings.map((finding) => `<li>${escapeHtml(finding)}</li>`).join("");
}

function renderScan(result) {
  const lastScan = $("#lastScan");
  lastScan.className = "status-chip status-chip-neutral";
  lastScan.textContent = `Letzter Scan: ${new Date(result.timestamp).toLocaleString("de-DE")}`;
  renderFirewall(result.firewall);
  renderDdos(result.firewall);
  renderSsl(result.ssl);
  renderHeaders(result.headers);
  renderWebVuln(result.webVulnerabilities);
  renderDeps(result.dependencies);
  renderSystem(result.system);
  renderScore(result.score);
}

async function loadLatest() {
  try {
    const data = await api("/api/scan/latest");
    if (data && !data.error) renderScan(data);
  } catch {
    // Noch kein Scan ist ein erwartbarer Startzustand.
  }
}

async function triggerScan() {
  const btn = $("#scanBtn");
  btn.disabled = true;
  btn.textContent = "Scan laeuft...";
  toast("Live-Scan", "Der Voll-Scan wurde gestartet.", "info");
  try {
    const data = await api("/api/scan", { method: "POST" });
    renderScan(data);
    toast("Scan abgeschlossen", "Die Module wurden mit echten Live-Daten aktualisiert.", "success");
  } catch (err) {
    toast("Scan fehlgeschlagen", err.message, "error");
  } finally {
    btn.disabled = false;
    btn.textContent = "Live-Scan starten";
  }
}

async function loadOpnsense() {
  const cfg = await api("/api/opnsense/config");
  const test = cfg.configured ? await api("/api/opnsense/test") : null;
  const rules = cfg.configured && test.connected ? await api("/api/opnsense/rules") : null;
  renderOpnsenseView(buildOpnsenseViewModel(cfg, test, rules));
}

function buildOpnsenseViewModel(cfg, test, rules) {
  if (!cfg.configured) {
    return {
      statusHtml: statusChip("Nicht konfiguriert", "warn"),
      hintHtml: "Host, API-Key und API-Secret in <code>.env</code> eintragen, dann den Server neu starten. Ohne diese Angaben bleibt nur die lokale Nick Firewall aktiv.",
      showHint: true,
      rulesHtml: "",
    };
  }

  if (test && test.connected) {
    return {
      statusHtml: statusChip(`Verbunden mit ${cfg.host}`, "ok"),
      hintHtml: "",
      showHint: false,
      rulesHtml: rules && rules.ok && rules.data && Array.isArray(rules.data.rows)
        ? `<div class="metric-list">${metricRow("Regeln gefunden", statusChip(`${rules.data.rows.length} Regel(n)`, "ok"))}${metricRow("Einordnung", escapeHtml("Die Edge-Firewall antwortet sauber auf API-Abfragen."))}</div>`
        : note("Verbindung steht, aber es konnten keine Regelobjekte gelesen werden."),
    };
  }

  return {
    statusHtml: statusChip(`Verbindung fehlgeschlagen: ${(test && test.error) || "unbekannt"}`, "bad"),
    hintHtml: "Die Zugangsdaten oder die Erreichbarkeit von OPNsense sollten geprueft werden. Es wird absichtlich kein Erfolg vorgetaeuscht.",
    showHint: true,
    rulesHtml: "",
  };
}

function renderOpnsenseView(viewModel) {
  const statusEl = $("#opnsenseStatus");
  const hintEl = $("#opnsenseHint");
  const rulesEl = $("#opnsenseRules");
  statusEl.innerHTML = viewModel.statusHtml;
  hintEl.innerHTML = viewModel.hintHtml;
  hintEl.classList.toggle("hidden", !viewModel.showHint);
  rulesEl.innerHTML = viewModel.rulesHtml;
}

function bindFirewallActions() {
  document.querySelectorAll("[data-fw-action]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const action = btn.dataset.fwAction;
      const out = $("#fwActionOutput");
      out.textContent = `Fuehre "${action}" aus...`;
      toast("Nick Firewall", `Aktion „${action}“ gestartet.`, "info");
      try {
        const res = await api(`/api/firewall/nick/${action}`, { method: "POST" });
        out.textContent = (res.stdout || "") + (res.stderr || "") + (res.note ? `\n\nHinweis: ${res.note}` : "");
        toast("Nick Firewall", res.ok ? `Aktion „${action}“ abgeschlossen.` : `Aktion „${action}“ beendet mit Rueckmeldung.`, res.ok ? "success" : "info");
        if (["install", "enable", "disable"].includes(action)) loadLatest();
      } catch (err) {
        out.textContent = `Fehler: ${err.message}`;
        toast("Nick Firewall", err.message, "error");
      }
    });
  });
}

async function loadBlocklist() {
  const body = $("#blocklistBody");
  try {
    const list = await api("/api/blocklist");
    const entries = Object.entries(list);
    if (entries.length === 0) {
      body.innerHTML = `<tr><td colspan="5">${statusChip("Keine gesperrten IPs", "ok")}</td></tr>`;
      return;
    }
    body.innerHTML = entries.map(([ip, info]) => `
      <tr>
        <td>${escapeHtml(ip)}</td>
        <td>${escapeHtml(info.reason || "–")}</td>
        <td>${escapeHtml(info.source || "–")}</td>
        <td>${statusChip(info.nftSynced ? `nftables${info.opnsenseSynced ? " + OPNsense" : ""}` : "nur App-Ebene", info.nftSynced ? "ok" : "warn")}</td>
        <td><button type="button" class="danger small-btn" data-unblock-ip="${escapeHtml(ip)}">Entsperren</button></td>
      </tr>`).join("");

    body.querySelectorAll("[data-unblock-ip]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const ip = btn.dataset.unblockIp;
        if (!window.confirm(`IP ${ip} wirklich entsperren?`)) return;
        try {
          await api(`/api/blocklist/${encodeURIComponent(ip)}`, { method: "DELETE" });
          toast("Blockliste", `IP ${ip} wurde entsperrt.`, "success");
          loadBlocklist();
          loadSecurityEvents();
        } catch (err) {
          toast("Entsperren fehlgeschlagen", err.message, "error");
        }
      });
    });
  } catch (err) {
    body.innerHTML = `<tr><td colspan="5">${escapeHtml(err.message)}</td></tr>`;
  }
}

async function loadSecurityEvents() {
  const list = $("#securityEventsList");
  try {
    const events = await api("/api/security-events?limit=50");
    if (!events.length) {
      list.innerHTML = `<li class="muted">Noch keine Ereignisse protokolliert.</li>`;
      return;
    }
    list.innerHTML = events.map((event) => {
      const time = new Date(event.timestamp).toLocaleString("de-DE");
      const typeLabel = {
        block: "🚫 Geblockt",
        unblock: "✅ Entsperrt",
        "usb-detected": "🔌 USB erkannt",
      }[event.type] || event.type;
      const detail = event.ip ? `${event.ip} – ${event.reason || event.source || "keine Zusatzinfo"}` : (event.detail || "kein Detail");
      return `<li><div class="event-line"><span class="event-time">${escapeHtml(time)}</span><span>${escapeHtml(typeLabel)}: ${escapeHtml(detail)}</span></div></li>`;
    }).join("");
  } catch (err) {
    list.innerHTML = `<li class="muted">${escapeHtml(err.message)}</li>`;
  }
}

function bindBlockForm() {
  $("#blockIpBtn").addEventListener("click", async () => {
    const input = $("#blockIpInput");
    const ip = input.value.trim();
    if (!ip) return;
    try {
      const res = await api("/api/blocklist", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip, reason: "Manuell ueber Dashboard gesperrt" }),
      });
      if (!res.ok) {
        toast("Sperren fehlgeschlagen", res.error || "unbekannter Fehler", "error");
        return;
      }
      input.value = "";
      toast("Blockliste", `IP ${ip} wurde aufgenommen.`, "success");
      loadBlocklist();
      loadSecurityEvents();
    } catch (err) {
      toast("Sperren fehlgeschlagen", err.message, "error");
    }
  });
}

async function loadHardeningStatus() {
  const el = $("#hardeningBody");
  try {
    const s = await api("/api/hardening/status");
    el.innerHTML = `<div class="metric-list">${[
      metricRow("Security-Header", statusChip(s.securityHeaders ? "aktiv via Helmet" : "fehlt", statusTone(s.securityHeaders))),
      metricRow("Dashboard-Passwort", statusChip(s.dashboardAuth ? "gesetzt" : "fehlt", statusTone(s.dashboardAuth))),
      metricRow("Login-Bruteforce-Schutz", escapeHtml(`${s.loginBruteforceProtection.maxFailures} Versuche / ${s.loginBruteforceProtection.windowMinutes} Min.`)),
      metricRow("App-Rate-Limit", escapeHtml(`${s.rateLimiting.maxRequests} Requests / ${s.rateLimiting.windowSeconds}s`)),
      metricRow("Guard-Allowlist", statusChip(s.guardAllowlistConfigured ? "gesetzt" : "nicht gesetzt", statusTone(s.guardAllowlistConfigured))),
      metricRow("Bind-Adresse", escapeHtml(s.hostBinding)),
    ].join("")}</div>${(s.hostBinding === "127.0.0.1" || s.hostBinding === "localhost") ? note("Im Standard-Setup ueber SSH-Tunnel sieht das Dashboard nur localhost. Die eigentliche Host-Abwehr gegen SSH-Angriffe bleibt daher Aufgabe von Nick Firewall + Servnix Guard bzw. fail2ban.") : ""}`;
  } catch (err) {
    el.innerHTML = note(err.message);
  }
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const btn = $("#themeToggle");
  btn.textContent = theme === "light" ? "🌙 Dark" : "☀️ Light";
}

function safeGetStoredTheme() {
  try {
    return window.localStorage.getItem(THEME_KEY);
  } catch {
    return null;
  }
}

function safeSetStoredTheme(theme) {
  try {
    window.localStorage.setItem(THEME_KEY, theme);
  } catch {
    // Fallback: Theme bleibt fuer diese Sitzung aktiv, nur ohne Persistenz.
  }
}

function initThemeToggle() {
  const stored = safeGetStoredTheme();
  applyTheme(stored === "light" ? "light" : "dark");
  $("#themeToggle").addEventListener("click", () => {
    const current = document.documentElement.dataset.theme === "light" ? "light" : "dark";
    const next = current === "light" ? "dark" : "light";
    safeSetStoredTheme(next);
    applyTheme(next);
  });
}

function initDashboard() {
  $("#scanBtn").addEventListener("click", triggerScan);
  setLoadingStates();
  initThemeToggle();
  bindFirewallActions();
  bindBlockForm();
  loadLatest();
  loadOpnsense().catch((err) => {
    renderOpnsenseView({
      statusHtml: statusChip(`OPNsense-Check fehlgeschlagen: ${err.message}`, "warn"),
      hintHtml: "",
      showHint: false,
      rulesHtml: "",
    });
  });
  loadBlocklist();
  loadSecurityEvents();
  loadHardeningStatus();
  setInterval(loadLatest, 30000);
  setInterval(loadBlocklist, 30000);
  setInterval(loadSecurityEvents, 30000);
}

if (typeof document !== "undefined") {
  initDashboard();
}

if (typeof module !== "undefined") {
  module.exports = {
    buildOpnsenseViewModel,
    escapeHtml,
    metricRow,
    note,
    safeGetStoredTheme,
    safeSetStoredTheme,
    statusChip,
  };
}
