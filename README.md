<div align="center">

<img src="https://raw.githubusercontent.com/nick-rift/Servnix/main/assets/logo.svg" width="120" height="120" alt="Servnix Logo">

# ⚡ SERVNIX ⚡
### Server-Sicherheits-Dashboard mit echter Firewall, echten Scans und OPNsense-Anbindung

**Kein Kundenservice. Kein Support-Bullshit. Nur Code, der wirklich läuft.**

[![TikTok](https://img.shields.io/badge/TikTok-@nick.rift-000000?style=for-the-badge&logo=tiktok&logoColor=white)](https://www.tiktok.com/@nick.rift)
[![Instagram](https://img.shields.io/badge/Instagram-@nick.rift-E4405F?style=for-the-badge&logo=instagram&logoColor=white)](https://www.instagram.com/nick.rift)
[![License](https://img.shields.io/badge/License-LGPL_2.1-blue?style=for-the-badge)](LICENSE)

</div>

---

## 🎯 Was ist Servnix wirklich?

Servnix ist ein selbst gehostetes Node.js-Dashboard, das auf deinem Server läuft und drei Dinge tatsächlich tut:

1. **Es scannt deinen Server live** – Firewall-Status, offene Ports, TLS/SSL-Zertifikat, HTTP-Security-Header, npm/pip-Vulnerabilities, Kernel/OS, fail2ban – alles per echten System-Kommandos (`nft`, `ss`, `openssl`, `npm audit`, `sysctl`, …), nicht per Beispieldaten.
2. **Es bringt eine eigene Firewall mit** – `servnix-firewall.sh` baut ein nftables-Regelwerk mit Default-Deny, Stateful Filtering, SYN-Flood-/Portscan-Schutz und Rate-Limiting, komplett unabhängig von OPNsense.
3. **Es kann optional mit OPNsense sprechen** – über die offizielle OPNsense-REST-API (API-Key/Secret), um Regeln/Status abzufragen und IPs zu sperren.

Was Servnix **nicht** ist: ein fertiges SOC, ein Pentest-Tool oder eine Compliance-Zertifizierung. Jede Zahl im Dashboard kommt aus einem echten Check auf deinem System. Wenn ein Tool fehlt (z. B. `fail2ban`), steht das ehrlich als "nicht installiert" da – nicht als grüner Haken.

---

## ⚡ Was tatsächlich funktioniert

| Bereich | Was gecheckt wird | Womit |
|---|---|---|
| **Firewall** | Servnix-nftables-Status, ufw-Status, offene Ports, Default-Deny, Rate-Limiting | `nft`, `ufw`, `ss` |
| **DDoS-Härtung** | SYN-Cookies, rp_filter (Anti-Spoofing), ICMP-Redirects | `sysctl` |
| **Brute-Force-Schutz** | fail2ban-Status & aktive Jails | `fail2ban-client` |
| **TLS/SSL** | Reales Zertifikat, Protokollversion, Gültigkeit, Cipher | Node `tls`-Modul |
| **HTTP-Security-Header** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy | echter HTTP-Request |
| **Dependency-Audit** | npm-Vulnerabilities, Python-Vulnerabilities | `npm audit`, `pip-audit` |
| **System** | Kernel-Version, OS, UID-0-Accounts, letzte Logins | `uname`, `/etc/passwd`, `last` |
| **OPNsense** | Verbindungstest, Firewall-Regeln, System-Health, IP blocken | OPNsense REST API |

Aus allen Checks wird ein **nachvollziehbarer Security-Score** berechnet (`server/lib/score.js`) – jede Regel steht im Code, nichts wird geraten.

---

## 🧱 Die Servnix-Firewall (eigenständig, ohne OPNsense)

`scripts/servnix-firewall.sh` legt eine eigene nftables-Tabelle `servnix_fw` an:

- **Default-Deny** auf `INPUT` – alles, was nicht explizit erlaubt ist, wird verworfen.
- **Stateful Filtering** – nur Pakete zu bereits etablierten/eigenen Verbindungen kommen durch.
- **Portscan-Erkennung** – klassische Scan-Flag-Kombinationen (NULL-Scan, SYN-FIN, SYN-RST) werden verworfen.
- **SYN-Flood-/DDoS-Rate-Limiting** – neue Verbindungen werden pro Sekunde begrenzt, SSH zusätzlich strenger.
- **Kernel-Härtung** – SYN-Cookies, rp_filter, deaktivierte ICMP-Redirects werden per `sysctl` gesetzt.
- **Persistenz** – die Regeln werden unter `/etc/nftables.servnix/` gespeichert und per systemd-Service beim Boot geladen.

```bash
sudo ./scripts/servnix-firewall.sh install   # einmalig einrichten (braucht root)
sudo ./scripts/servnix-firewall.sh status    # aktuelles Regelwerk anzeigen
sudo ./scripts/servnix-firewall.sh disable   # nur im Notfall - Server ist danach ungeschützt
```

Anpassbar über Umgebungsvariablen: `SERVNIX_ALLOW_TCP_PORTS="22,80,443"`, `SERVNIX_SSH_PORT="22"`.

Das Dashboard kann `install` / `enable` / `disable` / `status` auch per Button auslösen (Server braucht dafür passwortlose `sudo`-Rechte für genau dieses Script – siehe [docs/INSTALLATION.md](docs/INSTALLATION.md)).

---

## 🔗 OPNsense-Anbindung (optional)

Wenn du bereits eine OPNsense-Firewall betreibst, kann Servnix sich damit verbinden statt (oder zusätzlich zu) der eigenen nftables-Firewall:

1. In OPNsense: **System → Access → Users → API Keys** → neuen Key erzeugen.
2. In `.env`: `OPNSENSE_HOST`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET` eintragen.
3. Dashboard neu starten – die OPNsense-Kachel zeigt Verbindungsstatus, Regelanzahl und System-Health live an.
4. Über `/api/opnsense/block-ip` kann eine IP sofort in einen OPNsense-Alias gesperrt werden.

Ohne gültige Zugangsdaten zeigt das Dashboard ehrlich "nicht konfiguriert" bzw. den echten Verbindungsfehler an – es wird nichts vorgetäuscht.

---

## 🚀 Installation & Setup

**1. Repository klonen**
```bash
git clone https://github.com/nick-rift/Servnix.git
cd Servnix
chmod +x scripts/*.sh
```

**2. System validieren & Abhängigkeiten installieren**
```bash
./scripts/validate-system.sh
./scripts/install-dependencies.sh   # installiert u.a. nftables + fail2ban
```

**3. Konfigurieren**
```bash
cp .env.example .env
nano .env
```
Wichtig: Setze ein Dashboard-Passwort, sonst ist das Dashboard ungeschützt erreichbar:
```bash
node server/cli-hash-password.js "DeinSicheresPasswort"
# Ergebnis in .env als DASHBOARD_PASSWORD_HASH eintragen
```

**4. Eigene Firewall einrichten (optional, empfohlen)**
```bash
sudo ./scripts/servnix-firewall.sh install
```

**5. Dashboard starten**
```bash
npm install
npm start
```
```
Servnix Dashboard laeuft auf http://127.0.0.1:3000
→ Nur lokal erreichbar (Sicherheitsvorgabe). Zugriff von deinem PC per SSH-Tunnel:
   ssh -L 3000:localhost:3000 <user>@<server-ip>
   Danach im Browser: http://localhost:3000
```

**6. Ersten Scan ausführen**
```bash
./scripts/security-scan.sh
# oder direkt im Dashboard auf "Scan jetzt ausführen" klicken
```

---

## 🖥️ Dashboard aufrufen (nur über localhost, nicht über die Server-IP)

Aus Sicherheitsgründen bindet der Server standardmäßig **nur an `127.0.0.1`** (siehe `HOST` in
`.env.example`). Das Dashboard ist also **nie** direkt über die öffentliche Server-IP oder eine
Domain erreichbar – auch nicht, wenn Firewall-Ports offen wären. Zugriff von deinem eigenen
Rechner läuft über einen SSH-Tunnel:

**Auf deinem lokalen PC/Mac/Laptop** (nicht auf dem Server):
```bash
ssh -L 3000:localhost:3000 <dein-user>@<server-ip>
```
Dieser Befehl baut eine verschlüsselte Verbindung zum Server auf und leitet `localhost:3000`
auf deinem PC durch den Tunnel zum Dashboard auf dem Server weiter. Die SSH-Sitzung muss dabei
offen bleiben (Terminal-Fenster nicht schließen).

**Danach im Browser auf deinem PC öffnen:**
```
http://localhost:3000
```
Login mit `DASHBOARD_USER` (Standard: `admin`) und dem Passwort, das du mit
`node server/cli-hash-password.js` gesetzt hast.

Sobald du den Tunnel schließt (SSH-Sitzung beenden), ist das Dashboard von deinem PC aus
nicht mehr erreichbar – und war es von überall sonst im Internet nie.

**Alternative:** Läuft der Server dauerhaft, kannst du den Tunnel bequem im Hintergrund halten:
```bash
ssh -f -N -L 3000:localhost:3000 <dein-user>@<server-ip>
```
(`-f` schickt SSH in den Hintergrund, `-N` öffnet keine Shell, nur den Tunnel.)

Ein Reverse-Proxy mit eigenem TLS-Zertifikat und eigener Domain ist bewusst **nicht** die
empfohlene Standardlösung, weil Servnix damit Angriffsfläche im Netz hätte. Wer das trotzdem
möchte, kann `HOST=0.0.0.0` setzen und selbst einen abgesicherten Reverse-Proxy davorsetzen –
siehe Warnhinweis dazu in `.env.example`.

---

## 📊 Das Dashboard

Kein Mockup – ein reales, per Express ausgeliefertes Web-Interface (`public/`), das ausschließlich die eigene API konsumiert:

- **Security-Score** mit nachvollziehbarer Punkteliste (was genau fehlt und warum)
- **Firewall-Status** (Servnix-nftables + ufw), Port-Übersicht, DDoS-Härtung, fail2ban-Jails
- **TLS/SSL-Status** mit echtem Ablaufdatum und Protokoll
- **HTTP-Security-Header-Check**
- **Dependency-Audit** (npm/pip)
- **OPNsense-Kachel** mit Live-Verbindungsstatus
- **Firewall-Steuerung** (install/enable/disable/status per Klick)

Alle 30 Sekunden aktualisiert sich der zuletzt gespeicherte Scan automatisch; ein neuer Voll-Scan wird per Button oder `POST /api/scan` ausgelöst.

---

## 🔐 Sicherheits-Realitätscheck

| ✅ Was stimmt | ❌ Was Servnix NICHT ersetzt |
|---|---|
| Echte, live geprüfte Firewall-/TLS-/Header-/Dependency-Daten | Ein zertifiziertes Pentest oder einen Security-Audit durch Dritte |
| Eine funktionierende, eigenständige nftables-Firewall | WAF-Schutz auf Layer 7 gegen komplexe Angriffe |
| Echte OPNsense-API-Anbindung (Basic Auth mit Key/Secret) | Enterprise-DDoS-Schutz auf Netzwerkebene (dafür brauchst du einen Provider wie Cloudflare/OPNsense mit ausreichend Bandbreite) |
| Ein Score, dessen Berechnung offen im Code liegt | Eine Garantie für "100% sicher" – das gibt es nicht |

---

## 📋 API-Endpunkte

```
GET  /api/health                    Health-Check
GET  /api/scan/latest               letzten gespeicherten Scan abrufen
POST /api/scan                      neuen Voll-Scan ausführen
GET  /api/firewall/status           Firewall-Rohdaten
POST /api/firewall/servnix/:action  install | enable | disable | status
GET  /api/opnsense/config           Konfigurationsstatus (ohne Secrets)
GET  /api/opnsense/test             Verbindungstest
GET  /api/opnsense/rules            Firewall-Regeln von OPNsense
GET  /api/opnsense/health           System-Health von OPNsense
POST /api/opnsense/block-ip         IP per OPNsense-Alias sperren
```

Alle Endpunkte sind durch HTTP Basic Auth geschützt, sobald `DASHBOARD_PASSWORD_HASH` gesetzt ist.

---

## 🎓 Dokumentation

| Datei | Inhalt |
|-------|--------|
| [docs/INSTALLATION.md](docs/INSTALLATION.md) | Ausführlicher Setup-Guide inkl. sudo-Rechte fürs Firewall-Script |
| [docs/SECURITY.md](docs/SECURITY.md) | Was Servnix prüft, was nicht, wie man Findings meldet |
| [docs/API.md](docs/API.md) | Vollständige API-Referenz |

---

## 🤝 Contributing

```bash
1. Fork the repository
2. git checkout -b feature/amazing-feature
3. git commit -m 'Add amazing feature'
4. git push origin feature/amazing-feature
5. Open a Pull Request
```

---

<div align="center">

📜 Lizenz: [LGPL 2.1](LICENSE)

**Made with 🛡️ für echte Server-Sicherheit – ohne Bullshit.**

</div>
