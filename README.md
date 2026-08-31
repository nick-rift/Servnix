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
| **Guard** | SSH-Bruteforce- & Portscan-Erkennung, automatische IP-Sperrung, USB-Geräte-Alarm | `journalctl`, nftables-Log, `lsusb` |
| **Website-Sicherheit** | Öffentlich erreichbare sensible Dateien (`.env`, `.git`, Backups), gefährliche HTTP-Methoden, CORS-Fehlkonfiguration, Directory-Listing, Versions-Banner | echte HTTP-Requests |
| **Web-Angriffserkennung** | Exploit-Sondierung, SQL-Injection-/XSS-/Path-Traversal-Muster, Scanner-Tools im Access-Log, automatische IP-Sperrung | nginx-/apache-Access-Log |

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

## 🛡️ Servnix Guard – automatische Angriffserkennung & IP-Sperrung

**Wichtig für Ehrlichkeit:** Das ist **keine "KI"** im Sinne von Machine Learning – es ist
regelbasierte, transparente Schwellenwert-Erkennung auf echten Log-Daten. Jede Regel steht
im Code (`server/lib/intrusionDetection.js`), nichts ist eine Blackbox.

Was der Guard (`server/guard.js`) tatsächlich tut:

- **SSH-Bruteforce-Erkennung** – liest `journalctl`/`auth.log` und zählt fehlgeschlagene Logins
  pro IP. Ab `GUARD_SSH_MAX_FAILURES` (Standard: 8) in `GUARD_SSH_WINDOW_MINUTES` (Standard: 10)
  wird die IP automatisch gesperrt.
- **Portscan-Erkennung** – liest das Kernel-Log der Servnix-Firewall (Präfix
  `servnix-scan-attempt:`) und zählt verschiedene angefragte Ports pro IP. Ab
  `GUARD_PORTSCAN_MAX_PORTS` (Standard: 15) in `GUARD_PORTSCAN_WINDOW_MINUTES` (Standard: 5)
  wird die IP automatisch gesperrt.
- **USB-Geräte-Überwachung** – vergleicht `lsusb`-Ausgabe mit dem letzten bekannten Stand und
  meldet neu angeschlossene Geräte als Security-Event. **Das ist reine Erkennung/Alarmierung,
  kein automatisches Sperren von USB-Ports** – Software kann ein bereits physisch eingestecktes
  Gerät ohne zusätzliche Kernel-Policies (z. B. `usbguard`) nicht seriös blocken.

Eine gesperrte IP landet in der nftables-Menge `blackhole_v4` (siehe Servnix-Firewall oben) –
das blockt **den gesamten Server-Traffic dieser IP**, nicht nur das Dashboard. Wer also per SSH
brute-forced oder einen Portscan gegen den Webserver auf Port 80/443 fährt, wird komplett
ausgesperrt, inklusive Zugriff auf jede andere Webseite/jeden anderen Dienst auf demselben
Server. Ist zusätzlich OPNsense konfiguriert, wird die IP auch dort in den Alias eingetragen.

```bash
# Voraussetzung: Servnix-Firewall muss installiert sein (liefert das Scan-Log)
sudo ./scripts/servnix-firewall.sh install

# Eigene IP in .env eintragen, damit du dich nicht selbst aussperrst!
# GUARD_ALLOWLIST=<deine-eigene-ip>

# Guard als systemd-Dienst installieren (läuft dauerhaft, übersteht Reboots)
sudo ./scripts/servnix-guard.sh install
sudo ./scripts/servnix-guard.sh status
sudo journalctl -u servnix-guard -f     # Live-Logs

# Einmaliger Testlauf ohne root/systemd (zeigt nur an, sperrt nur bei echtem Treffer)
./scripts/servnix-guard.sh test
```

Alle Sperrungen, Entsperrungen und USB-Erkennungen werden protokolliert
(`server/data/security-events.log`) und sind im Dashboard unter **"Servnix Guard · Blockliste"**
und **"Security-Events"** einsehbar. Manuelles Sperren/Entsperren einer IP ist dort ebenfalls
per Klick möglich.

⚠️ Ein Entsperren aus einem OPNsense-Alias ist **nicht automatisiert** – dafür müsste die
Alias-Item-UUID aufgelöst werden. Wurde eine IP über OPNsense gesperrt, muss sie dort manuell
aus dem Alias entfernt werden.

---

## 🌐 Website-Schutz (Webserver/Webanwendungen härten)

Server-Firewall und Dashboard-Härtung schützen den Server – aber die meisten erfolgreichen
Angriffe auf gehostete Webseiten laufen über die Webanwendung selbst (offene `.env`-Dateien,
falsch konfiguriertes CORS, ungeschützte Admin-Panels, klassische SQLi/XSS-Sondierung). Dafür
gibt es zwei zusammenspielende Bausteine:

**1. Aktiver Website-Scan** (`server/lib/webVulnScan.js`, Teil von `POST /api/scan`) – stellt
echte HTTP-Requests an die konfigurierte `SCAN_TARGET_URL` und prüft:

- Ob sensible Dateien wie `.env`, `.git/config`, Backups (`.bak`, `.sql`) öffentlich abrufbar sind
- Ob gefährliche HTTP-Methoden (`TRACE`, `PUT`, `DELETE`) erlaubt sind
- CORS-Fehlkonfiguration (`Access-Control-Allow-Origin: *` zusammen mit Credentials)
- Directory-Listing und Versions-Banner-Preisgabe im `Server`-/`X-Powered-By`-Header

Ergebnis ist live im Dashboard unter **"Website-Sicherheit"** sichtbar und fließt in den
Security-Score ein.

**2. Web-Angriffserkennung im Servnix Guard** (`server/lib/webAttackDetection.js`) – liest das
echte nginx-/apache-Access-Log und erkennt automatisiert:

- Exploit-Sondierung bekannter sensibler Pfade (`.env`, `.git`, `wp-login.php`, `phpMyAdmin`, ...)
- SQL-Injection-/XSS-/Path-Traversal-Muster in der angefragten URL
- Bekannte Scanner-/Exploit-Tools am User-Agent (`sqlmap`, `nikto`, `nmap`, `wpscan`, ...)

Wer innerhalb kurzer Zeit mehrfach auffällt (`WEBGUARD_MAX_HITS`, Standard: 3), wird – genau wie
bei SSH-Bruteforce – automatisch serverweit gesperrt, nicht nur von der betroffenen Webseite
ausgeschlossen.

```bash
# Access-Log(s) der eigenen Webseiten konfigurieren (komma-getrennt), z.B. in .env:
# WEBGUARD_ACCESS_LOGS=/var/log/nginx/access.log

# Gehärtete nginx-Vorlage für eigene Webseiten als Basis nutzen:
cp templates/nginx-hardened.conf.example /etc/nginx/sites-available/meine-seite.conf
# -> Domain, Zertifikatspfade und proxy_pass anpassen, dann aktivieren:
sudo ln -s /etc/nginx/sites-available/meine-seite.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Danach laeuft die Web-Angriffserkennung automatisch mit dem bereits installierten
# Servnix Guard mit (kein separater Dienst noetig).
```

Die Vorlage setzt echte Security-Header, sperrt bekannte Exploit-Pfade direkt in nginx, erzwingt
moderne TLS-Versionen/Cipher, deaktiviert Directory-Listing und limitiert Requests pro IP gegen
einfache Layer-7-Flut-Angriffe.

**Ehrlicher Hinweis:** Weder der Scan noch die Angriffserkennung finden "jede Schwachstelle, die
es jemals geben wird" – das kann kein Tool. Erkannt werden die häufigsten, bekannten
Fehlkonfigurationen und Angriffsmuster. Eigene Programmierfehler in der Webanwendung (z. B.
fehlerhafte Business-Logik) erkennt kein automatisierter Scanner zuverlässig – dafür braucht es
einen echten Pentest.

---

## 🔐 Dashboard-Härtung (Schutz der App selbst)

Die beste Firewall nützt nichts, wenn die Dashboard-App selbst eine Schwachstelle ist. Deshalb
ist das Dashboard zusätzlich auf App-Ebene gehärtet – unabhängig von nftables/OPNsense:

- **Echte Security-Header per [Helmet](https://helmetjs.github.io/)** – CSP, `X-Frame-Options`,
  `X-Content-Type-Options`, kein `X-Powered-By`. Das Dashboard hält sich damit an genau die
  Header, die es selbst bei anderen Servern prüft.
- **Login-Bruteforce-Schutz** – wer wiederholt ein falsches Dashboard-Passwort probiert, wird
  nach `DASHBOARD_MAX_LOGIN_FAILURES` Versuchen (Standard: 5) automatisch über die Blockliste
  gesperrt – genau wie bei SSH-Bruteforce. Zeitfenster: `DASHBOARD_LOGIN_WINDOW_MINUTES`.
- **App-Ebene-Rate-Limiting** – begrenzt Requests pro IP (`RATE_LIMIT_MAX_REQUESTS` /
  `RATE_LIMIT_WINDOW_SECONDS`). Wer wiederholt in Folge das Limit reißt, wird zusätzlich komplett
  gesperrt (`RATE_LIMIT_MAX_VIOLATIONS_BEFORE_BLOCK`). Das fängt Request-Fluten ab, die über
  einen bereits erlaubten Port (z. B. den SSH-Tunnel-Port) an der Netzwerk-Firewall vorbeikommen.
- **Slowloris-Härtung** – kurze HTTP-Timeouts (`headersTimeout`, `requestTimeout`,
  `keepAliveTimeout`) verhindern, dass langsame/hängende Verbindungen den Node-Prozess
  ausbremsen.
- **Begrenzte Body-Größe** (`64kb`) gegen übergroße Request-Payloads.
- **Timing-sicherer Passwortvergleich** (`crypto.timingSafeEqual`) gegen Timing-Angriffe auf
  Benutzername/Passwort.
- **Log-Rotation** für `security-events.log`, damit ein Angreifer die Festplatte nicht durch
  endlos viele ausgelöste Events füllen kann (Disk-Exhaustion-Schutz).

Alle Werte sind live im Dashboard unter **"Dashboard-Härtung"** einsehbar
(`GET /api/hardening/status`).

**Ehrlicher Hinweis zur Grenze dieses Schutzes:** Solange das Dashboard wie empfohlen nur über
`127.0.0.1` + SSH-Tunnel erreichbar ist, sieht die App **jeden** Zugriff als `127.0.0.1` – die
echte Angreifer-IP wird durch den SSH-Tunnel maskiert. Die Login-Bruteforce-Sperre kann in
diesem Standard-Setup also niemanden tatsächlich aussperren (Loopback-Adressen werden aus
Selbstaussperr-Schutz ohnehin nie gesperrt) – sie greift vor allem, wenn `HOST` bewusst geändert
wird (z. B. hinter einem eigenen Reverse-Proxy mit echten Client-IPs). Der eigentliche Schutz
für den SSH-Zugang selbst ist und bleibt der Servnix Guard (SSH-Bruteforce-Erkennung) bzw.
`fail2ban` direkt auf dem SSH-Daemon.

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

**4a. Servnix Guard einrichten (optional, empfohlen)**
```bash
# Eigene IP in .env unter GUARD_ALLOWLIST eintragen, sonst droht Selbstaussperrung!
sudo ./scripts/servnix-guard.sh install
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
- **Website-Sicherheit** – sensible Dateien, gefährliche HTTP-Methoden, CORS, Directory-Listing
- **Dependency-Audit** (npm/pip)
- **OPNsense-Kachel** mit Live-Verbindungsstatus
- **Firewall-Steuerung** (install/enable/disable/status per Klick)
- **Servnix Guard · Blockliste** – gesperrte IPs mit Grund/Quelle/Sync-Status, manuelles Sperren/Entsperren per Klick
- **Security-Events** – Protokoll aller Sperrungen, Entsperrungen und erkannten USB-Geräte
- **Dashboard-Härtung** – Live-Status von Security-Headern, Login-Bruteforce-Schutz, Rate-Limiting

Alle 30 Sekunden aktualisiert sich der zuletzt gespeicherte Scan automatisch; ein neuer Voll-Scan wird per Button oder `POST /api/scan` ausgelöst.

---

## 🔐 Sicherheits-Realitätscheck

| ✅ Was stimmt | ❌ Was Servnix NICHT ersetzt |
|---|---|
| Echte, live geprüfte Firewall-/TLS-/Header-/Dependency-Daten | Ein zertifiziertes Pentest oder einen Security-Audit durch Dritte |
| Eine funktionierende, eigenständige nftables-Firewall | Ein vollwertiges WAF wie ModSecurity/Coraza gegen jede Anwendungslogik-Schwachstelle |
| Echte OPNsense-API-Anbindung (Basic Auth mit Key/Secret) | Enterprise-DDoS-Schutz auf Netzwerkebene (dafür brauchst du einen Provider wie Cloudflare/OPNsense mit ausreichend Bandbreite) |
| Ein Score, dessen Berechnung offen im Code liegt | Eine Garantie für "100% sicher" – das gibt es nicht |
| Automatische IP-Sperrung bei echten SSH-Bruteforce-/Portscan-Mustern | "KI" im Sinne von Machine Learning – der Guard ist regelbasiert, keine Blackbox |
| USB-Geräte-Erkennung & Alarmierung im Log | Physisches Blockieren eines USB-Geräts (dafür braucht es zusätzlich `usbguard`) |
| Echte Security-Header, Rate-Limiting, Bruteforce-Schutz, Slowloris-Härtung auf der Dashboard-App selbst | Schutz vor jedem denkbaren Angriff – "100% gegen alle Cyberangriffe" ist als Versprechen unseriös, siehe [docs/SECURITY.md](docs/SECURITY.md) |
| Echter Website-Scan + automatische IP-Sperrung bei erkannter Exploit-Sondierung/SQLi/XSS im Access-Log | Schutz vor unbekannten Zero-Day-Lücken in der eigenen Webanwendung – dafür braucht es Pentests/OWASP-Tools wie ZAP/Burp |

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
GET  /api/blocklist                 aktuelle IP-Blockliste
POST /api/blocklist                 IP manuell sperren ({ ip, reason })
DELETE /api/blocklist/:ip           IP entsperren
GET  /api/security-events           Protokoll aller Sperr-/Entsperr-/USB-Ereignisse
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
