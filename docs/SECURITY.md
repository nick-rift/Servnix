# Security Policy

## Was Servnix prüft

Servnix führt bei jedem Scan echte, live ausgeführte Checks aus (siehe `server/lib/*.js`):

- Firewall-Status (eigene nftables-Firewall und/oder ufw), offene Ports
- DDoS-relevante Kernel-Härtung (SYN-Cookies, rp_filter, ICMP-Redirects)
- fail2ban-Status und aktive Jails
- TLS/SSL-Zertifikat, Protokollversion, Cipher, Ablaufdatum
- HTTP-Security-Header (HSTS, CSP, X-Frame-Options, ...)
- npm-/Python-Dependency-Vulnerabilities
- Kernel-/OS-Version, UID-0-Accounts
- **Website-Schwachstellen** (`server/lib/webVulnScan.js`): öffentlich erreichbare sensible
  Dateien (`.env`, `.git/config`, Backups, ...), gefährliche erlaubte HTTP-Methoden
  (`TRACE`/`PUT`/`DELETE`), CORS-Fehlkonfiguration (`*` + Credentials), Directory-Listing,
  preisgegebene Server-/Versionsbanner – echte aktive Checks gegen den konfigurierten
  `SCAN_TARGET_URL`, keine geratenen Werte.

Zusätzlich läuft optional der **Servnix Guard** (`server/guard.js`) als eigener Dauerprozess und
wertet echte Logs kontinuierlich aus:

- SSH-Login-Fehlversuche (`journalctl`/`auth.log`) pro Quell-IP
- Portscan-Muster im nftables-Kernel-Log (verschiedene angefragte Ports pro Quell-IP)
- Veränderungen am USB-Geräte-Bestand (`lsusb`-Diff)
- **Web-Angriffsmuster** (`server/lib/webAttackDetection.js`) im echten nginx-/apache-Access-Log:
  Exploit-Sondierung sensibler Pfade (`.env`, `.git`, `wp-login.php`, `phpMyAdmin`, ...),
  SQL-Injection-/XSS-/Path-Traversal-Muster in der Request-Zeile, bekannte Scanner-Tool-User-Agents
  (`sqlmap`, `nikto`, `nmap`, ...)

Bei Überschreiten der konfigurierten Schwellenwerte wird die IP automatisch in die
nftables-Menge `blackhole_v4` eingetragen – das betrifft sofort den **gesamten** Server-Traffic
dieser IP (Dashboard, SSH, Webserver auf 80/443, alles), nicht nur das Dashboard oder die
betroffene Webseite selbst. Wer also versucht, eine Website auf dem Server anzugreifen, verliert
den Zugriff auf den kompletten Server, nicht nur auf die Website.

Zusätzlich ist die Dashboard-App selbst gehärtet (App-Ebene, unabhängig von nftables/OPNsense):

- Echte Security-Header per Helmet (CSP, `X-Frame-Options`, `X-Content-Type-Options`, kein
  `X-Powered-By`)
- Login-Bruteforce-Schutz (`DASHBOARD_MAX_LOGIN_FAILURES`/`DASHBOARD_LOGIN_WINDOW_MINUTES`) –
  sperrt die IP wie bei SSH-Bruteforce
- App-Ebene-Rate-Limiting (`RATE_LIMIT_*`) mit automatischer Sperrung bei wiederholtem Missbrauch
- Slowloris-Härtung (kurze HTTP-Header-/Request-Timeouts)
- Begrenzte Request-Body-Größe (64 KB)
- Timing-sicherer Passwort-/Benutzername-Vergleich (`crypto.timingSafeEqual`)
- Log-Rotation für `security-events.log` gegen Disk-Exhaustion durch massenhaft ausgelöste Events

Jeder Check kann fehlschlagen oder ein Tool kann fehlen – in dem Fall wird das als
"nicht verfügbar" bzw. mit der echten Fehlermeldung angezeigt, niemals als grüner Haken.

## Was Servnix NICHT ist

- **Kein Ersatz für ein professionelles Pentest** – Servnix findet keine komplexen,
  anwendungsspezifischen Schwachstellen (z. B. Business-Logic-Fehler).
- **Kein Enterprise-DDoS-Schutz auf Netzwerkebene.** Die eigene Firewall schützt vor
  einfachen SYN-Floods und Portscans auf Host-Ebene, aber nicht vor volumetrischen
  Angriffen, die die Anbindung des Servers selbst sättigen. Dafür braucht es einen
  Anbieter mit ausreichend Netzwerkkapazität (z. B. vorgeschaltetes OPNsense-Cluster,
  Cloudflare, oder den DDoS-Schutz deines Hosters).
- **Der Servnix Guard ist keine "KI"** im Sinne von Machine Learning oder Anomalieerkennung
  ohne feste Regeln. Es sind einfache, im Code sichtbare Schwellenwert-Regeln auf echten
  Log-Daten (X Fehlversuche/Ports in Y Minuten). Das ist bewusst so gebaut, damit jede
  Sperrung nachvollziehbar und keine Blackbox-Entscheidung ist.
- **Der USB-Monitor blockiert nichts physisch.** Er erkennt und protokolliert neu
  angeschlossene Geräte. Ein tatsächliches Sperren von USB-Ports braucht zusätzliche
  Betriebssystem-Mechanismen (z. B. `usbguard`), die Servnix nicht mitbringt.
- **Der Login-Bruteforce-Schutz des Dashboards sieht im empfohlenen Standard-Setup (nur
  `127.0.0.1` + SSH-Tunnel) jeden Zugriff als `127.0.0.1`** – die echte Angreifer-IP ist durch
  den Tunnel maskiert, und Loopback-Adressen werden aus Selbstaussperr-Schutz nie gesperrt.
  Dieser Schutz greift also vor allem bei einer bewussten `HOST`-Änderung (z. B. eigener
  Reverse-Proxy mit echten Client-IPs). Für den SSH-Zugang selbst sorgt weiterhin der Servnix
  Guard bzw. `fail2ban` für den eigentlichen Bruteforce-Schutz.
- **Die Web-Angriffserkennung findet nur, was im Access-Log als Angriffsmuster auftaucht.**
  Sie erkennt bekannte, sich wiederholende Sondierungs-/Exploit-Versuche (Regex-Muster,
  keine ML-Anomalieerkennung) – ein einzelner, gezielter Angriff ohne wiederholte Muster
  oder ein komplett neues, unbekanntes Angriffsmuster fällt nicht automatisch auf. Die
  Erkennung braucht außerdem ein Standard-"combined"-Access-Log (siehe
  `templates/nginx-hardened.conf.example`) – ohne konfiguriertes `WEBGUARD_ACCESS_LOGS` läuft
  sie leer.
- **`server/lib/webVulnScan.js` prüft eine feste Liste bekannter Fehlkonfigurationen**, keine
  beliebige Anwendungslogik. Eigene, anwendungsspezifische Schwachstellen (z. B. eine falsch
  programmierte Login-Funktion) findet dieser Check nicht – dafür braucht es einen echten
  Pentest oder ein spezialisiertes Tool wie OWASP ZAP/Burp Suite.
- **Es gibt keine Software, die "100% sicher gegen alle Cyberangriffe" macht** – das ist als
  Versprechen technisch nicht haltbar (Zero-Day-Lücken in Betriebssystem/Kernel/eingesetzter
  Software lassen sich durch keine Konfiguration ausschließen). Servnix reduziert real und
  nachvollziehbar die häufigsten Angriffsvektoren (offene Ports, schwache TLS-Konfiguration,
  fehlende Security-Header, Bruteforce, Portscans, bekannte Dependency-CVEs, bekannte
  Web-Exploit-Sondierung) – das ist der ehrliche Anspruch, nicht mehr und nicht weniger. Jeder,
  der "Schutz gegen jeden Cyberangriff, der jemals existieren wird" verspricht, lügt – auch
  Servnix nicht.
- **Keine Zertifizierung** für CIS/HIPAA/GDPR/PCI-DSS. Die Checks orientieren sich an
  gängigen Best Practices, ersetzen aber keinen formalen Audit.

## Schwachstellen melden

Wenn du eine Sicherheitslücke in Servnix selbst findest (nicht: ein Finding, das der Scanner
korrekt auf deinem Server gemeldet hat), erstelle bitte **kein öffentliches Issue**, sondern
kontaktiere den Maintainer direkt über die im Profil hinterlegten Kanäle.

## Best Practices für den Betrieb

- Dashboard-Passwort setzen (`node server/cli-hash-password.js`), sonst ist es offen.
- `.env` niemals committen (steht in `.gitignore`).
- Server bindet standardmäßig nur an `127.0.0.1` – Zugriff von außen per SSH-Tunnel, nicht per
  öffentlicher IP/Domain. `HOST=0.0.0.0` nur setzen, wenn ein eigener, abgesicherter
  Reverse-Proxy mit TLS + Auth davor steht.
- OPNsense-API-Zugangsdaten wie jedes andere Admin-Passwort behandeln und rotieren.
- Regelmäßig `./scripts/security-scan.sh` laufen lassen und die "Offenen Punkte" abarbeiten.
- Vor dem Aktivieren des Servnix Guards **immer** die eigene IP in `GUARD_ALLOWLIST` eintragen,
  sonst droht Selbstaussperrung bei zu vielen eigenen Fehlversuchen.
- Für eigene Webseiten/Webanwendungen die gehärtete Vorlage `templates/nginx-hardened.conf.example`
  als Basis für die nginx-Konfiguration nutzen (Security-Header, gesperrte Exploit-Pfade,
  Rate-Limiting, kein Directory-Listing) – und `WEBGUARD_ACCESS_LOGS` auf das jeweilige
  Access-Log zeigen lassen, damit der Servnix Guard Angriffe darauf tatsächlich erkennt.
- Node.js-Prozess nach Möglichkeit als eigener, unprivilegierter Systemuser laufen lassen (nicht
  als root) – nur der Servnix Guard und die Firewall-Scripts selbst brauchen root/sudo, nicht
  das Dashboard.
- Server regelmäßig mit Sicherheitsupdates versorgen (`apt update && apt upgrade`, `npm audit
  fix`) – kein Tool kann fehlende Betriebssystem-Patches ersetzen.
