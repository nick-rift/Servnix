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

Zusätzlich läuft optional der **Servnix Guard** (`server/guard.js`) als eigener Dauerprozess und
wertet echte Logs kontinuierlich aus:

- SSH-Login-Fehlversuche (`journalctl`/`auth.log`) pro Quell-IP
- Portscan-Muster im nftables-Kernel-Log (verschiedene angefragte Ports pro Quell-IP)
- Veränderungen am USB-Geräte-Bestand (`lsusb`-Diff)

Bei Überschreiten der konfigurierten Schwellenwerte wird die IP automatisch in die
nftables-Menge `blackhole_v4` eingetragen – das betrifft sofort den **gesamten** Server-Traffic
dieser IP (Dashboard, SSH, Webserver auf 80/443, alles), nicht nur das Dashboard selbst.

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
