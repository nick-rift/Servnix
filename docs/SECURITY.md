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
