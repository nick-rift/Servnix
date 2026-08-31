# Installation Guide

## Voraussetzungen

- Linux-Server (getestet: Ubuntu/Debian) mit Root-/sudo-Zugriff
- Node.js 18+ (`./scripts/validate-system.sh` prüft das)
- Optional: Python 3 + `pip-audit` für den Python-Dependency-Scan
- Optional: eine bestehende OPNsense-Firewall, wenn du diese anbinden willst

## Schritt für Schritt

```bash
git clone https://github.com/nick-rift/Servnix.git
cd Servnix
chmod +x scripts/*.sh

./scripts/validate-system.sh
./scripts/install-dependencies.sh

npm install
cp .env.example .env
```

### Dashboard-Login absichern

Ohne Passwort ist das Dashboard offen erreichbar – der Server warnt dich beim Start davon.

```bash
node server/cli-hash-password.js "DeinSicheresPasswort"
```

Den Ausgabe-Hash in `.env` als `DASHBOARD_PASSWORD_HASH` eintragen, `DASHBOARD_USER` bei Bedarf anpassen.

### Servnix-Firewall einrichten (empfohlen)

```bash
sudo ./scripts/servnix-firewall.sh install
sudo ./scripts/servnix-firewall.sh status
```

Das legt eine eigene nftables-Tabelle `servnix_fw` an, persistiert sie via systemd-Service
(`/etc/systemd/system/servnix-firewall.service`) und härtet DDoS-relevante Kernel-Parameter
über `/etc/sysctl.d/99-servnix.conf`.

**Damit du die Firewall auch per Dashboard-Button steuern kannst**, braucht der Prozess, unter
dem `npm start` läuft, passwortlose `sudo`-Rechte für genau dieses Script. Beispiel (Datei
`/etc/sudoers.d/servnix`, mit `visudo -f` anlegen):

```
deploy ALL=(root) NOPASSWD: /pfad/zu/Servnix/scripts/servnix-firewall.sh
```

Ersetze `deploy` durch den Linux-User, unter dem der Servnix-Prozess läuft. Ohne diesen Eintrag
funktionieren die Buttons im Dashboard nicht – der Scan-Teil des Dashboards läuft aber trotzdem.

### OPNsense anbinden (optional)

1. OPNsense-Weboberfläche → **System → Access → Users** → deinen API-User öffnen → **API Keys** → neuen Key erzeugen.
2. In `.env`:
   ```env
   OPNSENSE_HOST=https://opnsense.example.local
   OPNSENSE_API_KEY=...
   OPNSENSE_API_SECRET=...
   OPNSENSE_VERIFY_TLS=true
   ```
3. Server neu starten. Die OPNsense-Kachel im Dashboard zeigt den echten Verbindungsstatus.

Bei selbstsignierten Zertifikaten auf OPNsense kannst du `OPNSENSE_VERIFY_TLS=false` setzen –
das ist aber ein bewusstes Sicherheits-Downgrade und nur für interne Testumgebungen gedacht.

### Server starten

```bash
npm start
```

Dashboard läuft unter `http://<server-ip>:3000`. Für produktiven Betrieb empfiehlt sich ein
Reverse-Proxy (z. B. nginx/Caddy) mit echtem TLS-Zertifikat davor, statt den Node-Prozess
direkt öffentlich zu exponieren.

### Ersten Scan ausführen

```bash
./scripts/security-scan.sh
```

Das schreibt zusätzlich einen JSON-Report nach `reports/` und aktualisiert den Stand, den das
Dashboard unter `/api/scan/latest` anzeigt.
