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

### Servnix Guard einrichten (empfohlen)

Der Guard erkennt SSH-Bruteforce-Versuche und Portscans in echten Logs und sperrt die
Angreifer-IP automatisch (siehe README für Details). Voraussetzung: die Servnix-Firewall aus
dem vorherigen Schritt muss installiert sein, weil sie das Scan-Log liefert, das der Guard
für die Portscan-Erkennung ausliest.

```bash
sudo ./scripts/servnix-firewall.sh install   # falls noch nicht geschehen
```

**Bevor du den Guard aktivierst**, trage deine eigene IP (die, von der du per SSH zugreifst)
in `.env` ein, damit du dich nicht selbst aussperrst:

```env
GUARD_ALLOWLIST=203.0.113.42
```

Dann den Guard als systemd-Dienst installieren:

```bash
sudo ./scripts/servnix-guard.sh install
sudo ./scripts/servnix-guard.sh status
sudo journalctl -u servnix-guard -f      # Live-Logs mitverfolgen
```

Ohne root/systemd (z. B. lokal zum Testen) kannst du einen einzelnen Durchlauf ausführen, ohne
den Dienst dauerhaft zu installieren:

```bash
./scripts/servnix-guard.sh test
```

Weitere Feinjustierung (Schwellenwerte, Zeitfenster, USB-Monitor an/aus) über die
`GUARD_*`-Variablen in `.env.example`.

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

Der Server bindet standardmäßig nur an `127.0.0.1` (siehe `HOST` in `.env`) – das Dashboard ist
also nie direkt über die öffentliche Server-IP erreichbar. Zugriff von deinem eigenen Rechner
läuft über einen SSH-Tunnel:

```bash
# Auf deinem lokalen PC ausführen (Terminal offen lassen):
ssh -L 3000:localhost:3000 <user>@<server-ip>

# oder dauerhaft im Hintergrund:
ssh -f -N -L 3000:localhost:3000 <user>@<server-ip>
```

Danach im Browser auf deinem PC: `http://localhost:3000`.

Nur wenn du bewusst einen eigenen, abgesicherten Reverse-Proxy (mit TLS + eigener Auth) davor
betreiben willst, setze `HOST=0.0.0.0` in `.env` und exponiere ausschließlich den Reverse-Proxy,
nie den Node-Prozess direkt.

### Ersten Scan ausführen

```bash
./scripts/security-scan.sh
```

Das schreibt zusätzlich einen JSON-Report nach `reports/` und aktualisiert den Stand, den das
Dashboard unter `/api/scan/latest` anzeigt.
