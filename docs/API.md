# API-Referenz

Basis-URL: `http://127.0.0.1:3000` (Server bindet standardmäßig nur an localhost, siehe
[INSTALLATION.md](INSTALLATION.md) für den SSH-Tunnel-Zugriff von einem entfernten PC aus).
Alle Endpunkte sind per HTTP Basic Auth geschützt, sobald `DASHBOARD_PASSWORD_HASH` in `.env` gesetzt ist.

## Health

### `GET /api/health`
```json
{ "ok": true, "uptime": 123.4 }
```

## Scans

### `GET /api/scan/latest`
Letzten gespeicherten Scan-Report zurückgeben. `404`, wenn noch kein Scan gelaufen ist.

### `POST /api/scan`
Führt einen vollständigen Scan aus (Firewall, TLS, Header, Dependencies, System) und speichert
ihn als neuesten Stand. Body optional:
```json
{ "sslHost": "meine-domain.de", "targetUrl": "https://meine-domain.de" }
```
Antwort: vollständiges Scan-Objekt inkl. `score`.

## Firewall

### `GET /api/firewall/status`
Rohdaten des Firewall-Scans (Servnix-nftables, ufw, offene Ports, fail2ban, DDoS-Kernel-Parameter).

### `POST /api/firewall/servnix/:action`
`:action` ∈ `install | enable | disable | status`. Führt `scripts/servnix-firewall.sh <action>`
per `sudo` aus (siehe [INSTALLATION.md](INSTALLATION.md) für die nötige sudoers-Konfiguration).
```json
{ "action": "status", "ok": true, "stdout": "...", "stderr": "" }
```

## OPNsense

### `GET /api/opnsense/config`
```json
{ "configured": true, "host": "https://opnsense.example.local" }
```

### `GET /api/opnsense/test`
Echter Verbindungstest gegen die OPNsense-API.
```json
{ "connected": true, "info": { "...": "..." } }
```

### `GET /api/opnsense/rules`
Firewall-Regeln von OPNsense (`/api/firewall/filter/search_rule`).

### `GET /api/opnsense/health`
System-Health von OPNsense (`/api/diagnostics/system/system_information`).

### `POST /api/opnsense/block-ip`
```json
{ "ip": "203.0.113.5" }
```
Fügt die IP zum OPNsense-Alias `servnix_blocklist` hinzu (Alias muss in OPNsense existieren).
