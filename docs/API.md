# API-Referenz

Basis-URL: `http://127.0.0.1:3000` (Server bindet standardmäßig nur an localhost, siehe
[INSTALLATION.md](INSTALLATION.md) für den SSH-Tunnel-Zugriff von einem entfernten PC aus).
Alle Endpunkte sind per HTTP Basic Auth geschützt, sobald `DASHBOARD_PASSWORD_HASH` in `.env` gesetzt ist.
Alle Endpunkte sind zusätzlich per App-Ebene-Rate-Limiting geschützt (`429` bei zu vielen
Anfragen, siehe `GET /api/hardening/status`).

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

## Servnix Guard (Blockliste & Security-Events)

### `GET /api/blocklist`
Gibt die aktuelle Blockliste zurück (Objekt, Key = IP):
```json
{
  "203.0.113.5": {
    "reason": "SSH-Bruteforce: 8 fehlgeschlagene Logins in 10 Minuten",
    "source": "guard-ssh",
    "blockedAt": "2025-01-01T12:00:00.000Z",
    "nftSynced": true,
    "opnsenseSynced": false
  }
}
```

### `POST /api/blocklist`
Sperrt eine IP manuell. Private/Loopback-Adressen werden abgelehnt (Selbstaussperr-Schutz).
```json
{ "ip": "203.0.113.5", "reason": "Manueller Verdacht" }
```
Antwort enthält separat, ob die nftables- und OPNsense-Synchronisierung tatsächlich geklappt
hat (`nft.ok`, `opnsense.ok`) – es wird kein Erfolg vorgetäuscht, der nicht stattgefunden hat.

### `DELETE /api/blocklist/:ip`
Entsperrt eine IP wieder (nftables-Sync automatisch). **Hinweis:** Ein automatisches Entfernen
aus einem OPNsense-Alias ist nicht implementiert – dafür müsste die Alias-Item-UUID aufgelöst
werden. Wurde die IP über OPNsense gesperrt, muss sie dort manuell entfernt werden.

### `GET /api/security-events?limit=100`
Protokoll aller Sperrungen (`block`), Entsperrungen (`unblock`) und erkannten USB-Geräte
(`usb-detected`), neueste zuerst.
```json
[
  { "timestamp": "2025-01-01T12:00:00.000Z", "type": "block", "ip": "203.0.113.5", "reason": "...", "source": "guard-ssh", "nftSynced": true, "opnsenseSynced": false }
]
```

## Dashboard-Härtung

### `GET /api/hardening/status`
Gibt den tatsächlich aktiven Schutzstatus der Dashboard-App zurück (keine Fake-Werte):
```json
{
  "securityHeaders": true,
  "dashboardAuth": true,
  "loginBruteforceProtection": { "maxFailures": 5, "windowMinutes": 10 },
  "rateLimiting": { "maxRequests": 120, "windowSeconds": 60 },
  "guardAllowlistConfigured": true,
  "hostBinding": "127.0.0.1"
}
```


