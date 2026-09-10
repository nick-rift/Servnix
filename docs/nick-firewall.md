# Nick Firewall

Nick Firewall ist die eigenstaendig nutzbare Host-Firewall aus Servnix. Sie ist bewusst fuer Debian/Ubuntu mit `nftables` ausgelegt und laesst sich auch **ohne Dashboard** als eigenes Tool verwenden.

## Unterstuetzte Distros

- Debian (getesteter Zielpfad)
- Ubuntu (getesteter Zielpfad)

Andere Linux-Distributionen koennen funktionieren, sind in diesem Repository aber nicht ehrlich getestet.

## Schnellstart

### Option A: Git-Clone + Script (empfohlen)

```bash
git clone https://github.com/nick-rift/Servnix.git
cd Servnix
chmod +x scripts/*.sh
sudo ./scripts/nick-firewall.sh install
```

Nach dem Install steht die CLI systemweit bereit:

```bash
sudo nick-firewall status
sudo nick-firewall allow 443
sudo nick-firewall deny 203.0.113.5
```

### Option B: Raw-Script per curl laden

```bash
curl -fsSL https://raw.githubusercontent.com/nick-rift/Servnix/main/scripts/nick-firewall.sh -o /tmp/nick-firewall.sh
chmod +x /tmp/nick-firewall.sh
sudo /tmp/nick-firewall.sh install
```

> Der `curl`-Weg ist praktisch fuer schnelle Tests. Fuer Updates, Doku und den Guard ist der Git-Clone transparenter.

## CLI-Befehle

```bash
nick-firewall install
nick-firewall enable
nick-firewall disable
nick-firewall status
nick-firewall allow <port|ip>
nick-firewall deny <port|ip>
nick-firewall reset
```

### Beispiele

```bash
# Webserver-Port freigeben
sudo nick-firewall allow 8443

# Eine auffaellige IPv4-Adresse direkt blocken
sudo nick-firewall deny 203.0.113.99

# Aktuelles Regelwerk und Konfiguration ansehen
sudo nick-firewall status
```

## Interaktives Setup

Beim ersten `install` schlaegt Nick Firewall sinnvolle Defaults vor:

- erkennt den SSH-Port aus `sshd_config`, falls vorhanden
- scannt vorhandene offene TCP-Ports mit `ss`
- bietet Presets fuer
  - **Webserver**
  - **reiner SSH-Server**
  - **Custom**
- uebernimmt erkannte offene Ports **nicht stillschweigend**, sondern fragt im interaktiven Setup nach einer bestaetigten Freigabe

Die finale Konfiguration landet in:

```bash
/etc/nick-firewall/rules.conf
```

Dort koennen Regeln spaeter angepasst werden, ohne das Script selbst zu editieren.

## Konfigurationsdatei

Beispiel:

```bash
PROFILE="webserver"
SSH_PORT="22"
ALLOW_TCP_PORTS="22,80,443"
DENY_TCP_PORTS=""
ALLOW_IPS=""
DENY_IPS="203.0.113.99"
```

Nach Aenderungen kannst du das Regelwerk neu laden mit:

```bash
sudo nick-firewall enable
```

## Service-Datei und Persistenz

Beim Install werden diese Dateien erzeugt:

- `/etc/nick-firewall/rules.conf`
- `/etc/nick-firewall/nick-firewall.nft`
- `/etc/systemd/system/nick-firewall.service`
- `/etc/sysctl.d/99-nick-firewall.conf`
- `/usr/local/bin/nick-firewall`

Damit ist das Regelwerk nach Reboots wieder ladbar und die Kernel-Haertung bleibt dokumentiert.

## Dry-Run / Testen ohne Root oder CAP_NET_ADMIN

Wenn du lokal nur pruefen willst, wie die CLI reagieren wuerde, nutze `--dry-run`.

```bash
./scripts/nick-firewall.sh --dry-run install
./scripts/nick-firewall.sh --dry-run status
./scripts/nick-firewall.sh --dry-run allow 8443
./scripts/nick-firewall.sh --dry-run deny 203.0.113.99
```

Fuer simulierte Testumgebungen lassen sich die Zielpfade per Umgebungsvariablen umbiegen, z. B. `NICK_FIREWALL_ETC_DIR=/tmp/nick-fw-test`.

## Ehrliche Grenzen

- Nick Firewall ist **kein Ersatz fuer professionelle Firewalls** oder gemanagte Edge-Schutzsysteme in kritischen Umgebungen.
- Sie schuetzt den Host mit nachvollziehbaren `nftables`-Regeln, ist aber **kein WAF** gegen Anwendungslogikfehler.
- Getestet ist der Weg in diesem Repository auf **Debian/Ubuntu mit nftables**.
- Wer komplexe IPv6-, VLAN-, Container- oder Multi-NIC-Topologien faehrt, sollte das Regelwerk vor Produktion individuell pruefen.

## Zusammenspiel mit Servnix

Im Dashboard wird dieselbe CLI fuer `install`, `enable`, `disable` und `status` genutzt. Der alte Pfad `scripts/servnix-firewall.sh` bleibt als Legacy-Wrapper erhalten, damit bestehende Automationen nicht sofort brechen.
