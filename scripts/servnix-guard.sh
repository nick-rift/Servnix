#!/bin/bash
###############################################################################
# Servnix Guard - Installer fuer den automatischen Angriffserkennungs-Dienst
#
# Was der Guard tatsaechlich macht (regelbasiert, KEINE "KI-Magie"):
#   - Liest echte SSH-Logs (journalctl/auth.log) und zaehlt fehlgeschlagene
#     Logins pro IP -> ab GUARD_SSH_MAX_FAILURES wird die IP gesperrt
#   - Liest das Kernel-Log der Servnix-Firewall (Praefix "servnix-scan-attempt:")
#     und zaehlt verschiedene angefragte Ports pro IP -> ab GUARD_PORTSCAN_MAX_PORTS
#     wird die IP gesperrt
#   - Ueberwacht optional den USB-Geraetebestand (lsusb) und meldet neue
#     Geraete als Security-Event (Erkennung/Alarm, KEIN automatisches Sperren
#     von USB-Ports - das kann Software ohne usbguard/Kernel-Policies nicht
#     seriös leisten)
#   - Jede Sperre landet in der nftables-Menge "blackhole_v4" der
#     Servnix-Firewall -> betrifft SOFORT den gesamten Server-Traffic dieser
#     IP (Dashboard, SSH, Webserver, alles), nicht nur das Dashboard
#
# Voraussetzung: scripts/servnix-firewall.sh muss bereits installiert sein
# (liefert die Menge "blackhole_v4" und das Scan-Logging).
#
# Nutzung:
#   sudo ./scripts/servnix-guard.sh install   # systemd-Service anlegen + starten
#   sudo ./scripts/servnix-guard.sh status    # Dienststatus + letzte Logzeilen
#   sudo ./scripts/servnix-guard.sh disable   # Dienst stoppen + deaktivieren
#   ./scripts/servnix-guard.sh test           # einmaliger Testlauf (--once), kein root noetig
#
# Wichtig: Trage deine eigene IP in GUARD_ALLOWLIST (.env) ein, bevor du den
# Guard aktivierst, damit du dich nicht selbst aussperrst!
###############################################################################

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
NODE_BIN="$(command -v node || true)"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Dieses Script braucht Root-Rechte (systemd-Service anlegen). Bitte mit sudo ausfuehren." >&2
    exit 1
  fi
}

require_node() {
  if [ -z "${NODE_BIN}" ]; then
    echo "node wurde nicht im PATH gefunden. Node.js installieren, bevor der Guard laeuft." >&2
    exit 1
  fi
}

cmd_install() {
  require_root
  require_node

  if [ ! -f "${SCRIPT_DIR}/.env" ]; then
    echo "⚠️  Keine .env gefunden unter ${SCRIPT_DIR}/.env - der Guard laeuft mit Standardwerten." >&2
    echo "   Empfehlung: .env.example kopieren, GUARD_ALLOWLIST mit deiner eigenen IP setzen!" >&2
  fi

  cat > /etc/systemd/system/servnix-guard.service <<UNIT
[Unit]
Description=Servnix Guard (automatische Angriffserkennung + IP-Sperrung)
After=network.target servnix-firewall.service
Wants=servnix-firewall.service

[Service]
Type=simple
WorkingDirectory=${SCRIPT_DIR}
ExecStart=${NODE_BIN} ${SCRIPT_DIR}/server/guard.js
Restart=on-failure
RestartSec=10
# Der Guard braucht root, um nft-Regeln zu aendern (IP sperren/entsperren).
User=root

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable servnix-guard.service > /dev/null 2>&1 || true
  systemctl restart servnix-guard.service
  echo "✅ Servnix Guard installiert und laeuft als systemd-Dienst 'servnix-guard'."
  echo "   Status pruefen mit: sudo systemctl status servnix-guard"
  echo "   Live-Logs mit:      sudo journalctl -u servnix-guard -f"
}

cmd_disable() {
  require_root
  systemctl disable --now servnix-guard.service > /dev/null 2>&1 || true
  echo "⚠️  Servnix Guard gestoppt und deaktiviert. Es findet keine automatische Sperrung mehr statt."
}

cmd_status() {
  systemctl status servnix-guard.service --no-pager 2> /dev/null || echo "Servnix Guard ist nicht installiert. Installieren mit: sudo $0 install"
}

cmd_test() {
  require_node
  echo "→ Fuehre einmaligen Testlauf aus (liest Logs, sperrt bei echtem Schwellenwert-Ueberschreiten)..."
  cd "${SCRIPT_DIR}" && "${NODE_BIN}" server/guard.js --once
}

case "${1:-}" in
  install) cmd_install ;;
  disable) cmd_disable ;;
  status) cmd_status ;;
  test) cmd_test ;;
  *)
    echo "Verwendung: $0 {install|disable|status|test}" >&2
    exit 1
    ;;
esac
