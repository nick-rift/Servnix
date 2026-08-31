#!/bin/bash
###############################################################################
# Servnix Firewall - eigene, minimalistische Firewall auf Basis von nftables
#
# Das ist keine Marketing-Behauptung, sondern ein echtes Regelwerk:
#   - Default-Deny auf INPUT (alles was nicht explizit erlaubt ist, wird verworfen)
#   - Stateful Filtering (nur Antworten auf eigene/etablierte Verbindungen erlaubt)
#   - SYN-Flood-/DDoS-Rate-Limiting auf neue Verbindungen und ICMP
#   - Port-Scan-Erkennung (haeufige TCP-Flag-Kombinationen von Scannern werden verworfen)
#   - Nur SSH/HTTP/HTTPS standardmaessig offen, alles andere per SERVNIX_ALLOW_PORTS steuerbar
#
# Nutzung:
#   sudo ./scripts/servnix-firewall.sh install   # Regeln einmalig anlegen + persistieren
#   sudo ./scripts/servnix-firewall.sh enable    # aktiviert die Tabelle (nft)
#   sudo ./scripts/servnix-firewall.sh disable   # deaktiviert nur die Servnix-Tabelle
#   sudo ./scripts/servnix-firewall.sh status    # zeigt das aktive Regelwerk
#
# Umgebungsvariablen:
#   SERVNIX_ALLOW_TCP_PORTS="22,80,443"   zusaetzliche/abweichende TCP-Ports
#   SERVNIX_SSH_PORT="22"                 SSH-Port (wird strenger rate-limitiert)
###############################################################################

set -euo pipefail

TABLE="servnix_fw"
ALLOW_TCP_PORTS="${SERVNIX_ALLOW_TCP_PORTS:-22,80,443}"
SSH_PORT="${SERVNIX_SSH_PORT:-22}"

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "Dieses Script braucht Root-Rechte (nft aendert die Kernel-Firewall). Bitte mit sudo ausfuehren." >&2
    exit 1
  fi
}

require_nft() {
  if ! command -v nft &> /dev/null; then
    echo "nft (nftables) ist nicht installiert. Installieren mit: sudo apt-get install nftables" >&2
    exit 1
  fi
}

build_ruleset() {
  # Portliste in nft-Set-Syntax { 22, 80, 443 } umwandeln
  local ports_set
  ports_set="{ $(echo "$ALLOW_TCP_PORTS" | tr ',' ' ' | sed 's/ /, /g') }"

  cat <<EOF
table inet ${TABLE} {
    set blackhole_v4 {
        type ipv4_addr
        flags interval
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback immer erlauben
        iif "lo" accept

        # Bereits etablierte/verwandte Verbindungen durchlassen (stateful)
        ct state established,related accept
        ct state invalid drop

        # Servnix-Blockliste (z.B. via Dashboard/OPNsense-Sync befuellt)
        ip saddr @blackhole_v4 drop

        # Ungewoehnliche TCP-Flag-Kombinationen sind klassische Portscan-/Crafted-Packet-Muster
        tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop comment "null-scan"
        tcp flags & (fin|syn) == (fin|syn) drop comment "syn-fin-scan"
        tcp flags & (syn|rst) == (syn|rst) drop comment "syn-rst-scan"

        # ICMP Echo (ping) rate-limitieren statt komplett zu blocken
        icmp type echo-request limit rate 5/second accept
        icmpv6 type echo-request limit rate 5/second accept

        # Neue SSH-Verbindungen strikt rate-limitieren (Brute-Force-/DDoS-Schutz)
        tcp dport ${SSH_PORT} ct state new limit rate 10/minute burst 5 packets accept

        # Neue Verbindungen auf erlaubten Ports, aber global rate-limitiert (SYN-Flood-Schutz)
        tcp dport ${ports_set} ct state new limit rate 200/second burst 50 packets accept

        counter comment "dropped-by-default-deny"
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
EOF
}

cmd_install() {
  require_root
  require_nft
  echo "→ Erzeuge Servnix-Firewall-Regelwerk (Tabelle: ${TABLE})..."
  build_ruleset > /tmp/servnix_fw.nft
  nft -f /tmp/servnix_fw.nft
  rm -f /tmp/servnix_fw.nft

  # Persistenz: Regeln beim Boot wiederherstellen
  mkdir -p /etc/nftables.servnix
  build_ruleset > /etc/nftables.servnix/servnix_fw.nft
  if [ -d /etc/systemd/system ]; then
    cat > /etc/systemd/system/servnix-firewall.service <<'UNIT'
[Unit]
Description=Servnix Firewall (nftables)
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.servnix/servnix_fw.nft
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable servnix-firewall.service > /dev/null 2>&1 || true
    echo "→ systemd-Service 'servnix-firewall' angelegt und aktiviert (persistiert Reboots)."
  fi

  # DDoS-relevante Kernel-Parameter haerten
  cat > /etc/sysctl.d/99-servnix.conf <<'SYSCTL'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
SYSCTL
  sysctl -p /etc/sysctl.d/99-servnix.conf > /dev/null 2>&1 || true

  echo "✅ Servnix-Firewall installiert und aktiv. Status pruefen mit: $0 status"
}

cmd_enable() {
  require_root
  require_nft
  if [ -f /etc/nftables.servnix/servnix_fw.nft ]; then
    nft -f /etc/nftables.servnix/servnix_fw.nft
  else
    build_ruleset | nft -f -
  fi
  echo "✅ Servnix-Firewall aktiviert."
}

cmd_disable() {
  require_root
  require_nft
  nft delete table inet "${TABLE}" 2> /dev/null || true
  echo "⚠️  Servnix-Firewall-Tabelle entfernt. Der Server ist damit ohne dieses Regelwerk (Vorsicht!)."
}

cmd_status() {
  require_nft
  if nft list table inet "${TABLE}" 2> /dev/null; then
    :
  else
    echo "Servnix-Firewall ist NICHT aktiv."
    exit 1
  fi
}

case "${1:-}" in
  install) cmd_install ;;
  enable) cmd_enable ;;
  disable) cmd_disable ;;
  status) cmd_status ;;
  *)
    echo "Usage: $0 {install|enable|disable|status}"
    exit 1
    ;;
esac
