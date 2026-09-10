#!/bin/bash
###############################################################################
# Nick Firewall - eigenstaendig nutzbare nftables-Firewall fuer Debian/Ubuntu
#
# Was dieses Tool ehrlich leistet:
#   - Default-Deny auf INPUT mit Stateful Filtering
#   - Striktere SSH-Rate-Limits plus globale SYN-Flood-/DDoS-Begrenzung
#   - Portscan-Logging fuer den Servnix Guard
#   - Konfigurierbare Regeln ueber /etc/nick-firewall/rules.conf
#   - Klare CLI fuer Installation, Aktivierung, Status, Port/IP-Allow- und Deny
#
# Was es NICHT verspricht:
#   - Kein Ersatz fuer professionelle Firewalls in kritischen Umgebungen
#   - Kein WAF, kein DDoS-Scrubbing, keine Wunder gegen jede Schwachstelle
###############################################################################

set -euo pipefail

SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}")"
PRODUCT_NAME="Nick Firewall"
TABLE="nick_firewall"
LEGACY_TABLE="servnix_fw"
ETC_DIR="${NICK_FIREWALL_ETC_DIR:-/etc/nick-firewall}"
CONFIG_FILE="${NICK_FIREWALL_CONFIG:-${ETC_DIR}/rules.conf}"
RULESET_FILE="${NICK_FIREWALL_RULESET:-${ETC_DIR}/nick-firewall.nft}"
SYSTEMD_DIR="${NICK_FIREWALL_SYSTEMD_DIR:-/etc/systemd/system}"
SERVICE_FILE="${NICK_FIREWALL_SERVICE_FILE:-${SYSTEMD_DIR}/nick-firewall.service}"
BIN_PATH="${NICK_FIREWALL_BIN_PATH:-/usr/local/bin/nick-firewall}"
SYSCTL_FILE="${NICK_FIREWALL_SYSCTL_FILE:-/etc/sysctl.d/99-nick-firewall.conf}"
DRY_RUN_STATE_DIR="${NICK_FIREWALL_DRY_RUN_STATE_DIR:-/tmp/nick-firewall-dry-run}"
NFT_BIN="${NFT_BIN:-$(command -v nft || true)}"
SS_BIN="${SS_BIN:-$(command -v ss || true)}"
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-$(command -v systemctl || true)}"
DRY_RUN=0

DEFAULT_PROFILE="webserver"
DEFAULT_SSH_PORT="22"
DEFAULT_ALLOW_TCP_PORTS="22,80,443"
DEFAULT_DENY_TCP_PORTS=""
DEFAULT_ALLOW_IPS=""
DEFAULT_DENY_IPS=""

info() { echo "[${PRODUCT_NAME}] $*"; }
warn() { echo "[${PRODUCT_NAME}] WARN: $*" >&2; }
fail() { echo "[${PRODUCT_NAME}] FEHLER: $*" >&2; exit 1; }

usage() {
  cat <<USAGE
Verwendung:
  $0 [--dry-run] install
  $0 [--dry-run] enable
  $0 [--dry-run] disable
  $0 [--dry-run] status
  $0 [--dry-run] allow <port|ip>
  $0 [--dry-run] deny <port|ip>
  $0 [--dry-run] reset

Optionen:
  --dry-run   zeigt nur, was passieren wuerde; keine Root-Rechte noetig
USAGE
}

parse_args() {
  local parsed=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --dry-run)
        DRY_RUN=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        parsed+=("$1")
        shift
        ;;
    esac
  done
  set -- "${parsed[@]}"
  COMMAND="${1:-}"
  ARGUMENT="${2:-}"
}

is_tty() {
  [ -t 0 ] && [ -t 1 ]
}

run_cmd() {
  if [ "$DRY_RUN" -eq 1 ]; then
    info "DRY-RUN: $*"
    return 0
  fi
  "$@"
}

shadow_path() {
  printf '%s%s' "$DRY_RUN_STATE_DIR" "$1"
}

path_exists() {
  local target="$1"
  if [ "$DRY_RUN" -eq 1 ]; then
    [ -f "$(shadow_path "$target")" ]
    return $?
  fi
  [ -f "$target" ]
}

write_file() {
  local target="$1"
  local content="$2"

  if [ "$DRY_RUN" -eq 1 ]; then
    local dry_target
    dry_target="$(shadow_path "$target")"
    mkdir -p "$(dirname "$dry_target")"
    printf '%s\n' "$content" > "$dry_target"
    info "DRY-RUN: Datei schreiben -> ${target}"
    printf '%s\n' "$content"
    return 0
  fi

  mkdir -p "$(dirname "$target")"
  printf '%s\n' "$content" > "$target"
}

require_root() {
  if [ "$DRY_RUN" -eq 1 ]; then
    return 0
  fi
  if [ "$(id -u)" -ne 0 ]; then
    fail "Dieser Befehl braucht Root-Rechte. Bitte mit sudo ausfuehren oder --dry-run nutzen."
  fi
}

require_nft() {
  if [ -z "$NFT_BIN" ]; then
    if [ "$DRY_RUN" -eq 1 ]; then
      warn "nft wurde nicht gefunden. Ruleset kann nur als Vorschau erzeugt werden."
      return 0
    fi
    fail "nft (nftables) ist nicht installiert. Installieren mit: sudo apt-get install nftables"
  fi
}

trim_csv() {
  printf '%s' "$1" | sed 's/[[:space:]]//g; s/,,*/,/g; s/^,//; s/,$//'
}

join_csv_unique() {
  local current="$1"
  local item="$2"
  if [ -z "$(trim_csv "$current")" ]; then
    printf '%s' "$item"
    return 0
  fi
  printf '%s\n%s\n' "$(trim_csv "$current" | tr ',' '\n')" "$item" | awk 'NF' | sort -u | paste -sd',' -
}

join_csv_unique_ports() {
  local current="$1"
  local item="$2"
  if [ -z "$(trim_csv "$current")" ]; then
    printf '%s' "$item"
    return 0
  fi
  printf '%s\n%s\n' "$(trim_csv "$current" | tr ',' '\n')" "$item" | awk 'NF' | sort -n | uniq | paste -sd',' -
}

remove_csv_item() {
  local current
  current="$(trim_csv "$1")"
  local item="$2"
  if [ -z "$current" ]; then
    return 0
  fi
  printf '%s' "$current" | tr ',' '\n' | awk -v item="$item" '$0 != item && NF' | paste -sd',' -
}

is_valid_port() {
  case "$1" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$1" -ge 1 ] && [ "$1" -le 65535 ]
}

is_valid_ipv4() {
  local ip="$1"
  local IFS='.'
  local -a octets
  read -r -a octets <<< "$ip"
  [ "${#octets[@]}" -eq 4 ] || return 1
  local octet
  for octet in "${octets[@]}"; do
    case "$octet" in
      ''|*[!0-9]*) return 1 ;;
    esac
    [ "$octet" -ge 0 ] && [ "$octet" -le 255 ] || return 1
  done
}

sort_csv_ports() {
  local csv
  csv="$(trim_csv "$1")"
  if [ -z "$csv" ]; then
    return 0
  fi
  printf '%s' "$csv" | tr ',' '\n' | awk 'NF' | sort -n | uniq | paste -sd',' -
}

sort_csv_ips() {
  local csv
  csv="$(trim_csv "$1")"
  if [ -z "$csv" ]; then
    return 0
  fi
  printf '%s' "$csv" | tr ',' '\n' | awk 'NF' | sort -u | paste -sd',' -
}

validate_csv_ports() {
  local csv
  csv="$(trim_csv "$1")"
  [ -z "$csv" ] && return 0
  local port
  IFS=',' read -r -a PORTS <<< "$csv"
  for port in "${PORTS[@]}"; do
    is_valid_port "$port" || fail "Ungueltiger Port in Konfiguration: ${port}"
  done
}

validate_csv_ips() {
  local csv
  csv="$(trim_csv "$1")"
  [ -z "$csv" ] && return 0
  local ip
  IFS=',' read -r -a IPS <<< "$csv"
  for ip in "${IPS[@]}"; do
    is_valid_ipv4 "$ip" || fail "Ungueltige IPv4-Adresse in Konfiguration: ${ip}"
  done
}

normalize_config_values() {
  PROFILE="${PROFILE:-$DEFAULT_PROFILE}"
  SSH_PORT="${SSH_PORT:-$DEFAULT_SSH_PORT}"
  ALLOW_TCP_PORTS="$(sort_csv_ports "${ALLOW_TCP_PORTS:-$DEFAULT_ALLOW_TCP_PORTS}")"
  DENY_TCP_PORTS="$(sort_csv_ports "${DENY_TCP_PORTS:-$DEFAULT_DENY_TCP_PORTS}")"
  ALLOW_IPS="$(sort_csv_ips "${ALLOW_IPS:-$DEFAULT_ALLOW_IPS}")"
  DENY_IPS="$(sort_csv_ips "${DENY_IPS:-$DEFAULT_DENY_IPS}")"
  is_valid_port "$SSH_PORT" || fail "SSH_PORT ist ungueltig: ${SSH_PORT}"
  validate_csv_ports "$ALLOW_TCP_PORTS"
  validate_csv_ports "$DENY_TCP_PORTS"
  validate_csv_ips "$ALLOW_IPS"
  validate_csv_ips "$DENY_IPS"
}

save_config() {
  normalize_config_values
  local content
  content=$(cat <<CFG
# Konfiguration fuer Nick Firewall
# Ehrlich getestet fuer Debian/Ubuntu mit nftables. Kein Ersatz fuer Hardware-/Enterprise-Firewalls.
PROFILE="${PROFILE}"
SSH_PORT="${SSH_PORT}"
ALLOW_TCP_PORTS="${ALLOW_TCP_PORTS}"
DENY_TCP_PORTS="${DENY_TCP_PORTS}"
ALLOW_IPS="${ALLOW_IPS}"
DENY_IPS="${DENY_IPS}"
CFG
)
  write_file "$CONFIG_FILE" "$content"
}

load_config() {
  if ! path_exists "$CONFIG_FILE"; then
    setup_defaults
    save_config
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    # shellcheck disable=SC1090
    . "$(shadow_path "$CONFIG_FILE")"
  else
    # shellcheck disable=SC1090
    . "$CONFIG_FILE"
  fi
  normalize_config_values
}

find_ssh_port() {
  if [ -f "$SSHD_CONFIG" ]; then
    local configured_port
    configured_port=$(awk 'tolower($1) == "port" && $2 ~ /^[0-9]+$/ { print $2; exit }' "$SSHD_CONFIG" || true)
    if [ -n "${configured_port:-}" ] && is_valid_port "$configured_port"; then
      printf '%s' "$configured_port"
      return 0
    fi
  fi
  printf '%s' "$DEFAULT_SSH_PORT"
}

find_open_ports() {
  if [ -z "$SS_BIN" ]; then
    printf '%s' "$DEFAULT_ALLOW_TCP_PORTS"
    return 0
  fi
  local detected
  detected=$($SS_BIN -tlnH 2>/dev/null | awk '
    {
      split($4, parts, ":")
      port = parts[length(parts)]
      if (port ~ /^[0-9]+$/) print port
    }
  ' | sort -n | uniq | paste -sd',' - || true)
  printf '%s' "${detected:-$DEFAULT_ALLOW_TCP_PORTS}"
}

ports_for_profile() {
  local profile="$1"
  local ssh_port="$2"
  case "$profile" in
    ssh-only)
      printf '%s' "$ssh_port"
      ;;
    *)
      printf '%s' "$(sort_csv_ports "${ssh_port},80,443")"
      ;;
  esac
}

setup_defaults() {
  local detected_ssh
  detected_ssh="$(find_ssh_port)"
  PROFILE="$DEFAULT_PROFILE"
  SSH_PORT="$detected_ssh"
  ALLOW_TCP_PORTS="$(ports_for_profile "$PROFILE" "$SSH_PORT")"
  DENY_TCP_PORTS="$DEFAULT_DENY_TCP_PORTS"
  ALLOW_IPS="$DEFAULT_ALLOW_IPS"
  DENY_IPS="$DEFAULT_DENY_IPS"
}

interactive_setup() {
  local detected_ssh detected_open preset_choice custom_ports custom_allow_ips
  detected_ssh="$(find_ssh_port)"
  detected_open="$(find_open_ports)"

  info "Interaktives Setup startet. Vorschlag: SSH-Port ${detected_ssh}, offene Ports: ${detected_open:-keine erkannt}."
  echo "Waehle ein Preset:"
  echo "  1) Webserver (sicherer Standard: SSH + 80 + 443)"
  echo "  2) Reiner SSH-Server (nur SSH offen)"
  echo "  3) Custom"
  read -r -p "Preset [1]: " preset_choice
  preset_choice="${preset_choice:-1}"

  case "$preset_choice" in
    2) PROFILE="ssh-only" ;;
    3) PROFILE="custom" ;;
    *) PROFILE="webserver" ;;
  esac

  read -r -p "SSH-Port [${detected_ssh}]: " SSH_PORT
  SSH_PORT="${SSH_PORT:-$detected_ssh}"
  is_valid_port "$SSH_PORT" || fail "Ungueltiger SSH-Port: ${SSH_PORT}"

  if [ "$PROFILE" = "custom" ]; then
    read -r -p "Erlaubte TCP-Ports (CSV) [${SSH_PORT}]: " custom_ports
    ALLOW_TCP_PORTS="${custom_ports:-$SSH_PORT}"
  else
    ALLOW_TCP_PORTS="$(ports_for_profile "$PROFILE" "$SSH_PORT")"
    if [ -n "$detected_open" ]; then
      echo "Erkannte offene TCP-Ports: ${detected_open}"
      read -r -p "Diese erkannten Ports zusaetzlich dauerhaft erlauben? [y/N]: " preset_choice
      case "${preset_choice:-N}" in
        y|Y|yes|YES)
          ALLOW_TCP_PORTS="$(sort_csv_ports "${ALLOW_TCP_PORTS},${detected_open}")"
          ;;
      esac
    fi
  fi

  read -r -p "Zusaetzliche Allow-IP(s), CSV, optional []: " custom_allow_ips
  ALLOW_IPS="${custom_allow_ips:-}"
  DENY_TCP_PORTS=""
  DENY_IPS=""
  normalize_config_values
}

ensure_config_ready() {
  if path_exists "$CONFIG_FILE"; then
    load_config
    return 0
  fi
  if is_tty; then
    interactive_setup
  else
    setup_defaults
  fi
  save_config
}

build_nft_set_body() {
  local values="$1"
  if [ -z "$values" ]; then
    return 0
  fi
  printf '        elements = { %s }\n' "$(printf '%s' "$values" | sed 's/,/, /g')"
}

ports_to_nft_set() {
  local values="$1"
  if [ -z "$values" ]; then
    printf '{}'
  else
    printf '{ %s }' "$(printf '%s' "$values" | sed 's/,/, /g')"
  fi
}

ruleset_content() {
  load_config

  local general_ports
  local deny_ip_body
  local allow_ip_body
  local deny_port_body
  general_ports="$(remove_csv_item "$ALLOW_TCP_PORTS" "$SSH_PORT")"
  general_ports="$(sort_csv_ports "$general_ports")"
  deny_ip_body="$(build_nft_set_body "$DENY_IPS")"
  allow_ip_body="$(build_nft_set_body "$ALLOW_IPS")"
  deny_port_body="$(build_nft_set_body "$DENY_TCP_PORTS")"

  cat <<RULESET
 table inet ${TABLE} {
     set blackhole_v4 {
         type ipv4_addr
         flags interval
${deny_ip_body}
     }

     set allowlist_v4 {
         type ipv4_addr
         flags interval
${allow_ip_body}
     }

     set denied_tcp_ports {
         type inet_service
${deny_port_body}
     }

     chain input {
         type filter hook input priority 0; policy drop;

         iif "lo" accept
         ct state established,related accept
         ct state invalid drop

         ip saddr @allowlist_v4 accept comment "trusted-allowlist"
         ip saddr @blackhole_v4 drop comment "blocked-ip-list"

         tcp flags & (fin|syn|rst|psh|ack|urg) == 0 drop comment "null-scan"
         tcp flags & (fin|syn) == (fin|syn) drop comment "syn-fin-scan"
         tcp flags & (syn|rst) == (syn|rst) drop comment "syn-rst-scan"

         icmp type echo-request limit rate 5/second accept
         icmpv6 type echo-request limit rate 5/second accept

         tcp dport @denied_tcp_ports drop comment "explicit-port-deny"
         tcp dport ${SSH_PORT} ct state new limit rate 10/minute burst 5 packets accept comment "ssh-rate-limit"
RULESET

  if [ -n "$general_ports" ]; then
    cat <<RULESET
         tcp dport $(ports_to_nft_set "$general_ports") ct state new limit rate 200/second burst 50 packets accept comment "allowed-service-ports"
RULESET
  fi

  cat <<RULESET
         ct state new log prefix "nick-firewall-scan: " flags all drop comment "logged-scan-attempt"
         counter comment "default-deny"
     }

     chain forward {
         type filter hook forward priority 0; policy drop;
     }

     chain output {
         type filter hook output priority 0; policy accept;
     }
 }
RULESET
}

write_ruleset() {
  write_file "$RULESET_FILE" "$(ruleset_content)"
}

service_content() {
  cat <<SERVICE
[Unit]
Description=Nick Firewall (nftables)
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c '/usr/sbin/nft delete table inet ${TABLE} 2>/dev/null || true; /usr/sbin/nft -f ${RULESET_FILE}'
ExecStop=/bin/sh -c '/usr/sbin/nft delete table inet ${TABLE} 2>/dev/null || true'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SERVICE
}

sysctl_content() {
  cat <<SYSCTL
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
SYSCTL
}

apply_ruleset() {
  require_nft
  if [ "$DRY_RUN" -eq 1 ]; then
    info "DRY-RUN: aktive Tabellen ${TABLE}/${LEGACY_TABLE} wuerden neu geladen"
    ruleset_content
    return 0
  fi
  "$NFT_BIN" delete table inet "$TABLE" 2>/dev/null || true
  "$NFT_BIN" -f "$RULESET_FILE"
}

warn_if_legacy_active() {
  if [ -n "$NFT_BIN" ] && "$NFT_BIN" list table inet "$LEGACY_TABLE" >/dev/null 2>&1; then
    warn "Legacy-Tabelle ${LEGACY_TABLE} ist noch aktiv. Nick Firewall ersetzt sie nicht automatisch, um bestehende Regeln nicht destruktiv zu loeschen."
    warn "Pruefe vor Produktivbetrieb bewusst, ob die alte Servnix-Firewall noch benoetigt wird."
  fi
}

install_cli_copy() {
  if [ "$SCRIPT_PATH" = "$BIN_PATH" ]; then
    return 0
  fi
  if [ "$DRY_RUN" -eq 1 ]; then
    info "DRY-RUN: ${SCRIPT_PATH} -> ${BIN_PATH} kopieren"
    return 0
  fi
  install -Dm755 "$SCRIPT_PATH" "$BIN_PATH"
}

cmd_install() {
  require_root
  ensure_config_ready
  write_ruleset
  write_file "$SERVICE_FILE" "$(service_content)"
  write_file "$SYSCTL_FILE" "$(sysctl_content)"
  install_cli_copy
  warn_if_legacy_active
  apply_ruleset
  run_cmd sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
  if [ -n "$SYSTEMCTL_BIN" ]; then
    run_cmd "$SYSTEMCTL_BIN" daemon-reload
    run_cmd "$SYSTEMCTL_BIN" enable nick-firewall.service >/dev/null 2>&1 || true
  fi
  info "Installiert. Config: ${CONFIG_FILE}"
  info "Aktivieren/Status: sudo nick-firewall enable | status"
}

cmd_enable() {
  require_root
  ensure_config_ready
  write_ruleset
  warn_if_legacy_active
  apply_ruleset
  if [ -n "$SYSTEMCTL_BIN" ]; then
    run_cmd "$SYSTEMCTL_BIN" daemon-reload
    run_cmd "$SYSTEMCTL_BIN" enable nick-firewall.service >/dev/null 2>&1 || true
    run_cmd "$SYSTEMCTL_BIN" start nick-firewall.service >/dev/null 2>&1 || true
  fi
  info "Aktiviert. Erlaubte TCP-Ports: ${ALLOW_TCP_PORTS}"
}

cmd_disable() {
  require_root
  require_nft
  if [ "$DRY_RUN" -eq 1 ]; then
    info "DRY-RUN: Tabellen ${TABLE}/${LEGACY_TABLE} wuerden entfernt und der Dienst gestoppt"
    return 0
  fi
  "$NFT_BIN" delete table inet "$TABLE" 2>/dev/null || true
  "$NFT_BIN" delete table inet "$LEGACY_TABLE" 2>/dev/null || true
  if [ -n "$SYSTEMCTL_BIN" ]; then
    "$SYSTEMCTL_BIN" stop nick-firewall.service >/dev/null 2>&1 || true
  fi
  warn "Deaktiviert. Ohne andere Firewall gibt es dann keinen Schutz aus diesem Regelwerk."
}

service_status_text() {
  if [ -n "$SYSTEMCTL_BIN" ] && [ -f "$SERVICE_FILE" ]; then
    "$SYSTEMCTL_BIN" is-enabled nick-firewall.service 2>/dev/null || true
  else
    echo "nicht installiert"
  fi
}

active_table_name() {
  if [ -n "$NFT_BIN" ] && "$NFT_BIN" list table inet "$TABLE" >/dev/null 2>&1; then
    printf '%s' "$TABLE"
    return 0
  fi
  if [ -n "$NFT_BIN" ] && "$NFT_BIN" list table inet "$LEGACY_TABLE" >/dev/null 2>&1; then
    printf '%s' "$LEGACY_TABLE"
    return 0
  fi
  return 1
}

cmd_status() {
  ensure_config_ready
  info "Config-Datei: ${CONFIG_FILE}"
  info "Profil: ${PROFILE}"
  info "SSH-Port: ${SSH_PORT}"
  info "Erlaubte TCP-Ports: ${ALLOW_TCP_PORTS:-keine}"
  info "Explizit gesperrte TCP-Ports: ${DENY_TCP_PORTS:-keine}"
  info "Allow-IP(s): ${ALLOW_IPS:-keine}"
  info "Deny-IP(s): ${DENY_IPS:-keine}"
  info "systemd: $(service_status_text)"

  if table_name="$(active_table_name)"; then
    info "Aktive nftables-Tabelle: ${table_name}"
    "$NFT_BIN" list table inet "$table_name"
  else
    warn "Keine aktive Nick-Firewall-Tabelle geladen."
    return 1
  fi
}

reload_after_config_change() {
  if [ "$DRY_RUN" -eq 1 ]; then
    write_ruleset
    info "DRY-RUN: geaenderte Konfiguration wuerde sofort neu geladen"
    return 0
  fi
  cmd_enable
}

cmd_allow() {
  [ -n "${ARGUMENT:-}" ] || fail "allow braucht ein Ziel: Port oder IPv4-Adresse"
  ensure_config_ready
  if is_valid_port "$ARGUMENT"; then
    ALLOW_TCP_PORTS="$(join_csv_unique_ports "$ALLOW_TCP_PORTS" "$ARGUMENT")"
    DENY_TCP_PORTS="$(remove_csv_item "$DENY_TCP_PORTS" "$ARGUMENT")"
    save_config
    reload_after_config_change
    info "Port ${ARGUMENT} ist jetzt erlaubt."
    return 0
  fi
  if is_valid_ipv4 "$ARGUMENT"; then
    ALLOW_IPS="$(join_csv_unique "$ALLOW_IPS" "$ARGUMENT")"
    DENY_IPS="$(remove_csv_item "$DENY_IPS" "$ARGUMENT")"
    save_config
    reload_after_config_change
    info "IP ${ARGUMENT} ist jetzt auf der Allowlist."
    return 0
  fi
  fail "allow akzeptiert nur einzelne TCP-Ports oder IPv4-Adressen"
}

cmd_deny() {
  [ -n "${ARGUMENT:-}" ] || fail "deny braucht ein Ziel: Port oder IPv4-Adresse"
  ensure_config_ready
  if is_valid_port "$ARGUMENT"; then
    DENY_TCP_PORTS="$(join_csv_unique_ports "$DENY_TCP_PORTS" "$ARGUMENT")"
    ALLOW_TCP_PORTS="$(remove_csv_item "$ALLOW_TCP_PORTS" "$ARGUMENT")"
    save_config
    reload_after_config_change
    info "Port ${ARGUMENT} ist jetzt explizit gesperrt."
    return 0
  fi
  if is_valid_ipv4 "$ARGUMENT"; then
    DENY_IPS="$(join_csv_unique "$DENY_IPS" "$ARGUMENT")"
    ALLOW_IPS="$(remove_csv_item "$ALLOW_IPS" "$ARGUMENT")"
    save_config
    reload_after_config_change
    info "IP ${ARGUMENT} ist jetzt auf der Sperrliste."
    return 0
  fi
  fail "deny akzeptiert nur einzelne TCP-Ports oder IPv4-Adressen"
}

cmd_reset() {
  require_root
  if is_tty; then
    interactive_setup
  else
    setup_defaults
  fi
  save_config
  write_ruleset
  apply_ruleset
  info "Konfiguration auf sinnvolle Defaults/Preset zurueckgesetzt."
}

parse_args "$@"

case "$COMMAND" in
  install) cmd_install ;;
  enable) cmd_enable ;;
  disable) cmd_disable ;;
  status) cmd_status ;;
  allow) cmd_allow ;;
  deny) cmd_deny ;;
  reset) cmd_reset ;;
  *)
    usage >&2
    exit 1
    ;;
esac
