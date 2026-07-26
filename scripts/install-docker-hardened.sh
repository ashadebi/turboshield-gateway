#!/usr/bin/env bash
# =============================================================================
# TurboShield — Docker Install + Hardening (Debian/Ubuntu)
# Memasang Docker Engine resmi + menerapkan hardening (CIS-inspired) dan
# tweak agar IP PUBLIK ASLI klien tercatat di log (bukan IP gateway Docker).
#
# Idempotent: aman dijalankan ulang. Membuat backup config sebelum mengubah.
# Jalankan sebagai root:  sudo bash install-docker-hardened.sh
# =============================================================================
set -euo pipefail

BLUE="\033[1;34m"; GREEN="\033[1;32m"; YELLOW="\033[1;33m"; RED="\033[1;31m"; NC="\033[0m"
log(){ echo -e "${BLUE}[TurboShield]${NC} $*"; }
ok(){ echo -e "${GREEN}  ✓${NC} $*"; }
warn(){ echo -e "${YELLOW}  ! $*${NC}"; }
err(){ echo -e "${RED}  ✗ $*${NC}"; }

[ "$(id -u)" -eq 0 ] || { err "Harus dijalankan sebagai root (sudo)."; exit 1; }
TS=$(date +%Y%m%d-%H%M%S)

# ------------------------------------------------------------------ 1. Docker
install_docker(){
  if command -v docker >/dev/null 2>&1; then
    ok "Docker sudah terpasang: $(docker --version)"
    return
  fi
  log "Memasang Docker Engine (repo resmi)…"
  apt-get update -qq
  apt-get install -y -qq ca-certificates curl gnupg >/dev/null
  install -m 0755 -d /etc/apt/keyrings
  local distro; distro=$(. /etc/os-release && echo "$ID")
  curl -fsSL "https://download.docker.com/linux/${distro}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
https://download.docker.com/linux/${distro} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update -qq
  apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin >/dev/null
  ok "Docker terpasang: $(docker --version)"
}

# ------------------------------------------------ 2. daemon.json (hardening + real-IP)
configure_daemon(){
  log "Menerapkan /etc/docker/daemon.json (hardening + real-IP)…"
  mkdir -p /etc/docker
  [ -f /etc/docker/daemon.json ] && cp /etc/docker/daemon.json "/etc/docker/daemon.json.bak-${TS}" && warn "backup daemon.json lama dibuat"
  cat > /etc/docker/daemon.json <<'JSON'
{
  "userland-proxy": false,
  "no-new-privileges": true,
  "live-restore": true,
  "icc": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "default-ulimits": {
    "nofile": { "Name": "nofile", "Hard": 65535, "Soft": 65535 }
  },
  "userns-remap": "default"
}
JSON
  ok "daemon.json ditulis"
  echo -e "  ${YELLOW}Penjelasan kunci:${NC}"
  echo "    userland-proxy=false → IP PUBLIK ASLI klien terbaca (bukan 172.x gateway)"
  echo "    no-new-privileges    → cegah privilege escalation di container"
  echo "    icc=false            → matikan komunikasi antar-container default (segmentasi)"
  echo "    live-restore         → container tetap jalan saat daemon restart"
  echo "    userns-remap         → remap root container ke user tak-berhak di host"
}

# --------------------------------------------------------- 3. userns-remap note
handle_userns(){
  # userns-remap kadang bentrok dgn bind-mount /var/run/docker.sock (dashboard TurboShield).
  # Kalau ingin dashboard bisa reload WAF via socket, userns-remap perlu dimatikan.
  if [ "${TS_DISABLE_USERNS:-0}" = "1" ]; then
    warn "TS_DISABLE_USERNS=1 → menonaktifkan userns-remap (kompatibilitas docker.sock)"
    sed -i '/"userns-remap"/d' /etc/docker/daemon.json
    # bersihkan trailing comma
    sed -i ':a;N;$!ba;s/,\n}/\n}/' /etc/docker/daemon.json
  fi
}

# -------------------------------------------------------------- 4. restart docker
restart_docker(){
  log "Restart Docker…"
  systemctl enable docker >/dev/null 2>&1 || true
  systemctl restart docker
  sleep 3
  docker info >/dev/null 2>&1 && ok "Docker aktif kembali" || { err "Docker gagal start — cek: journalctl -u docker"; exit 1; }
  local up; up=$(docker info --format '{{.SecurityOptions}}' 2>/dev/null)
  echo "  SecurityOptions: $up"
}

# ------------------------------------------------------- 5. kernel/sysctl hardening
harden_sysctl(){
  log "Hardening sysctl (network)…"
  cat > /etc/sysctl.d/99-turboshield.conf <<'SYS'
# TurboShield network hardening
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1
# izinkan forwarding (dibutuhkan Docker)
net.ipv4.ip_forward=1
SYS
  sysctl -p /etc/sysctl.d/99-turboshield.conf >/dev/null 2>&1 || true
  ok "sysctl diterapkan"
}

# ------------------------------------------------------------- 6. auditd (opsional)
setup_audit(){
  if [ "${TS_ENABLE_AUDIT:-0}" = "1" ]; then
    log "Memasang auditd + rules Docker (CIS 1.1)…"
    apt-get install -y -qq auditd >/dev/null 2>&1 || true
    cat > /etc/audit/rules.d/docker.rules <<'AUD'
-w /usr/bin/docker -p wa -k docker
-w /var/lib/docker -p wa -k docker
-w /etc/docker -p wa -k docker
-w /etc/docker/daemon.json -p wa -k docker
-w /usr/bin/containerd -p wa -k docker
-w /usr/bin/runc -p wa -k docker
AUD
    systemctl restart auditd 2>/dev/null || service auditd restart 2>/dev/null || true
    ok "auditd rules dipasang"
  else
    warn "auditd dilewati (set TS_ENABLE_AUDIT=1 untuk mengaktifkan)"
  fi
}

# ------------------------------------------------------------------- MAIN
main(){
  echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
  echo -e "${GREEN}║  TurboShield — Docker Install + Hardening     ║${NC}"
  echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
  install_docker
  configure_daemon
  handle_userns
  harden_sysctl
  restart_docker
  setup_audit
  echo
  ok "SELESAI. Docker terpasang & di-harden."
  echo -e "${YELLOW}Langkah lanjut:${NC}"
  echo "  • Deploy stack TurboShield: cd /opt/turboshield && docker compose up -d"
  echo "  • Pastikan real-IP: lihat docs/REAL-IP.md"
  echo "  • Jika dashboard perlu docker.sock & userns bentrok, jalankan ulang dengan:"
  echo "      TS_DISABLE_USERNS=1 sudo bash $0"
}
main "$@"
