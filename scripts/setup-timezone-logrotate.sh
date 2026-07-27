#!/usr/bin/env bash
# =============================================================================
# TurboShield — Setup Timezone (Asia/Jakarta) + Logrotate audit log
# Jalankan sebagai root:  sudo bash scripts/setup-timezone-logrotate.sh
# =============================================================================
set -euo pipefail
GREEN="\033[1;32m"; BLUE="\033[1;34m"; NC="\033[0m"
log(){ echo -e "${BLUE}[TurboShield]${NC} $*"; }
ok(){ echo -e "${GREEN}  ✓${NC} $*"; }
[ "$(id -u)" -eq 0 ] || { echo "Harus root (sudo)."; exit 1; }

TZ_WANT="Asia/Jakarta"
TS_DIR="${TS_DIR:-/root/turboshield}"

# 1. Timezone host
log "Set timezone host → ${TZ_WANT}"
timedatectl set-timezone "$TZ_WANT" 2>/dev/null || ln -sf "/usr/share/zoneinfo/${TZ_WANT}" /etc/localtime
ok "Host TZ: $(date +'%Z %z')"

# 2. Logrotate untuk audit log
log "Pasang logrotate config"
cp "${TS_DIR}/scripts/logrotate-turboshield" /etc/logrotate.d/turboshield
sed -i "s#/root/turboshield#${TS_DIR}#g" /etc/logrotate.d/turboshield
ok "Config: /etc/logrotate.d/turboshield"
log "Uji (dry-run):"
logrotate --debug /etc/logrotate.d/turboshield 2>&1 | grep -E "considering|rotating|log needs" | head || true

# 3. Restart stack agar TZ container aktif (butuh recreate)
if command -v docker >/dev/null 2>&1 && [ -f "${TS_DIR}/docker-compose.yml" ]; then
  log "Recreate container agar TZ Asia/Jakarta aktif"
  (cd "$TS_DIR" && docker compose up -d)
  ok "Container TZ: $(docker exec ts-waf date +'%Z %z' 2>/dev/null || echo '-')"
fi

echo -e "${GREEN}Selesai.${NC} Logrotate berjalan otomatis via cron harian (/etc/cron.daily/logrotate)."
