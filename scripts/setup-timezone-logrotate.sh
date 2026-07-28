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
# Auto-detect direktori instalasi dari lokasi script ini (scripts/..) → bebas dir,
# tidak harus /root. Override manual: TS_DIR=/path/ke/turboshield sudo -E bash ...
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
TS_DIR="${TS_DIR:-$(cd "$SCRIPT_DIR/.." && pwd)}"
echo "Install dir terdeteksi: ${TS_DIR}"

# 1. Timezone host
log "Set timezone host → ${TZ_WANT}"
timedatectl set-timezone "$TZ_WANT" 2>/dev/null || ln -sf "/usr/share/zoneinfo/${TZ_WANT}" /etc/localtime
ok "Host TZ: $(date +'%Z %z')"

# 2. Logrotate untuk audit log (generate config dgn path aktual, bukan hardcoded)
log "Pasang logrotate config"
sed "s#__TS_DIR__#${TS_DIR}#g" "${TS_DIR}/scripts/logrotate-turboshield" > /etc/logrotate.d/turboshield
ok "Config: /etc/logrotate.d/turboshield (log: ${TS_DIR}/waf/logs)"
log "Uji (dry-run):"
logrotate --debug /etc/logrotate.d/turboshield 2>&1 | grep -E "considering|rotating|log needs" | head || true

# 3. Restart stack agar TZ container aktif (butuh recreate)
if command -v docker >/dev/null 2>&1 && [ -f "${TS_DIR}/docker-compose.yml" ]; then
  log "Recreate container agar TZ Asia/Jakarta aktif"
  (cd "$TS_DIR" && docker compose up -d)
  ok "Container TZ: $(docker exec ts-waf date +'%Z %z' 2>/dev/null || echo '-')"
fi

echo -e "${GREEN}Selesai.${NC} Logrotate berjalan otomatis via cron harian (/etc/cron.daily/logrotate)."
