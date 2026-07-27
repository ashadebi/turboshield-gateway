# Hardening Docker & Host

Script `scripts/install-docker-hardened.sh` menerapkan hardening berikut. Ini adalah
praktik CIS-inspired yang seimbang antara keamanan dan kompatibilitas.

## `/etc/docker/daemon.json`

```json
{
  "userland-proxy": false,
  "no-new-privileges": true,
  "live-restore": true,
  "icc": false,
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "5" },
  "default-ulimits": { "nofile": { "Name": "nofile", "Hard": 65535, "Soft": 65535 } },
  "userns-remap": "default"
}
```

| Opsi | Fungsi keamanan |
|---|---|
| `userland-proxy: false` | Preserve source IP (real-IP) + kurangi attack surface proxy |
| `no-new-privileges: true` | Cegah privilege escalation (setuid) di dalam container |
| `icc: false` | Matikan komunikasi antar-container default → segmentasi jaringan |
| `live-restore: true` | Container tetap jalan saat daemon di-restart/upgrade |
| `log-opts` | Rotasi log → cegah disk penuh (DoS) |
| `default-ulimits` | Batasi file descriptor → cegah exhaustion |
| `userns-remap: default` | Root di container ≠ root di host (mitigasi container escape) |

> **Trade-off userns-remap:** menyulitkan bind-mount `docker.sock` & beberapa volume.
> TurboShield dashboard butuh `docker.sock` untuk reload WAF, jadi di deployment
> standar userns-remap **dinonaktifkan** (jalankan script dengan `TS_DISABLE_USERNS=1`).
> Alternatif lebih aman: gunakan **socket-proxy** (tehcnitium/docker-socket-proxy)
> yang membatasi API Docker yang boleh diakses dashboard.

## sysctl (`/etc/sysctl.d/99-turboshield.conf`)

```
net.ipv4.conf.all.rp_filter=1          # anti IP spoofing
net.ipv4.tcp_syncookies=1              # mitigasi SYN flood
net.ipv4.conf.all.accept_redirects=0   # tolak ICMP redirect
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.all.log_martians=1       # log paket mencurigakan
net.ipv4.ip_forward=1                  # dibutuhkan Docker
```

## auditd (opsional, `TS_ENABLE_AUDIT=1`)

Memantau file & binary Docker (CIS 1.1.x): `/usr/bin/docker`, `/var/lib/docker`,
`/etc/docker`, `containerd`, `runc`. Berguna untuk forensik & deteksi tamper.

## Praktik tambahan yang disarankan

- **Firewall**: batasi `:8181` (dashboard) ke IP admin / VPN saja.
- **Non-root containers**: jalankan image dengan `user:` non-root bila memungkinkan.
- **Read-only rootfs**: tambahkan `read_only: true` + `tmpfs` untuk container stateless.
- **Resource limits**: set `mem_limit`, `cpus`, `pids_limit` di compose.
- **Image scanning**: pindai image dengan `trivy` / `docker scout` sebelum deploy.
- **Update rutin**: `apt upgrade` + `docker pull` image terbaru berkala.

## Timezone & Log Rotation

**Timezone:** seluruh stack di-set ke **Asia/Jakarta (WIB)** — host via `timedatectl`,
container via env `TZ: "Asia/Jakarta"` di `docker-compose.yml`. Ini membuat timestamp
di audit log & UI konsisten dengan waktu lokal.

**Logrotate:** audit log ModSecurity (`waf/logs/*.log`) dirotasi otomatis:
- harian, simpan 14 arsip (~2 minggu), atau lebih awal bila > 50MB
- `copytruncate` → truncate tanpa restart nginx (ModSecurity terus menulis ke fd sama)
- arsip di-gzip (`delaycompress`), penamaan bertanggal (`modsec_audit.log-YYYYMMDD.gz`)

Pasang keduanya sekaligus:
```bash
sudo bash scripts/setup-timezone-logrotate.sh
```
Atau manual: `sudo cp scripts/logrotate-turboshield /etc/logrotate.d/turboshield`
(jalan otomatis via `/etc/cron.daily/logrotate`). Juga: log Docker sendiri dibatasi
via `log-opts` di daemon.json (max 10MB × 5 file per container).

## Menjalankan

```bash
sudo bash scripts/install-docker-hardened.sh
# dengan auditd:
TS_ENABLE_AUDIT=1 sudo bash scripts/install-docker-hardened.sh
# tanpa userns-remap (kompatibilitas docker.sock):
TS_DISABLE_USERNS=1 sudo bash scripts/install-docker-hardened.sh
```

Semua perubahan mem-backup config lama (`.bak-<timestamp>`) dan idempotent.
