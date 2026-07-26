# Instalasi TurboShield Gateway

Panduan lengkap instalasi dari nol di server Debian/Ubuntu.

## Prasyarat
- Server Debian 12 / Ubuntu 22.04+ (x86_64), akses root.
- Domain mengarah ke IP publik server (untuk SSL Let's Encrypt).
- Port **80**, **443** (WAF) dan **8181** (dashboard) terbuka.

## 1. Install Docker + Hardening

```bash
git clone <repo-url> /opt/turboshield
cd /opt/turboshield
sudo bash scripts/install-docker-hardened.sh
```

Script ini memasang Docker Engine resmi dan menerapkan hardening + tweak real-IP
(`userland-proxy:false`). Lihat [HARDENING.md](HARDENING.md) & [REAL-IP.md](REAL-IP.md).

> **Catatan userns-remap:** dashboard butuh akses `docker.sock` untuk reload WAF.
> Jika mengaktifkan `userns-remap` di daemon.json, jalankan script dengan
> `TS_DISABLE_USERNS=1 sudo bash scripts/install-docker-hardened.sh` agar tidak bentrok.

## 2. Deploy Stack

```bash
cd /opt/turboshield
docker compose up -d
docker compose ps        # pastikan ts-waf, ts-dashboard, ts-testapp Up
```

Container:
- **ts-waf** — nginx + ModSecurity, publish `80:8080` & `443:8443`
- **ts-dashboard** — FastAPI, publish `8181:8181`
- **ts-testapp** — backend demo untuk uji WAF

## 3. Setup Admin (First-Run Wizard)

Buka `http://<server-ip>:8181` di browser:
1. Pilih bahasa (Indonesia / English) di pojok kanan atas.
2. Masukkan **email admin**.
3. Sistem meng-generate **password kuat** — tampil sekali (dan dikirim ke Telegram bila sudah dikonfigurasi).
4. Simpan password, lalu login.

## 4. Konfigurasi Awal yang Disarankan

- **WAF & Security** → pastikan Engine Mode = **On (Blocking)**, threshold sesuai kebutuhan.
- **Proxy & Routing** → tambah host produksimu (domain + upstream), aktifkan SSL.
- **Integrasi** → isi Telegram bot (untuk alert) & LibreNMS (opsional).

## 5. SSL untuk Domain

Di menu **Proxy & Routing** → pilih host → **🔒 SSL**:
- **Let's Encrypt**: klik Terbitkan (domain harus sudah mengarah ke server).
- **Upload sendiri**: tempel fullchain PEM + private key.

## Verifikasi

```bash
# request normal → 200
curl -I https://<domain>/
# serangan → 403
curl "https://<domain>/?q=1'+OR+'1'='1"
```

## Troubleshooting

| Gejala | Solusi |
|---|---|
| WAF restart-loop | `docker logs ts-waf` — cek permission file config (harus 644) |
| Dashboard tak reload WAF | pastikan `/var/run/docker.sock` ter-mount & docker-cli ada di container |
| SSL gagal | cek DNS domain → IP server, port 80 terbuka untuk ACME challenge |
| IP log = 172.x | terapkan `userland-proxy:false` (lihat REAL-IP.md) & restart docker |
