# 📖 Panduan Instalasi TurboShield Gateway (dari Nol)

Panduan ini menuntun kamu langkah demi langkah — dari server kosong sampai
WAF + dashboard hidup dan siap dipakai. Tidak perlu pengalaman Docker sebelumnya.

---

## 🧾 Yang Kamu Butuhkan Sebelum Mulai

| Kebutuhan | Keterangan |
|---|---|
| Server | Debian 12 atau Ubuntu 22.04+ (x86_64), akses **root** |
| Port terbuka | **80** & **443** (untuk WAF), **8181** (untuk dashboard admin) |
| Domain (opsional) | Kalau mau pakai SSL Let's Encrypt, domain harus sudah mengarah ke IP server ini |
| Direktori instalasi | **Bebas** — bisa `/opt`, `/srv`, `~/`, di mana saja. Tidak ada path yang di-hardcode. |

---

## 1️⃣ Clone Repository

Pilih direktori mana saja yang kamu suka:

```bash
git clone https://github.com/ashadebi/turboshield-gateway.git turboshield
cd turboshield
```

> 💡 Semua konfigurasi nanti otomatis mengikuti folder ini — mau kamu taruh di
> `/opt/turboshield`, `/srv/apps/ts`, atau `~/proyek/turboshield`, sama saja.

---

## 2️⃣ Install Docker + Hardening Keamanan

Jalankan script instalasi (butuh `sudo`):

```bash
sudo bash scripts/install-docker-hardened.sh
```

**Apa yang dilakukan script ini:**
- Install Docker Engine resmi dari repo Docker (bukan versi lawas distro)
- Terapkan hardening: `userland-proxy:false` (agar IP asli pengunjung tercatat,
  bukan IP internal Docker), `no-new-privileges`, batasi log container, dan
  beberapa sysctl anti-spoofing
- (Opsional) aktifkan `userns-remap` untuk isolasi container lebih ketat

> ⚠️ **Catatan penting:** dashboard TurboShield butuh akses ke `docker.sock`
> untuk bisa reload WAF otomatis. Kalau kamu ingin `userns-remap` aktif,
> jalankan dengan flag berikut agar tidak bentrok:
> ```bash
> TS_DISABLE_USERNS=1 sudo bash scripts/install-docker-hardened.sh
> ```

Detail lengkap tiap opsi hardening: lihat [`HARDENING.md`](HARDENING.md).

---

## 3️⃣ Jalankan Stack TurboShield

Dari folder yang sama (tempat kamu `git clone` tadi):

```bash
docker compose up -d
docker compose ps
```

Tunggu beberapa saat (pertama kali agak lama karena Docker menarik image dan
memasang dependency). Pastikan ketiga container statusnya **Up**:

| Container | Fungsi | Port |
|---|---|---|
| `ts-waf` | nginx + ModSecurity v3 + OWASP CRS (WAF utama) | 80, 443 |
| `ts-dashboard` | Panel admin FastAPI | 8181 |
| `ts-testapp` | Backend contoh untuk uji coba WAF | (internal) |

Cek status kesehatan:
```bash
curl -I http://localhost/           # harus 200 (lewat WAF, ke testapp)
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8181/api/health   # harus 200
```

---

## 4️⃣ Setup Akun Admin (First-Run Wizard)

Buka browser ke `http://<ip-server-kamu>:8181`

1. **Pilih bahasa** (🇮🇩 Indonesia / 🇬🇧 English) di pojok kanan atas layar
2. Masukkan **email admin** kamu
3. Klik "Buat Akun & Generate Password" — sistem akan membuatkan **password
   kuat otomatis**, ditampilkan **HANYA SEKALI** di layar (dan dikirim ke
   Telegram kalau kamu sudah setting bot Telegram — lihat langkah 6)
4. **Salin & simpan password itu sekarang juga** — tidak akan ditampilkan lagi
5. Klik lanjut, lalu login pakai email + password tadi

---

## 5️⃣ Tambahkan Website/Aplikasi Pertamamu (Proxy & Routing)

Ini langkah supaya WAF mulai melindungi aplikasi asli kamu (bukan cuma testapp bawaan):

1. Buka menu **🌐 Proxy & Routing** di sidebar
2. Klik **➕ Tambah Host**
3. Isi:
   - **Domain**: nama domain aplikasimu, misal `app.contohkamu.com`
   - **Upstream**: alamat backend asli, misal `127.0.0.1:3000` atau
     `nama-container:8080` (kalau backend juga jalan di Docker)
   - **Scheme**: `http` (paling umum, kecuali backend sudah pakai HTTPS sendiri)
   - **Proteksi WAF**: `On` (blocking penuh) — bisa diturunkan ke `Detection Only`
     dulu kalau khawatir false-positive di awal
4. Klik **Simpan & Reload** — WAF langsung aktif melindungi domain ini

**Aktifkan SSL (HTTPS):**
- Kembali ke tabel host, klik tombol **🔒 SSL** di sebelah host tadi
- Pilih **Let's Encrypt** (otomatis, gratis — syaratnya domain sudah mengarah
  ke IP server ini) atau **Upload Sertifikat Sendiri** (tempel isi file
  `.crt`/`.pem` dan private key)

---

## 6️⃣ Setting Notifikasi & Monitoring (Opsional tapi Disarankan)

Buka menu **📡 Integrasi & Monitoring**:
- **Telegram Bot**: isi Bot Token (dari [@BotFather](https://t.me/BotFather))
  + Chat ID kamu → aktifkan supaya password admin & alert serangan dikirim
  otomatis ke Telegram
- **LibreNMS** (kalau kamu punya): isi URL + API token untuk monitoring jaringan

---

## 7️⃣ Atur Rate Limiting & Bot Protection (Opsional, Disarankan untuk Produksi)

- **⏱️ Rate Limiting**: batasi jumlah request per IP/header/cookie/API-key ke
  path tertentu — misal halaman login dibatasi 5 request/menit supaya tidak
  bisa di-brute-force
- **🤖 Bot Protection**: aktifkan block-list scanner (sqlmap, nikto, dst) dan
  atur allow-list search engine (Googlebot, Bingbot) supaya tidak terganggu

Detail lengkap cara pakai tiap menu ini: lihat [`USAGE.md`](USAGE.md).

---

## 8️⃣ Timezone & Log Rotation (Opsional, Disarankan)

Supaya jam di log sesuai zona waktumu dan log tidak membengkak tak terbatas:

```bash
sudo bash scripts/setup-timezone-logrotate.sh
```

Default script ini set ke **Asia/Jakarta** — edit variabel `TZ_WANT` di dalam
script kalau server kamu di zona waktu lain.

---

## ✅ Verifikasi Akhir — Pastikan Semua Bekerja

```bash
# 1. Request normal harus lolos (200)
curl -I https://<domainmu>/

# 2. Serangan SQL Injection harus diblokir WAF (403)
curl "https://<domainmu>/?q=1'+OR+'1'='1"

# 3. Dashboard bisa diakses
curl -s -o /dev/null -w '%{http_code}\n' http://<ip-server>:8181/api/health
```

Kalau ketiganya sesuai ekspektasi (200, 403, 200) — instalasi **selesai dan berfungsi**. 🎉

---

## 🆘 Troubleshooting

| Gejala | Kemungkinan Sebab | Solusi |
|---|---|---|
| `ts-waf` restart terus-menerus | Sertifikat SSL corrupt/kosong | `docker logs ts-waf` — cek error PEM, pastikan file cert bukan direktori kosong |
| Dashboard tidak bisa reload WAF | `docker.sock` tidak ter-mount | Cek `docker-compose.yml` bagian `ts-dashboard` ada baris `/var/run/docker.sock` |
| Let's Encrypt gagal terbit | DNS domain belum mengarah ke server, atau port 80 diblokir firewall | Cek `dig <domain>` harus resolve ke IP server ini; buka port 80 |
| Log/IP tercatat `172.x.x.x` (bukan IP publik asli) | Docker `userland-proxy` masih aktif | Jalankan ulang `scripts/install-docker-hardened.sh`, atau cek [`REAL-IP.md`](REAL-IP.md) |
| Situs jadi tidak bisa diakses setelah tambah host baru | Upstream mengarah ke IP publik server sendiri (hairpin NAT) padahal backend di container lain | Lihat solusi lengkap di [`REAL-IP.md`](REAL-IP.md) bagian "Hairpin NAT" |
| Klik tombol di dashboard tidak ada reaksi | JS error (jarang terjadi, biasanya sudah diperbaiki) | Buka Developer Console browser (F12), cek error merah, laporkan di [GitHub Issues](https://github.com/ashadebi/turboshield-gateway/issues) |

---

## 📚 Dokumentasi Lanjutan

- [`USAGE.md`](USAGE.md) — panduan pemakaian **setiap menu** di dashboard secara detail
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — cara kerja & desain sistem
- [`REAL-IP.md`](REAL-IP.md) — real IP klien, hairpin NAT, cross-network routing
- [`HARDENING.md`](HARDENING.md) — detail hardening Docker, timezone, logrotate
