# 📘 Panduan Pemakaian Dashboard TurboShield

Akses dashboard: `http://<ip-server>:8181`

Di pojok kanan atas setiap halaman ada:
- 🌐 **Pilihan bahasa**: 🇮🇩 Indonesia / 🇬🇧 English
- 🌙/☀️ **Tema**: Dark / Light

Menu di sidebar terbagi 3 kelompok: **Utama**, **Keamanan**, **Jaringan**, **Kecerdasan**.

---

## 📊 Dashboard (Utama)

Halaman pertama yang muncul setelah login. Menampilkan ringkasan real-time:
- **CPU, Memori, Disk** — pemakaian server saat ini
- **Ancaman Diblokir** — total serangan yang sudah ditolak WAF
- **Grafik serangan per kategori** (SQLi, XSS, RCE, LFI, dst)
- **System Health** — termasuk suhu CPU kalau server punya sensor
- **Live Threat Feed** — daftar serangan terbaru, auto-refresh tiap 10 detik

Tidak ada yang perlu dikonfigurasi di sini — halaman ini murni monitoring.

---

## 🛡️ WAF & Security (Keamanan)

Kontrol utama mesin WAF (ModSecurity + OWASP CRS).

- **Engine Mode** — pilih salah satu:
  - 🟢 **On** — blokir serangan sungguhan (mode produksi)
  - 🟡 **Detection Only** — hanya catat di log, tidak memblokir (cocok untuk
    masa percobaan awal supaya tahu ada false-positive atau tidak)
  - 🔴 **Off** — WAF nonaktif total (tidak disarankan kecuali sedang debug)
- **Anomaly Scoring Threshold** — angka skor OWASP CRS untuk memutuskan
  blokir. Makin **kecil** angkanya, makin **ketat** (lebih mudah blokir).
  Default: 5. Naikkan kalau terlalu banyak false-positive.
- **Custom Rules** — tempat menulis aturan ModSecurity SecLang sendiri
  (misal whitelist IP kantor, atau kecualikan satu rule tertentu yang
  bikin false-positive di aplikasimu).

Setelah ubah apa pun di halaman ini, klik **💾 Simpan & Reload WAF** — perubahan
langsung aktif tanpa downtime (config divalidasi dulu sebelum di-apply).

---

## 🚨 Threat Log (Keamanan)

Daftar lengkap semua serangan yang terdeteksi WAF, lengkap dengan:
**Waktu · IP asli penyerang · Method HTTP · URI yang diserang · Kategori
serangan (SQLi/XSS/RCE/LFI/dst) · Pesan rule yang memicu**.

Gunakan halaman ini untuk:
- Investigasi kalau curiga ada serangan yang lolos/gagal diblokir
- Cek apakah suatu IP layak ditambahkan ke block-list manual (Custom Rules)
- Verifikasi Rate Limiting / Bot Protection benar-benar menangkap traffic mencurigakan

---

## ⏱️ Rate Limiting (Keamanan)

Membatasi **jumlah request** yang boleh masuk per satuan waktu, berdasarkan
siapa/apa yang mengirim request. Berguna untuk mencegah brute-force login,
membatasi pemakaian API per klien, dsb.

### Cara menambah rule
1. Klik **➕ Tambah Rule**
2. Isi:
   - **Proxy Host** — pilih domain/host yang mau dibatasi (host harus sudah
     ada dulu di menu Proxy & Routing)
   - **Path Prefix** — bagian URL yang mau dibatasi, contoh `/login`, `/api`,
     atau `/` kalau mau berlaku untuk seluruh situs
   - **Scope** — dasar penghitungan:
     - **Per-IP** — dihitung berdasarkan alamat IP pengunjung (paling umum)
     - **Per-Header** — dihitung berdasarkan isi header HTTP tertentu
     - **Per-Cookie** — dihitung berdasarkan nilai cookie tertentu (misal session ID)
     - **Per-API-Key** — dihitung berdasarkan API key (dari header atau query param)
   - **Rate** — angka batas, contoh `5` per `menit`
   - **Burst** (opsional) — toleransi lonjakan sesaat sebelum ditolak (default
     otomatis 2x rate kalau dikosongkan)
   - **Nodelay** — kalau dicentang, request yang melebihi burst langsung
     ditolak (429). Kalau tidak, request akan diantre sebentar.
3. Klik **💾 Simpan & Reload WAF**

### Contoh pemakaian umum
| Skenario | Path | Scope | Rate |
|---|---|---|---|
| Lindungi halaman login dari brute-force | `/login` | Per-IP | 5 / menit |
| Batasi pemakaian API per klien | `/api` | Per-API-Key | 100 / detik |
| Homepage bebas diakses | *(jangan buat rule)* | — | tak terbatas |

Ketika limit terlampaui, pengunjung akan menerima **HTTP 429 Too Many Requests**.

> Rule ini berjalan di level nginx (`limit_req`) — nyata dan teruji, bukan simulasi.

---

## 🤖 Bot Protection (Keamanan)

Mengenali & memperlakukan bot berdasarkan **User-Agent** yang mereka kirim,
dibagi 3 kategori (dievaluasi berurutan: **Allow** dulu, lalu **Block**, lalu **Challenge**):

### ✅ Allow-list — bot resmi, tidak diganggu
Sudah tersedia default: **Google, Bing, Apple, Facebook, Telegram, Slack,
Discord**. Tinggal aktif/nonaktifkan lewat toggle di masing-masing baris.

> ⚠️ **Catatan jujur:** pengenalan ini hanya berdasarkan **teks User-Agent**,
> yang secara teknis bisa dipalsukan siapa saja. Fitur ini cukup untuk tujuan
> "supaya Googlebot/crawler resmi tidak keliru diblokir WAF", tapi **bukan**
> jaminan keamanan berbasis IP asli Google.

### 🚫 Block-list — tool scanner/exploit, langsung ditolak
Default aktif: **sqlmap, nikto, nmap, wpscan, dirbuster, masscan, havij,
acunetix, nessus**. Request dari User-Agent ini langsung dapat **403**.

### ⚠️ Challenge-list — bot/tool netral (bukan jahat, bukan resmi juga)
Default aktif: **curl, python-requests, go-http-client, scraper generik,
unknown bot generik**. Ada 2 mode (atur di bagian atas halaman):
- **📝 Log Only** (default) — request tetap diteruskan, tapi tercatat di
  Threat Log supaya kamu tahu ada aktivitas non-browser
- **🚫 Block** — ditolak 403 sepenuhnya (lebih ketat, tapi risiko
  memblokir tool otomatis yang sah, misal monitoring internalmu sendiri)

> ⚠️ **Catatan jujur:** ini bukan CAPTCHA sungguhan (infra JS-challenge belum
> ada di versi ini) — istilah "Challenge" di sini berarti "kategori
> netral yang perlu perhatian", bukan tantangan interaktif ke pengunjung.

### ➕ Tambah Kategori Custom
Kalau ada bot lain yang mau kamu atur (misal YandexBot, atau tool internal
perusahaanmu), scroll ke bawah halaman:
1. Pilih kategori (Allow/Challenge/Block)
2. Isi **Key** (identifier singkat, huruf/angka/underscore saja)
3. Isi **Label** (nama yang ditampilkan)
4. Isi **User-Agent pattern** — bisa lebih dari satu, pisahkan dengan koma
5. Klik **➕ Tambah & Reload WAF**

---

## 🌐 Proxy & Routing (Jaringan)

Mengatur domain/aplikasi apa saja yang dilindungi WAF — mirip fungsinya
dengan Nginx Proxy Manager.

### Tambah Host
1. Klik **➕ Tambah Host**
2. Isi:
   - **Domain** — nama domain aplikasimu
   - **Upstream** — alamat backend asli (`host:port`, atau nama container
     Docker kalau backend juga jalan di Docker network yang sama)
   - **Scheme** — `http` atau `https` (skema ke backend, bukan ke pengunjung)
   - **Proteksi WAF** — `On` / `Detection Only` / `Off` (per-host, override global)
   - **WebSocket** — centang kalau aplikasimu pakai WebSocket
   - **Block Exploits** — blokir otomatis pola path mencurigakan umum
     (`.git`, `.env`, `/wp-admin`, dst) di layer nginx sebelum sampai WAF
   - **Force SSL** — paksa redirect HTTP → HTTPS
   - **Custom Nginx Config** — baris config nginx tambahan kalau perlu
     penyesuaian khusus
3. Klik **💾 Simpan & Reload**

### Edit / Hapus Host
Klik ✏️ untuk edit, 🗑️ untuk hapus di tabel host. Menghapus host otomatis
membersihkan rate-limit rule yang menempel padanya.

### 🔒 SSL per Host
Klik tombol **🔒 SSL** di baris host:
- **Let's Encrypt** — otomatis & gratis, syaratnya domain sudah mengarah
  (DNS A record) ke IP server ini, dan port 80 terbuka untuk verifikasi ACME
- **Upload Sertifikat Sendiri** — tempel isi file sertifikat (`fullchain.pem`)
  dan private key (`privkey.pem`) kalau kamu sudah punya sertifikat dari
  provider lain

> ⚠️ Kalau backend aplikasimu berjalan di **container Docker lain** (bukan di
> host langsung), jangan arahkan upstream ke IP publik server + port yang
> di-expose — ini bisa gagal karena *hairpin NAT*. Arahkan ke **nama container
> + port internal** sebagai gantinya. Detail lengkap: [`REAL-IP.md`](REAL-IP.md).

---

## 🤖 AI & Automation (Kecerdasan)

Sambungkan TurboShield ke layanan AI untuk analisis log otomatis (Log Intelligence).

- **Provider**: Gemini, OpenAI, Claude, OpenRouter, Ollama (self-host), atau
  Custom (endpoint kompatibel OpenAI API)
- Isi API key / model / endpoint sesuai provider pilihanmu
- Klik **🔌 Uji Koneksi** untuk memastikan kredensial valid sebelum disimpan
- **n8n Webhook** — isi URL webhook n8n kalau mau memicu automasi/alert
  eksternal (misal ke Slack, Telegram, atau agent lain) saat ada serangan

---

## 📡 Integrasi & Monitoring (Kecerdasan)

- **📊 LibreNMS** — isi URL server LibreNMS + X-Auth-Token untuk menarik data
  monitoring jaringan. Klik **Uji Koneksi** untuk memverifikasi (akan
  menampilkan jumlah device yang terbaca)
- **📱 Telegram Bot**:
  1. Buat bot baru via [@BotFather](https://t.me/BotFather) di Telegram,
     salin Bot Token-nya
  2. Isi Bot Token + Chat ID tujuan notifikasi
  3. Centang **"Kirim password admin ke Telegram saat setup"** kalau mau
     password admin otomatis terkirim ke Telegram (berguna kalau kamu setup
     dashboard dari jarak jauh dan takut lupa screenshot password)
  4. Klik **🔌 Uji Koneksi** — akan mengirim pesan tes ke Chat ID tersebut
- **🔗 Wazuh SIEM** — integrasi korelasi event SIEM (menyusul di versi mendatang)

---

## 💡 Tips Keamanan Umum

- **Batasi akses port `:8181`** — dashboard ini panel admin, sebaiknya tidak
  diekspos ke internet umum. Gunakan firewall, VPN, atau proxy dengan auth
  tambahan untuk membatasinya hanya ke IP kamu/tim.
- **Rutin cek Threat Log** — sesuaikan Anomaly Threshold kalau ada banyak
  false-positive dari aplikasi sahmu sendiri.
- **Untuk pengecualian spesifik**, tambahkan aturan `SecRuleRemoveById` di
  **Custom Rules** (menu WAF & Security) daripada menurunkan proteksi secara
  global (misal set Engine Mode ke Off).
- **Mulai dari Detection Only** kalau baru pertama kali pasang WAF di
  aplikasi produksi — pantau Threat Log dulu beberapa hari sebelum
  memindahkan ke mode Blocking penuh.
