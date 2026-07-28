# Panduan Penggunaan Dashboard

Akses: `http://<server-ip>:8181`. Ganti bahasa (ID/EN) & tema (Dark/Light) di pojok kanan atas.

## 📊 Dashboard
Ringkasan real-time: CPU, Memori, Disk, total ancaman diblokir, grafik serangan per
kategori, System Health (termasuk suhu bila sensor tersedia), dan live threat feed
(auto-refresh tiap 10 detik).

## 🛡️ WAF & Security
- **Engine Mode**: `On` (blokir), `Detection Only` (catat saja), `Off` (nonaktif).
- **Anomaly Threshold**: skor OWASP CRS untuk memblokir (makin kecil makin ketat, default 5).
- **Custom Rules**: aturan ModSecurity SecLang (whitelist IP, blokir User-Agent, rate-limit).
- Klik **Simpan & Reload** → perubahan aktif langsung.

## 🚨 Threat Log
Daftar lengkap serangan yang terdeteksi: waktu, IP asli, method, URI, kategori
(SQLi/XSS/RCE/LFI), dan pesan rule yang memicu.

## 🌐 Proxy & Routing
- **Tambah Host**: domain, upstream (`host:port`), scheme, **Proteksi WAF per-host**
  (On/Detection/Off), WebSocket, Block Exploits, Force SSL, custom nginx config.
- **Edit / Hapus** host dari tabel.
- **🔒 SSL**: per host — Let's Encrypt otomatis atau upload cert+key sendiri.
- Setiap host baru otomatis dilindungi WAF (kecuali diset Off).

## 🤖 AI & Automation
- **Provider**: Gemini, OpenAI, Claude, OpenRouter, Ollama, Custom (OpenAI-compatible).
- Isi API key / model / endpoint sesuai provider, klik **Uji Koneksi** untuk validasi.
- **n8n webhook**: untuk memicu alert otomatis (mis. ke OpenClaw) saat serangan.

## 📡 Integrasi & Monitoring
- **LibreNMS**: URL + X-Auth-Token → tarik metrik perangkat jaringan. Uji Koneksi
  membaca jumlah device.
- **Telegram Bot**: bot token + chat ID. Aktifkan "kirim password admin saat setup"
  agar kredensial admin dikirim ke Telegram otomatis. Uji Koneksi mengirim pesan tes.
- **Wazuh**: (menyusul).

## ⏱️ Rate Limiting
- **Tambah Rule**: pilih proxy host, path prefix (`/login`, `/api`, atau `/` untuk semua path), scope (Per-IP/Header/Cookie/API-Key), rate (angka per detik/menit), burst (opsional, default 2x rate), nodelay (tolak langsung vs antre).
- Contoh: Login → `/login`, Per-IP, 5/menit. API → `/api`, Per-API-Key, 100/detik. Homepage → jangan buat rule (unlimited by default).
- Native nginx `limit_req_zone` — real, teruji return **429** saat limit terlampaui.
- Hapus host di Proxy Manager otomatis membersihkan rule rate-limit yang menempel di host itu.

## 🤖 Bot Protection
3 kategori via User-Agent (evaluasi berurutan: Allow → Block → Challenge):
- **✅ Allow-list**: Google/Bing/Apple/Facebook/Telegram/Slack/Discord — dilewati tanpa gangguan (skip rule di bawahnya). ⚠️ Verifikasi hanya via string User-Agent (bisa dipalsukan) — cukup untuk "jangan ganggu SEO crawler", bukan untuk security boundary IP.
- **🚫 Block-list**: sqlmap/nikto/nmap/wpscan/dirbuster/masscan/havij/acunetix/nessus — langsung **403**.
- **⚠️ Challenge-list**: curl/python-requests/go-http-client/scraper generik/unknown bot — **tanpa infra CAPTCHA** (belum ada), jadi mode default **Log Only** (tercatat di Threat Log, tetap diteruskan/fail-open). Bisa diubah ke mode **Block** (403 keras, risiko false-positive lebih tinggi).
- **Tambah Kategori Custom**: isi key, label, dan daftar User-Agent pattern (pisah koma) untuk bot lain (mis. YandexBot).
- Toggle per-kategori on/off langsung reload WAF.

## Tips Keamanan
- Batasi akses `:8181` (firewall/VPN).
- Rutin cek Threat Log & sesuaikan threshold bila ada false positive.
- Untuk false positive tertentu, tambahkan pengecualian di **Custom Rules**
  (`SecRuleRemoveById`) daripada menurunkan proteksi global.
