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

## Tips Keamanan
- Batasi akses `:8181` (firewall/VPN).
- Rutin cek Threat Log & sesuaikan threshold bila ada false positive.
- Untuk false positive tertentu, tambahkan pengecualian di **Custom Rules**
  (`SecRuleRemoveById`) daripada menurunkan proteksi global.
