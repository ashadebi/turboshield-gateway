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


## 🧩 Security Engines

Recommended mode:
- **Primary WAF**: Coraza / ModSecurity CRS.
- **Extra Protection**: CrowdSec.
- **open-appsec**: skipped for now.

Dashboard controls:
- **Status**: refresh CrowdSec/container/bouncer status.
- **Mode**: `Detect only` or `Block`. Blocking requires firewall bouncer.
- **Restart CrowdSec/Bouncer**: restarts `ts-crowdsec` and `crowdsec-firewall-bouncer`.

CrowdSec reads `waf/logs/modsec_audit.log` and nginx logs, then creates decisions. Firewall bouncer enforces decisions with iptables.

## 🔀 Streams

Streams are TCP/UDP forwarding rules, similar to Nginx Proxy Manager Streams. Use them for raw protocols such as RTMP/SRT/TCP/UDP:
- listen port
- protocol: TCP or UDP
- upstream host
- upstream port
- enable/disable

Streams do **not** use ModSecurity/WAF because they are not HTTP traffic.

## 📺 TV Portal / HLS-DASH Proxy

Public no-auth TV portal served by dashboard for a host such as `tv.teelee.my.id`.

Features:
- lightweight HTML player
- `hls.js` for HLS `.m3u8`
- `dash.js` for DASH `.mpd`
- server-side HLS playlist rewrite
- nested playlist and relative segment proxy
- channel API:
  - `GET /api/tv/channels`
  - `GET /api/tv/playlist/{id}`
  - `GET /api/tv/proxy/{id}?u=...`

HLS/DASH uses HTTP, so it belongs in the HTTP proxy layer, not Streams.
