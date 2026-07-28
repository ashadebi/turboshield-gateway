# 🛡️🐉 TurboShield Gateway

<img src="assets/logo-256.png" alt="TurboShield Gateway logo — shield with a friendly dragon face sticking its tongue out" width="120" align="right">

**WAF Reverse Proxy + Management Dashboard** — nginx + ModSecurity v3 + OWASP Core Rule Set, dengan panel administrasi berbasis web (FastAPI), manajemen proxy host ala Nginx Proxy Manager, SSL otomatis (Let's Encrypt) / upload sendiri, integrasi AI & monitoring, serta hardening Docker lengkap.

![status](https://img.shields.io/badge/status-active-brightgreen) ![waf](https://img.shields.io/badge/WAF-ModSecurity%20v3%20%2B%20OWASP%20CRS-blue) ![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## ✨ Fitur

| Modul | Kemampuan |
|---|---|
| **WAF Engine** | nginx + ModSecurity v3 + OWASP CRS (SQLi, XSS, RCE, LFI, path traversal, scanner). Coraza-compatible (SecLang/CRS sama). |
| **Dashboard** | Panel web port **8181**: setup wizard, login (session), health real-time, live threat feed, grafik. |
| **WAF Control** | Toggle engine mode **On / Detection Only / Off**, anomaly threshold, editor custom rules — reload live. |
| **Rate Limiting** | Per-IP/Header/Cookie/API-Key, per-path per-host, native nginx `limit_req` — real, bukan simulasi. |
| **Bot Protection** | Allow-list (Google/Bing/Apple/FB/Telegram/Slack/Discord), Block-list (sqlmap/nikto/nmap/dst), Challenge-list (curl/python-requests/scraper) dgn mode Log/Block. |
| **Proxy Manager** | CRUD proxy host (domain, upstream, scheme, WebSocket, block-exploits), **toggle WAF per-host**, custom nginx config. |
| **SSL Manager** | Let's Encrypt otomatis (certbot) **atau** upload sertifikat sendiri, per-host. |
| **AI Integration** | Gemini / OpenAI / Claude / OpenRouter / Ollama / Custom + n8n webhook. Test koneksi. |
| **Monitoring** | LibreNMS (X-Auth-Token), Telegram bot (alert + kirim password admin saat setup). |
| **i18n & Theme** | Bahasa **Indonesia / English**, tema **Dark / Light**. |
| **Real IP** | IP publik asli klien tercatat di log (Docker `userland-proxy:false` + nginx `real_ip`). |
| **Hardening** | Script instalasi Docker + hardening CIS-inspired (lihat `scripts/`). |

---

## 🚀 Instalasi Cepat

```bash
# 1. Clone ke direktori pilihanmu — bebas, tidak harus /opt (bisa /srv, ~/, dll.)
git clone <repo-url> turboshield && cd turboshield

# 2. Install Docker + hardening (Debian/Ubuntu)
sudo bash scripts/install-docker-hardened.sh

# 3. Deploy stack (semua path host auto-detect dari direktori ini)
docker compose up -d

# 4. Buka dashboard & setup admin
#    http://<server-ip>:8181  → isi email → password digenerate
```

Detail lengkap: [`docs/INSTALL.md`](docs/INSTALL.md).

---

## 🏗️ Arsitektur

```
                  Internet
                     │  :80 / :443
          ┌──────────▼──────────┐
          │   ts-waf (nginx +   │   ← WAF: ModSecurity v3 + OWASP CRS
          │   ModSecurity v3)   │   ← reverse proxy + SSL (Let's Encrypt)
          └──────┬───────┬──────┘
                 │       │ proxy_pass
        ┌────────▼──┐  ┌─▼─────────────┐
        │ ts-testapp│  │ upstream lain │  ← backend yg dilindungi
        └───────────┘  └───────────────┘
          ┌─────────────────────┐
          │ ts-dashboard (:8181)│   ← FastAPI: kontrol WAF, proxy, SSL,
          │   FastAPI + docker  │      AI, monitoring. Reload WAF via
          │   socket            │      docker exec nginx -s reload.
          └─────────────────────┘
```

Detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## 📚 Dokumentasi

- [`docs/INSTALL.md`](docs/INSTALL.md) — instalasi lengkap langkah demi langkah
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — desain sistem & komponen
- [`docs/REAL-IP.md`](docs/REAL-IP.md) — cara IP publik asli tercatat (Docker + nginx) + fix hairpin NAT saat proxy ke backend di container lain
- [`docs/HARDENING.md`](docs/HARDENING.md) — hardening Docker & host
- [`docs/USAGE.md`](docs/USAGE.md) — panduan pakai dashboard per menu

---

## 📂 Struktur Repo

```
turboshield/
├── docker-compose.yml          # stack: waf + dashboard + testapp
├── dashboard/                  # FastAPI app (backend + static UI)
│   ├── app.py                  # API: auth, WAF, proxy, SSL, AI, monitoring
│   ├── proxy_ai.py             # proxy host generator + SSL + integrasi
│   └── static/                 # setup.html, login.html, dashboard.html
├── waf/                        # config WAF (rules, realip, proxy-hosts)
├── scripts/                    # install-docker-hardened.sh (+ tweak)
└── docs/                       # dokumentasi
```

---

## ⚠️ Catatan Keamanan

- Ganti semua kredensial default & jangan commit `dashboard/data/` (sudah di `.gitignore`).
- Dashboard `:8181` sebaiknya dibatasi (firewall / VPN / proxy ber-auth) — jangan diekspos publik tanpa proteksi.
- Deploy di lingkungan testing dulu sebelum produksi.

## 📄 Lisensi

MIT — lihat [`LICENSE`](LICENSE).

*Dibuat oleh Vio (AI Agent) untuk kawan Agoes.* 🛡️
