# Arsitektur TurboShield Gateway

## Diagram Komponen

```
                          Internet (klien / penyerang)
                                     │
                                     │  HTTP :80 / HTTPS :443
                                     ▼
        ┌────────────────────────────────────────────────┐
        │  ts-waf   (owasp/modsecurity-crs:nginx-alpine)   │
        │  ┌──────────────────────────────────────────┐    │
        │  │ nginx  ── real_ip (00-realip.conf)        │    │
        │  │        ── ModSecurity v3 (modsecurity on) │    │
        │  │        ── OWASP CRS (~930 rules)           │    │
        │  │        ── managed rules (engine/threshold) │    │
        │  │        ── custom rules (rate-limit, dll)   │    │
        │  │        ── proxy-hosts/*.conf (dinamis)     │    │
        │  └──────────────────────────────────────────┘    │
        └───────┬───────────────────────────┬──────────────┘
                │ proxy_pass                 │ proxy_pass
                ▼                            ▼
        ┌──────────────┐            ┌──────────────────┐
        │ ts-testapp   │            │ upstream backend │
        │ (demo :8080) │            │ (app produksi)   │
        └──────────────┘            └──────────────────┘

        ┌───────────────────────────────────────────────┐
        │ ts-dashboard  (FastAPI :8181)                  │
        │  - auth (wizard, login, session)               │
        │  - baca audit log WAF (/waf/logs)              │
        │  - tulis managed/custom/proxy rules (/waf)     │
        │  - reload WAF: docker exec ts-waf nginx -s ... │
        │    via /var/run/docker.sock                    │
        └───────────────────────────────────────────────┘
```

## Alur Data

### Request klien
1. Klien → nginx (`:80/:443`).
2. `real_ip` menormalkan IP asli (dari XFF bila via proxy trusted).
3. ModSecurity mengevaluasi request terhadap OWASP CRS + rules kustom.
4. Skor anomali ≥ threshold → **403** (blocking) / dicatat saja (detection).
5. Lolos → `proxy_pass` ke upstream sesuai `server_name`.

### Kontrol dari dashboard
1. Admin ubah setting di UI (`:8181`).
2. FastAPI menulis file config ke volume bersama `./waf` (chmod 644).
3. FastAPI menjalankan `docker exec ts-waf nginx -t` (validasi) lalu `-s reload`.
4. Perubahan aktif tanpa downtime; config invalid otomatis rollback.

## Volume & File Kunci

| Path host | Mount di container | Fungsi |
|---|---|---|
| `waf/rules/aaa-turboshield-managed.conf` | CRS rules | engine mode + anomaly threshold |
| `waf/rules/turboshield-custom.conf` | CRS rules | rate-limit, whitelist, block UA |
| `waf/realip.conf` | `conf.d/00-realip.conf` | pemulihan IP asli |
| `waf/proxy-hosts/*.conf` | `conf.d/proxy-hosts/` | server block per host (dinamis) |
| `waf/certs/` | `/etc/nginx/certs` | sertifikat SSL per host |
| `waf/logs/modsec_audit.log` | `/var/log/turboshield` | audit log (dibaca dashboard) |
| `dashboard/data/` | `/app/data` | admin.json, sessions, config (JANGAN commit) |

## Keputusan Desain

- **Kenapa image OWASP resmi?** Terawat, CRS + ModSecurity ter-bundle & teruji;
  lebih stabil daripada compile manual `lua-resty-coraza`.
- **Kenapa ModSecurity, bukan Coraza murni?** Di nginx, ModSecurity v3 paling matang.
  Coraza reimplementasi ModSecurity dalam Go — **bahasa rule (SecLang) & OWASP CRS
  identik**, jadi fitur untuk pengguna sama. Disebut "Coraza-compatible".
- **Kenapa reload via docker.sock?** Dashboard di container terpisah perlu memicu
  reload nginx di container WAF. Alternatif produksi: docker-socket-proxy (lebih aman).
- **Kenapa file-based config?** Transparan, mudah di-review/backup/git, dan nginx
  reload murah. State minimal di JSON.
