# Real IP — Menangkap IP Publik Asli Klien

## Masalah

Secara default, log WAF sering menampilkan IP internal Docker (mis. `172.18.0.1`)
atau IP gateway NAT infra (mis. `10.1.1.133`), **bukan** IP publik asli penyerang.
Ini membuat threat log, rate-limit, dan blokir-IP tidak akurat.

Ada **dua penyebab berbeda**, dengan dua solusi:

---

## Penyebab 1 — Docker userland-proxy (paling umum)

Docker default memakai `docker-proxy` (userland proxy) yang mem-*masquerade* IP
sumber menjadi IP gateway bridge. Trafik yang lewat jalur ini kehilangan IP asli.

### Solusi: matikan userland-proxy

`/etc/docker/daemon.json`:
```json
{ "userland-proxy": false }
```
```bash
systemctl restart docker
```

Dengan ini Docker memakai **iptables DNAT murni** yang mempertahankan source IP.
Hasil: scanner/klien yang mengakses **langsung** ke IP server kini tercatat dengan
IP publik aslinya. ✅

**Verifikasi:**
```bash
# dari mesin lain, hit server, lalu:
docker exec ts-waf sh -c 'tail /var/log/turboshield/modsec_audit.log' \
  | python3 -c 'import sys,json;[print(json.loads(l)["transaction"]["client_ip"]) for l in sys.stdin if l.strip().startswith("{")]'
```

---

## Penyebab 2 — Ada NAT / Load Balancer / Proxy di depan server

Jika server berada di belakang **NAT infra**, **load balancer**, atau **CDN**,
IP sumber yang sampai ke server adalah IP perangkat tersebut, bukan klien asli.
Docker fix tidak menolong di sini karena IP sudah hilang **sebelum** mencapai server.

### Solusi: nginx `real_ip` + header X-Forwarded-For

Syaratnya: perangkat di depan **harus meneruskan** header `X-Forwarded-For`
(atau PROXY protocol). Lalu nginx dikonfigurasi mempercayai perangkat itu dan
mengambil IP asli dari header.

`waf/realip.conf` (sudah disertakan, di-mount ke `conf.d/00-realip.conf`):
```nginx
set_real_ip_from 10.1.1.0/24;      # subnet NAT/LB infra (TRUSTED)
set_real_ip_from 172.16.0.0/12;
set_real_ip_from 192.168.0.0/16;
real_ip_header X-Forwarded-For;
real_ip_recursive on;
```

> ⚠️ **Keamanan:** hanya percayai subnet infra yang kamu kendalikan.
> JANGAN `set_real_ip_from 0.0.0.0/0` — penyerang bisa memalsukan XFF.

**Konfigurasi sisi infra (contoh):**
- **HAProxy**: `option forwardfor` atau `send-proxy`
- **nginx LB**: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;`
- **Cloudflare**: aktif otomatis (`CF-Connecting-IP` / XFF) — tambahkan range CF ke trusted.

**Verifikasi:**
```bash
curl -H 'X-Forwarded-For: 203.0.113.55' http://localhost/  # dari subnet trusted
# client_ip di log harus 203.0.113.55
```

---

## Ringkasan

| Skenario | Solusi |
|---|---|
| Klien akses langsung ke IP server | Docker `userland-proxy:false` |
| Ada NAT/LB/CDN di depan | nginx `real_ip` + infra teruskan XFF |
| Keduanya | Terapkan dua-duanya (defense in depth) |
