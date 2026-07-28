# Real IP & Cross-Network Routing — Menangkap IP Publik Asli & Menghindari Hairpin NAT

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

## Penyebab 3 — Hairpin NAT: WAF proxy_pass ke IP publik server sendiri (koneksi gagal total, bukan cuma IP salah)

Kasus ini beda dari #1/#2: bukan IP yang tercatat salah, tapi **koneksi WAF → backend gagal total** (situs down/timeout). Terjadi ketika kamu mengarahkan upstream proxy host ke **IP publik server itu sendiri** (mis. `1.2.3.4:82`) padahal backend-nya adalah container Docker lain di server yang sama.

**Kenapa gagal:** container `ts-waf` mencoba konek ke IP publik host dari *dalam* network Docker-nya sendiri. Ini disebut *hairpin NAT* / *NAT loopback* — paket harus keluar lewat interface publik lalu masuk lagi via port-forward, dan banyak setup Docker/iptables **tidak mendukung rute pulang-pergi ini**. Hasilnya: `curl` dari dalam container `ts-waf` ke `<ip-publik>:<port>` return `000` (connection refused/timeout), walau dari luar server port itu bisa diakses normal.

**Gejala:** config nginx valid, cert ada, `ts-waf` healthy — tapi situs tidak bisa diakses dari luar sama sekali (bukan 403 WAF, tapi gagal connect/timeout di reverse proxy).

### Solusi: proxy ke nama container di network Docker yang sama (bukan IP publik)

1. Sambungkan `ts-waf` ke network Docker tempat backend berada:
   ```bash
   docker network connect <network_backend> ts-waf
   ```
2. Set **upstream** proxy host ke **nama container + port internal**, bukan IP publik:
   ```
   upstream: nama-container-backend:80      # BENAR — antar-container langsung
   upstream: 103.x.x.x:82                    # SALAH — hairpin NAT, sering gagal
   ```
3. **Permanenkan** (`docker network connect` ad-hoc hilang saat container di-recreate) — edit `docker-compose.yml`:
   ```yaml
   networks:
     tsnet:
       driver: bridge
     dev_default:          # nama network tempat backend berada
       external: true
   services:
     waf:
       networks: [tsnet, dev_default]
   ```

**Verifikasi:**
```bash
# harus 200, bukan 000
docker exec ts-waf curl -s -o /dev/null -w "%{http_code}\n" http://nama-container-backend:80/
```

> Untuk backend aplikasi (bukan API), pertimbangkan set **WAF mode = DetectionOnly**
> per-host dulu (menu Proxy → Edit → Proteksi WAF) untuk menghindari false-positive
> pada form kompleks, sebelum pindah ke Blocking penuh.

---

## Ringkasan

| Skenario | Solusi |
|---|---|
| Klien akses langsung ke IP server | Docker `userland-proxy:false` |
| Ada NAT/LB/CDN di depan | nginx `real_ip` + infra teruskan XFF |
| Backend di container lain, situs down total (bukan cuma IP salah) | Hubungkan network + upstream via nama container, bukan IP publik |
| Semua sekaligus | Terapkan ketiganya (defense in depth) |
