#!/usr/bin/env python3
"""TurboShield — Rate Limiting (dipakai app.py + proxy_ai.py).
Model: daftar rule per proxy-host, tiap rule = {path_prefix, scope, key_name,
rate, unit, burst, nodelay}. Scope yg didukung SEKARANG (native nginx, tanpa
modul tambahan): ip, header, cookie, apikey (header atau query param).
Per-ASN & Per-Country DIBERI TEMPAT di skema tapi baru aktif di modul Geo
Blocking (butuh data GeoIP terpisah) — lihat catatan di api_rate_limits().
"""
import os, json, re, uuid
from pathlib import Path

DATA_DIR   = Path(os.environ.get("TS_DATA_DIR", "/app/data"))
RL_DB      = DATA_DIR / "rate_limits.json"
ZONES_FILE = Path("/waf/ratelimit-zones.conf")   # mount -> conf.d/00-aaa-ratelimit-zones.conf

SCOPES = ("ip", "header", "cookie", "apikey")

def load_rules():
    if RL_DB.exists():
        try: return json.loads(RL_DB.read_text())
        except Exception: return []
    return []

def save_rules(rules):
    RL_DB.write_text(json.dumps(rules, indent=2)); os.chmod(RL_DB, 0o600)

def rules_for_host(domain):
    return [r for r in load_rules() if r.get("host") == domain and r.get("enabled", True)]

def _zone_name(rule):
    return "tsrl_" + re.sub(r"[^a-z0-9]", "_", rule["id"].lower())[:24]

def _norm_ident(name):
    """Nama header/cookie -> identifier valid nginx var (huruf/angka/underscore)."""
    return re.sub(r"[^a-zA-Z0-9]", "_", name.strip()).lower()

def _zone_key_expr(rule):
    scope = rule.get("scope", "ip")
    if scope == "ip":
        return "$binary_remote_addr"
    if scope == "header":
        return "$http_" + _norm_ident(rule.get("key_name", ""))
    if scope == "cookie":
        return "$cookie_" + _norm_ident(rule.get("key_name", ""))
    if scope == "apikey":
        src = rule.get("key_source", "header")
        if src == "query":
            return "$arg_" + _norm_ident(rule.get("key_name", "api_key"))
        return "$http_" + _norm_ident(rule.get("key_name", "x_api_key"))
    return "$binary_remote_addr"

def validate_rule(rule):
    if not rule.get("host"): return False, "Host wajib dipilih."
    if not rule.get("path_prefix", "").startswith("/"): return False, "Path harus diawali '/'."
    if rule.get("scope") not in SCOPES: return False, f"Scope tidak dikenal: {rule.get('scope')}"
    if rule.get("scope") in ("header", "cookie", "apikey") and not rule.get("key_name", "").strip():
        return False, "Nama header/cookie/API-key wajib diisi untuk scope ini."
    try:
        rate = int(rule.get("rate", 0))
        if rate <= 0: raise ValueError
    except Exception:
        return False, "Rate harus angka > 0."
    if rule.get("unit") not in ("s", "m"):
        return False, "Unit harus 's' (detik) atau 'm' (menit)."
    return True, "ok"

def regenerate_zones_file():
    """Tulis SEMUA limit_req_zone (http-level) dari semua rule aktif, sekali jalan.
    File ini di-mount di conf.d/00-aaa-ratelimit-zones.conf — HARUS dimuat
    sebelum proxy-hosts (nama file diawali '00-aaa' agar urut alfabetis paling awal)."""
    lines = ["# TurboShield — rate-limit zones (auto-generated, jangan edit manual)\n"]
    for r in load_rules():
        if not r.get("enabled", True):
            continue
        zone = _zone_name(r)
        key = _zone_key_expr(r)
        rate = f'{int(r["rate"])}r/{r["unit"]}'
        lines.append(f'limit_req_zone {key} zone={zone}:10m rate={rate};\n')
    ZONES_FILE.write_text("".join(lines))
    try: os.chmod(ZONES_FILE, 0o644)
    except Exception: pass

def render_locations_for_host(domain, ws_lines, up_host, exploit_lines_inline=""):
    """Generate location-block nginx utk tiap rule aktif host ini (dipakai
    proxy_ai.render_host_conf, disisipkan SEBELUM catch-all location '/').
    Path lain yg tak match rule manapun otomatis 'unlimited' (fallback location /).
    """
    out = []
    for r in rules_for_host(domain):
        zone = _zone_name(r)
        burst = int(r.get("burst", max(1, int(r["rate"]) * 2)))
        nodelay = " nodelay" if r.get("nodelay", True) else ""
        path = r["path_prefix"]
        out.append(
            f'    location {path} {{\n'
            f'        limit_req zone={zone} burst={burst}{nodelay};\n'
            f'        limit_req_status 429;\n'
            f'        client_max_body_size 0;\n'
            f'        proxy_pass {up_host};\n'
            f'        proxy_http_version 1.1;\n'
            f'        proxy_set_header Host $host;\n'
            f'        proxy_set_header X-Real-IP $remote_addr;\n'
            f'        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n'
            f'        proxy_set_header X-Forwarded-Proto $scheme;\n'
            f'{ws_lines}'
            f'    }}\n'
        )
    return "".join(out)
