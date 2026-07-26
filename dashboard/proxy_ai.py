#!/usr/bin/env python3
"""TurboShield — Proxy Manager + SSL + AI Integration (dipakai app.py).
Fungsi:
- CRUD proxy host (domain, upstream, scheme, websocket, block-common-exploits, custom nginx config)
- Generator server-block nginx (HTTP + optional HTTPS) yang ditulis ke /waf/proxy-hosts
- SSL: request Let's Encrypt (certbot webroot) ATAU upload cert+key sendiri
- AI integration config (provider, api_key, model, endpoint, n8n webhook) + test koneksi
"""
import os, json, re, subprocess, ssl, socket, urllib.request
from pathlib import Path
from datetime import datetime, timezone

DATA_DIR    = Path(os.environ.get("TS_DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
HOSTS_DB    = DATA_DIR / "proxy_hosts.json"
AI_DB       = DATA_DIR / "ai_config.json"
# path DI DALAM container dashboard (mount ./waf -> /waf)
PROXY_DIR   = Path("/waf/proxy-hosts")
CERTS_DIR   = Path("/waf/certs")
ACME_DIR    = Path("/waf/acme")
WAF_CT      = os.environ.get("TS_WAF_CONTAINER", "ts-waf")
for d in (PROXY_DIR, CERTS_DIR, ACME_DIR):
    try: d.mkdir(parents=True, exist_ok=True)
    except Exception: pass

# paths DI DALAM container WAF (untuk ditulis di config nginx)
WAF_CERTS = "/etc/nginx/certs"
WAF_ACME  = "/var/www/acme"

def _slug(domain):
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", domain.strip().lower())

def load_hosts():
    if HOSTS_DB.exists():
        try: return json.loads(HOSTS_DB.read_text())
        except Exception: return []
    return []

def save_hosts(h):
    HOSTS_DB.write_text(json.dumps(h, indent=2)); os.chmod(HOSTS_DB, 0o600)

# ---------------- nginx server-block generator ----------------
def render_host_conf(h):
    dom = h["domain"]; slug = _slug(dom)
    scheme = h.get("scheme", "http"); up = h["upstream"]
    up_host = f"{scheme}://{up}"
    ws = h.get("websocket", True)
    block_exploits = h.get("block_exploits", True)
    custom = h.get("custom_config", "") or ""
    ssl_on = h.get("ssl", {}).get("enabled", False)
    force_ssl = h.get("ssl", {}).get("force", False) and ssl_on
    waf_mode = h.get("waf_mode", "On")   # On | DetectionOnly | Off

    # Per-host WAF directive (override global). ModSecurity nginx mendukung
    # 'modsecurity on/off' di server context; mode diatur via SecRuleEngine di rule.
    if waf_mode == "Off":
        waf_lines = "    modsecurity off;\n"
    else:
        waf_lines = "    modsecurity on;\n    modsecurity_rules 'SecRuleEngine %s';\n" % (
            "DetectionOnly" if waf_mode == "DetectionOnly" else "On")

    ws_lines = ""
    if ws:
        ws_lines = ("        proxy_set_header Upgrade $http_upgrade;\n"
                    "        proxy_set_header Connection $connection_upgrade;\n")
    exploit_lines = ""
    if block_exploits:
        exploit_lines = ('    if ($request_uri ~* "(\\.\\./|\\.git|\\.env|/wp-admin|/xmlrpc)") { return 403; }\n')

    common_loc = (
        "    location / {\n"
        "        client_max_body_size 0;\n"
        f"        proxy_pass {up_host};\n"
        "        proxy_http_version 1.1;\n"
        "        proxy_set_header Host $host;\n"
        "        proxy_set_header X-Real-IP $remote_addr;\n"
        "        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
        "        proxy_set_header X-Forwarded-Proto $scheme;\n"
        f"{ws_lines}"
        "    }\n"
        "    include includes/location_common.conf;\n"
    )

    # ACME challenge selalu tersedia di :8080 untuk Let's Encrypt
    acme_loc = (
        "    location /.well-known/acme-challenge/ {\n"
        f"        root {WAF_ACME};\n"
        "    }\n"
    )

    conf = f"# TurboShield managed host: {dom}\n"
    # ---- HTTP server (8080) ----
    conf += "server {\n"
    conf += "    listen 8080;\n"
    conf += f"    server_name {dom};\n"
    conf += waf_lines
    conf += acme_loc
    conf += exploit_lines
    if force_ssl:
        conf += "    location / { return 301 https://$host$request_uri; }\n"
    else:
        conf += common_loc
    if custom.strip():
        conf += "    # --- custom config ---\n"
        conf += "\n".join("    " + l for l in custom.splitlines()) + "\n"
    conf += "}\n"

    # ---- HTTPS server (8443) ----
    if ssl_on:
        crt = f"{WAF_CERTS}/{slug}/fullchain.pem"
        key = f"{WAF_CERTS}/{slug}/privkey.pem"
        conf += "server {\n"
        conf += "    listen 8443 ssl;\n"
        conf += f"    server_name {dom};\n"
        conf += waf_lines
        conf += f"    ssl_certificate {crt};\n"
        conf += f"    ssl_certificate_key {key};\n"
        conf += "    ssl_protocols TLSv1.2 TLSv1.3;\n"
        conf += "    ssl_prefer_server_ciphers off;\n"
        conf += acme_loc
        conf += exploit_lines
        conf += common_loc
        if custom.strip():
            conf += "\n".join("    " + l for l in custom.splitlines()) + "\n"
        conf += "}\n"
    return conf

def write_host_conf(h):
    slug = _slug(h["domain"])
    (PROXY_DIR / f"{slug}.conf").write_text(render_host_conf(h))
    try: os.chmod(PROXY_DIR / f"{slug}.conf", 0o644)
    except Exception: pass

def remove_host_conf(domain):
    slug = _slug(domain)
    f = PROXY_DIR / f"{slug}.conf"
    if f.exists(): f.unlink()

def waf_reload():
    try:
        r = subprocess.run(["docker","exec",WAF_CT,"nginx","-s","reload"],
                           capture_output=True,text=True,timeout=20)
        return r.returncode==0, (r.stderr or r.stdout).strip()
    except Exception as e:
        return False, str(e)

def waf_test_config():
    try:
        r = subprocess.run(["docker","exec",WAF_CT,"nginx","-t"],
                           capture_output=True,text=True,timeout=20)
        return r.returncode==0, (r.stderr or r.stdout).strip()
    except Exception as e:
        return False, str(e)

# ---------------- SSL: Let's Encrypt (certbot webroot) ----------------
def request_letsencrypt(domain, email=""):
    slug = _slug(domain)
    dest = CERTS_DIR / slug
    dest.mkdir(parents=True, exist_ok=True)
    email_args = ["--email", email] if email else ["--register-unsafely-without-email"]
    # certbot webroot -> tulis challenge ke ACME_DIR (di-serve nginx di :80)
    cmd = ["docker","run","--rm",
           "-v", f"{os.environ.get('TS_HOST_ACME','/root/turboshield/waf/acme')}:/var/www/acme",
           "-v", f"{os.environ.get('TS_HOST_LE','/root/turboshield/waf/letsencrypt')}:/etc/letsencrypt",
           "certbot/certbot","certonly","--webroot","-w","/var/www/acme",
           "--non-interactive","--agree-tos"] + email_args + ["-d", domain]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        out = (r.stdout + r.stderr)
        le_live = Path(os.environ.get("TS_LE_LIVE","/waf/letsencrypt/live")) / domain
        fc = le_live / "fullchain.pem"; pk = le_live / "privkey.pem"
        if fc.exists() and pk.exists():
            (dest/"fullchain.pem").write_bytes(fc.read_bytes())
            (dest/"privkey.pem").write_bytes(pk.read_bytes())
            os.chmod(dest/"fullchain.pem",0o644); os.chmod(dest/"privkey.pem",0o644)
            return True, "Sertifikat Let's Encrypt berhasil diterbitkan."
        return False, "certbot gagal:\n"+out[-800:]
    except Exception as e:
        return False, str(e)

def save_uploaded_cert(domain, cert_pem, key_pem):
    slug = _slug(domain)
    dest = CERTS_DIR / slug; dest.mkdir(parents=True, exist_ok=True)
    if "BEGIN CERTIFICATE" not in cert_pem:
        return False, "File sertifikat tidak valid (tidak ada BEGIN CERTIFICATE)."
    if "PRIVATE KEY" not in key_pem:
        return False, "File private key tidak valid (tidak ada PRIVATE KEY)."
    (dest/"fullchain.pem").write_text(cert_pem); os.chmod(dest/"fullchain.pem",0o644)
    (dest/"privkey.pem").write_text(key_pem); os.chmod(dest/"privkey.pem",0o644)
    return True, "Sertifikat berhasil diunggah."

def cert_info(domain):
    slug = _slug(domain)
    fc = CERTS_DIR / slug / "fullchain.pem"
    if not fc.exists(): return None
    try:
        r = subprocess.run(["openssl","x509","-in",str(fc),"-noout","-enddate","-issuer"],
                           capture_output=True,text=True,timeout=10)
        return r.stdout.strip()
    except Exception: return None

# ---------------- AI integration ----------------
AI_PROVIDERS = {
    "gemini":  {"label":"Google Gemini",  "needs":["api_key","model"], "default_model":"gemini-2.0-flash"},
    "openai":  {"label":"OpenAI",         "needs":["api_key","model"], "default_model":"gpt-4o-mini"},
    "claude":  {"label":"Anthropic Claude","needs":["api_key","model"], "default_model":"claude-sonnet-4"},
    "openrouter":{"label":"OpenRouter",   "needs":["api_key","model"], "default_model":"anthropic/claude-3.5-sonnet"},
    "ollama":  {"label":"Ollama (self-host)","needs":["endpoint","model"], "default_model":"llama3.1"},
    "custom":  {"label":"Custom OpenAI-compatible","needs":["endpoint","api_key","model"], "default_model":""},
}

def load_ai():
    if AI_DB.exists():
        try: return json.loads(AI_DB.read_text())
        except Exception: return {}
    return {}

def save_ai(cfg):
    AI_DB.write_text(json.dumps(cfg, indent=2)); os.chmod(AI_DB, 0o600)

def _masked(cfg):
    out = json.loads(json.dumps(cfg))
    for section in ("llm","n8n","librenms","telegram"):
        s = out.get(section, {})
        for kf in ("api_key","token","auth_token"):
            if s.get(kf):
                k=s[kf]; s[kf] = (k[:4]+"..."+k[-4:]) if len(k)>10 else "***"
    return out

# ---------------- LibreNMS ----------------
def test_librenms(url, token):
    if not url: return False, "URL LibreNMS wajib diisi."
    base = url.rstrip("/")
    try:
        req = urllib.request.Request(base + "/api/v0/devices",
              headers={"X-Auth-Token": token})
        with urllib.request.urlopen(req, timeout=12) as r:
            if r.status == 200:
                import json as _j
                data = _j.loads(r.read().decode())
                n = len(data.get("devices", [])) if isinstance(data, dict) else 0
                return True, f"Koneksi OK — {n} device terbaca dari LibreNMS."
            return False, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason} (cek token/URL)"
    except Exception as e:
        return False, str(e)

# ---------------- Telegram ----------------
def test_telegram(token, chat_id):
    if not token: return False, "Bot token wajib diisi."
    try:
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/getMe")
        with urllib.request.urlopen(req, timeout=12) as r:
            import json as _j
            d = _j.loads(r.read().decode())
            if not d.get("ok"): return False, "Token tidak valid."
            bot = d["result"].get("username", "?")
        # kirim test message kalau chat_id ada
        if chat_id:
            ok2, msg2 = send_telegram(token, chat_id, "✅ TurboShield: koneksi bot berhasil.")
            return ok2, (f"Bot @{bot} OK. " + msg2)
        return True, f"Bot @{bot} valid. (isi Chat ID utk uji kirim pesan)"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: cek bot token."
    except Exception as e:
        return False, str(e)

def send_telegram(token, chat_id, text):
    try:
        import urllib.parse
        data = urllib.parse.urlencode({"chat_id": chat_id, "text": text}).encode()
        req = urllib.request.Request(f"https://api.telegram.org/bot{token}/sendMessage", data=data)
        with urllib.request.urlopen(req, timeout=12) as r:
            import json as _j
            d = _j.loads(r.read().decode())
            return (d.get("ok", False), "Pesan terkirim." if d.get("ok") else "Gagal kirim (cek chat_id).")
    except Exception as e:
        return False, str(e)

def test_ai_connection(provider, api_key, model, endpoint):
    """Uji koneksi ringan ke provider AI."""
    try:
        if provider == "gemini":
            url=f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
            req=urllib.request.Request(url)
        elif provider == "openai":
            req=urllib.request.Request("https://api.openai.com/v1/models",
                headers={"Authorization":f"Bearer {api_key}"})
        elif provider == "claude":
            # anthropic: cek via messages endpoint minimal (butuh header khusus)
            req=urllib.request.Request("https://api.anthropic.com/v1/models",
                headers={"x-api-key":api_key,"anthropic-version":"2023-06-01"})
        elif provider == "openrouter":
            req=urllib.request.Request("https://openrouter.ai/api/v1/models",
                headers={"Authorization":f"Bearer {api_key}"})
        elif provider in ("ollama","custom"):
            base=(endpoint or "").rstrip("/")
            if not base: return False,"Endpoint wajib diisi."
            path="/api/tags" if provider=="ollama" else "/models"
            req=urllib.request.Request(base+path,
                headers={"Authorization":f"Bearer {api_key}"} if api_key else {})
        else:
            return False,"Provider tidak dikenal."
        with urllib.request.urlopen(req, timeout=12) as r:
            if r.status==200:
                return True, f"Koneksi OK (HTTP 200) ke {provider}."
            return False, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}: {e.reason} (cek API key/model)"
    except Exception as e:
        return False, str(e)
