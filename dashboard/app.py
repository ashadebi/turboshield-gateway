#!/usr/bin/env python3
"""TurboShield Gateway — Dashboard backend (FastAPI).
Menyediakan: setup wizard (first-run), login/session, system health, threat feed
(dari ModSecurity audit log), dan kontrol WAF (engine mode, anomaly threshold, custom rules).
"""
import os, json, secrets, hashlib, time, subprocess, re, uuid
from datetime import datetime, timezone
from pathlib import Path
from collections import deque, Counter

from fastapi import FastAPI, Request, Response, Form, HTTPException, Depends
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import psutil

# ---------------- Konfigurasi ----------------
DATA_DIR   = Path(os.environ.get("TS_DATA_DIR", "/app/data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
CRED_FILE  = DATA_DIR / "admin.json"
SESS_FILE  = DATA_DIR / "sessions.json"
AUDIT_LOG  = os.environ.get("TS_AUDIT_LOG", "/waf/logs/modsec_audit.log")
MANAGED    = os.environ.get("TS_MANAGED_RULE", "/waf/rules/aaa-turboshield-managed.conf")
CUSTOM     = os.environ.get("TS_CUSTOM_RULE", "/waf/rules/turboshield-custom.conf")
WAF_CT     = os.environ.get("TS_WAF_CONTAINER", "ts-waf")

app = FastAPI(title="TurboShield Gateway", docs_url=None, redoc_url=None)

# ---------------- Util auth ----------------
def _hash(pw: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), salt.encode(), 200_000).hex()

def load_admin():
    return json.loads(CRED_FILE.read_text()) if CRED_FILE.exists() else None

def save_admin(email, pw):
    salt = secrets.token_hex(16)
    CRED_FILE.write_text(json.dumps({
        "email": email, "salt": salt, "hash": _hash(pw, salt),
        "created": datetime.now(timezone.utc).isoformat()
    }))
    os.chmod(CRED_FILE, 0o600)

def load_sessions():
    if SESS_FILE.exists():
        try: return json.loads(SESS_FILE.read_text())
        except Exception: return {}
    return {}

def save_sessions(s):
    SESS_FILE.write_text(json.dumps(s)); os.chmod(SESS_FILE, 0o600)

def new_session(email):
    s = load_sessions(); tok = secrets.token_urlsafe(32)
    s[tok] = {"email": email, "ts": time.time()}
    save_sessions(s); return tok

def valid_session(tok):
    if not tok: return None
    s = load_sessions(); rec = s.get(tok)
    if not rec: return None
    if time.time() - rec["ts"] > 86400:  # 24 jam
        s.pop(tok, None); save_sessions(s); return None
    return rec["email"]

def require_auth(request: Request):
    email = valid_session(request.cookies.get("ts_session"))
    if not email: raise HTTPException(status_code=401, detail="unauthorized")
    return email

# ---------------- Util WAF ----------------
def waf_reload():
    try:
        r = subprocess.run(["docker", "exec", WAF_CT, "nginx", "-s", "reload"],
                           capture_output=True, text=True, timeout=20)
        return r.returncode == 0, (r.stderr or r.stdout).strip()
    except Exception as e:
        return False, str(e)

def read_managed():
    """Ambil engine mode & threshold dari file managed."""
    mode, thr = "On", 5
    try:
        txt = Path(MANAGED).read_text()
        m = re.search(r"SecRuleEngine\s+(\w+)", txt)
        if m: mode = m.group(1)
        t = re.search(r"inbound_anomaly_score_threshold=(\d+)", txt)
        if t: thr = int(t.group(1))
    except Exception: pass
    return mode, thr

def write_managed(mode, thr):
    content = f"""# TurboShield Managed Rules (dikelola dashboard — jangan edit manual)
SecRuleEngine {mode}
SecAction "id:90000,phase:1,pass,nolog,\\
  setvar:tx.inbound_anomaly_score_threshold={thr},\\
  setvar:tx.outbound_anomaly_score_threshold=4"
"""
    Path(MANAGED).write_text(content)
    try: os.chmod(MANAGED, 0o644)   # WAJIB world-readable agar WAF (uid nginx) bisa baca
    except Exception: pass

# ---------------- Util threat feed ----------------
def parse_threats(limit=200):
    """Parse ModSecurity JSON audit log -> daftar serangan terbaru."""
    events = deque(maxlen=limit)
    p = Path(AUDIT_LOG)
    if not p.exists(): return []
    try:
        for line in p.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"): continue
            try: j = json.loads(line)
            except Exception: continue
            tx = j.get("transaction", {})
            msgs = tx.get("messages", []) or j.get("transaction", {}).get("messages", [])
            # image format: top-level 'transaction'
            trans = j.get("transaction", {})
            req = trans.get("request", {})
            resp = trans.get("response", {})
            ms = trans.get("messages", [])
            rule_msgs = []
            cats = set()
            for m in ms:
                det = m.get("details", {})
                rule_msgs.append(m.get("message", ""))
                for t in (det.get("tags") or []):
                    if t.startswith("attack-"): cats.add(t.replace("attack-", ""))
            events.append({
                "time": trans.get("time_stamp", ""),
                "ip": trans.get("client_ip", ""),
                "method": req.get("method", ""),
                "uri": (req.get("uri", "") or "")[:120],
                "status": resp.get("http_code", ""),
                "categories": sorted(cats) or ["anomaly"],
                "messages": rule_msgs[:3],
            })
    except Exception:
        return list(events)[::-1]
    return list(events)[::-1]

# ---------------- Util system health ----------------
def system_health():
    cpu = psutil.cpu_percent(interval=0.3)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage("/")
    temp = None
    try:
        t = psutil.sensors_temperatures()
        for _, arr in (t or {}).items():
            if arr: temp = round(arr[0].current, 1); break
    except Exception: pass
    return {
        "cpu_percent": cpu,
        "mem_percent": mem.percent,
        "mem_used_gb": round(mem.used/1e9, 2), "mem_total_gb": round(mem.total/1e9, 2),
        "disk_percent": disk.percent,
        "disk_free_gb": round(disk.free/1e9, 1), "disk_total_gb": round(disk.total/1e9, 1),
        "temp_c": temp,  # None -> "N/A" di UI (VPS biasanya tak ada sensor)
        "boot": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M"),
    }

def waf_status():
    try:
        r = subprocess.run(["docker", "inspect", "-f",
             "{{.State.Status}}|{{.State.Health.Status}}", WAF_CT],
             capture_output=True, text=True, timeout=10)
        st = r.stdout.strip().split("|")
        return {"state": st[0] if st else "unknown",
                "health": st[1] if len(st) > 1 else "n/a"}
    except Exception as e:
        return {"state": "error", "health": str(e)}

# ================= ROUTES: AUTH =================
from fastapi.staticfiles import StaticFiles

@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    host = (request.headers.get("host") or "").split(":")[0].lower()
    if host == "tv.teelee.my.id":
        return HTMLResponse(Path("/app/static/tv.html").read_text())
    if load_admin() is None:
        return HTMLResponse(Path("/app/static/setup.html").read_text())
    if valid_session(request.cookies.get("ts_session")):
        return HTMLResponse(Path("/app/static/dashboard.html").read_text())
    return HTMLResponse(Path("/app/static/login.html").read_text())

# logo & aset statis (favicon, app-icon) — publik, cuma file gambar
if Path("/app/static/assets").exists():
    app.mount("/assets", StaticFiles(directory="/app/static/assets"), name="assets")

@app.post("/api/setup")
def api_setup(email: str = Form(...), confirm: str = Form(default="")):
    if load_admin() is not None:
        raise HTTPException(400, "Setup sudah pernah dilakukan.")
    if "@" not in email or "." not in email:
        raise HTTPException(400, "Email tidak valid.")
    pw = secrets.token_urlsafe(12)  # password kuat auto-generate
    save_admin(email, pw)
    # kirim ke Telegram bila sudah dikonfigurasi
    tg_sent = False
    try:
        import proxy_ai as _px
        tg = _px.load_ai().get("telegram", {})
        if tg.get("token") and tg.get("chat_id") and tg.get("notify_setup", True):
            ok, _ = _px.send_telegram(tg["token"], tg["chat_id"],
                f"🛡️ TurboShield Gateway\nAkun admin dibuat.\nEmail: {email}\nPassword: {pw}\n\nSimpan baik-baik & hapus pesan ini setelah dicatat.")
            tg_sent = ok
    except Exception:
        pass
    return {"status": "ok", "email": email, "password": pw, "telegram_sent": tg_sent,
            "note": "Simpan password ini — hanya ditampilkan sekali."}

@app.post("/api/login")
def api_login(response: Response, email: str = Form(...), password: str = Form(...)):
    a = load_admin()
    if not a: raise HTTPException(400, "Belum setup.")
    if email.strip().lower() != a["email"].lower() or _hash(password, a["salt"]) != a["hash"]:
        raise HTTPException(401, "Email atau password salah.")
    tok = new_session(a["email"])
    r = JSONResponse({"status": "ok"})
    r.set_cookie("ts_session", tok, httponly=True, samesite="lax", max_age=86400)
    return r

@app.post("/api/logout")
def api_logout(request: Request):
    tok = request.cookies.get("ts_session")
    s = load_sessions(); s.pop(tok, None); save_sessions(s)
    r = JSONResponse({"status": "ok"}); r.delete_cookie("ts_session"); return r

# ================= ROUTES: DATA (protected) =================
@app.get("/api/overview")
def api_overview(email: str = Depends(require_auth)):
    threats = parse_threats(200)
    cat = Counter()
    for t in threats:
        for c in t["categories"]: cat[c] += 1
    top_ip = Counter(t["ip"] for t in threats if t["ip"])
    return {
        "health": system_health(),
        "waf": waf_status(),
        "threat_total": len(threats),
        "threat_by_cat": dict(cat.most_common(8)),
        "top_ips": dict(top_ip.most_common(5)),
        "recent": threats[:20],
        "admin_email": email,
    }

@app.get("/api/threats")
def api_threats(email: str = Depends(require_auth)):
    return {"threats": parse_threats(200)}

@app.get("/api/waf")
def api_waf_get(email: str = Depends(require_auth)):
    mode, thr = read_managed()
    return {"engine_mode": mode, "anomaly_threshold": thr, "waf": waf_status()}

@app.post("/api/waf")
def api_waf_set(email: str = Depends(require_auth),
                engine_mode: str = Form(...), anomaly_threshold: int = Form(...)):
    if engine_mode not in ("On", "DetectionOnly", "Off"):
        raise HTTPException(400, "engine_mode tidak valid.")
    if not (1 <= anomaly_threshold <= 100):
        raise HTTPException(400, "threshold 1-100.")
    write_managed(engine_mode, anomaly_threshold)
    ok, msg = waf_reload()
    return {"status": "ok" if ok else "reload_failed", "reload_msg": msg,
            "engine_mode": engine_mode, "anomaly_threshold": anomaly_threshold}

@app.get("/api/custom-rules")
def api_custom_get(email: str = Depends(require_auth)):
    try: return {"content": Path(CUSTOM).read_text()}
    except Exception as e: return {"content": "", "error": str(e)}

@app.post("/api/custom-rules")
def api_custom_set(email: str = Depends(require_auth), content: str = Form(...)):
    Path(CUSTOM).write_text(content)
    try: os.chmod(CUSTOM, 0o644)
    except Exception: pass
    ok, msg = waf_reload()
    return {"status": "ok" if ok else "reload_failed", "reload_msg": msg}

@app.get("/api/health")
def api_health():  # publik utk healthcheck
    return {"status": "healthy", "service": "turboshield-dashboard"}

# ================= ROUTES: PROXY MANAGER =================
import proxy_ai as PX

@app.get("/api/proxy-hosts")
def api_hosts_list(email: str = Depends(require_auth)):
    hosts = PX.load_hosts()
    for h in hosts:
        h["cert_info"] = PX.cert_info(h["domain"])
    return {"hosts": hosts, "ai_providers": PX.AI_PROVIDERS}

@app.post("/api/proxy-hosts")
def api_hosts_save(email: str = Depends(require_auth),
                   domain: str = Form(...), upstream: str = Form(...),
                   scheme: str = Form("http"), websocket: str = Form("true"),
                   block_exploits: str = Form("true"), force_ssl: str = Form("false"),
                   ssl_enabled: str = Form(""), custom_config: str = Form(""),
                   waf_mode: str = Form("On")):
    domain = domain.strip().lower()
    if not domain or " " in domain:
        raise HTTPException(400, "Domain tidak valid.")
    if not upstream.strip():
        raise HTTPException(400, "Upstream wajib diisi (contoh: 192.168.1.10:3000).")
    if waf_mode not in ("On", "DetectionOnly", "Off"):
        waf_mode = "On"
    hosts = PX.load_hosts()
    existing = next((h for h in hosts if h["domain"] == domain), None)
    rec = existing or {"domain": domain, "ssl": {"enabled": False, "force": False}}
    rec.update({
        "upstream": upstream.strip(), "scheme": scheme,
        "websocket": websocket == "true", "block_exploits": block_exploits == "true",
        "custom_config": custom_config, "waf_mode": waf_mode,
        "updated": datetime.now(timezone.utc).isoformat(),
    })
    rec.setdefault("ssl", {"enabled": False, "force": False})
    # ssl_enabled hanya di-set bila param dikirim eksplisit; else pertahankan (dikelola panel SSL)
    if ssl_enabled != "":
        rec["ssl"]["enabled"] = ssl_enabled == "true"
    rec["ssl"]["force"] = force_ssl == "true"
    if not existing: hosts.append(rec)
    # tulis config + test + reload
    PX.write_host_conf(rec)
    ok, msg = PX.waf_test_config()
    if not ok:
        PX.remove_host_conf(domain)
        raise HTTPException(400, f"Config nginx invalid, dibatalkan:\n{msg[-400:]}")
    PX.save_hosts(hosts)
    rok, rmsg = PX.waf_reload()
    return {"status": "ok" if rok else "reload_failed", "reload_msg": rmsg, "host": rec}

@app.post("/api/proxy-hosts/delete")
def api_hosts_delete(email: str = Depends(require_auth), domain: str = Form(...)):
    domain = domain.strip().lower()
    hosts = [h for h in PX.load_hosts() if h["domain"] != domain]
    PX.save_hosts(hosts)
    PX.remove_host_conf(domain)
    # bersihkan rate-limit rules yg nempel di host yg dihapus + regenerate zona
    rl_rules = [r for r in RL.load_rules() if r.get("host") != domain]
    RL.save_rules(rl_rules)
    RL.regenerate_zones_file()
    ok, msg = PX.waf_reload()
    return {"status": "ok", "reload_msg": msg}

# ================= ROUTES: RATE LIMITING =================
import ratelimit as RL

@app.get("/api/rate-limits")
def api_rl_list(email: str = Depends(require_auth)):
    return {"rules": RL.load_rules(), "scopes": list(RL.SCOPES),
            "hosts": [h["domain"] for h in PX.load_hosts()]}

@app.post("/api/rate-limits")
def api_rl_save(email: str = Depends(require_auth),
                 rule_id: str = Form(""), host: str = Form(...),
                 path_prefix: str = Form("/"), scope: str = Form("ip"),
                 key_name: str = Form(""), key_source: str = Form("header"),
                 rate: int = Form(...), unit: str = Form("s"),
                 burst: int = Form(0), nodelay: str = Form("true"),
                 enabled: str = Form("true")):
    rules = RL.load_rules()
    rid = rule_id.strip() or str(uuid.uuid4())[:8]
    rec = {
        "id": rid, "host": host.strip().lower(), "path_prefix": path_prefix.strip() or "/",
        "scope": scope, "key_name": key_name.strip(), "key_source": key_source,
        "rate": rate, "unit": unit if unit in ("s", "m") else "s",
        "burst": burst if burst > 0 else max(1, rate * 2),
        "nodelay": nodelay == "true", "enabled": enabled == "true",
        "updated": datetime.now(timezone.utc).isoformat(),
    }
    ok, msg = RL.validate_rule(rec)
    if not ok:
        raise HTTPException(400, msg)
    rules = [r for r in rules if r["id"] != rid]
    rules.append(rec)
    RL.save_rules(rules)
    # regenerate zona + config host yg terdampak, lalu reload
    host_obj = next((h for h in PX.load_hosts() if h["domain"] == rec["host"]), None)
    if not host_obj:
        raise HTTPException(400, f"Host '{rec['host']}' tidak ditemukan di Proxy Manager.")
    PX.write_host_conf(host_obj)
    tok, tmsg = PX.waf_test_config()
    if not tok:
        rules = [r for r in rules if r["id"] != rid]
        RL.save_rules(rules); RL.regenerate_zones_file(); PX.write_host_conf(host_obj)
        raise HTTPException(400, f"Config nginx invalid, rule dibatalkan:\n{tmsg}")
    ok2, msg2 = PX.waf_reload()
    return {"status": "ok", "rule": rec, "reload_msg": msg2}

@app.post("/api/rate-limits/delete")
def api_rl_delete(email: str = Depends(require_auth), rule_id: str = Form(...)):
    rules = RL.load_rules()
    target = next((r for r in rules if r["id"] == rule_id), None)
    rules = [r for r in rules if r["id"] != rule_id]
    RL.save_rules(rules)
    RL.regenerate_zones_file()
    if target:
        host_obj = next((h for h in PX.load_hosts() if h["domain"] == target["host"]), None)
        if host_obj:
            PX.write_host_conf(host_obj)
    ok, msg = PX.waf_reload()
    return {"status": "ok", "reload_msg": msg}

# ================= ROUTES: BOT PROTECTION =================
import botprotect as BP

@app.get("/api/bot-protection")
def api_bot_get(email: str = Depends(require_auth)):
    return BP.load_config()

@app.post("/api/bot-protection/toggle")
def api_bot_toggle(email: str = Depends(require_auth),
                    section: str = Form(...), key: str = Form(...), enabled: str = Form(...)):
    if section not in ("allow", "challenge", "block"):
        raise HTTPException(400, "Section tidak dikenal.")
    cfg = BP.load_config()
    if key not in cfg[section]:
        raise HTTPException(404, f"Kategori '{key}' tidak ditemukan di {section}.")
    cfg[section][key]["enabled"] = enabled == "true"
    BP.save_config(cfg)
    BP.regenerate_rule_file()
    tok, tmsg = PX.waf_test_config()
    if not tok:
        raise HTTPException(400, f"Config nginx/ModSecurity invalid:\n{tmsg}")
    ok, msg = PX.waf_reload()
    return {"status": "ok", "reload_msg": msg, "config": cfg}

@app.post("/api/bot-protection/mode")
def api_bot_mode(email: str = Depends(require_auth), challenge_mode: str = Form(...)):
    if challenge_mode not in ("log", "block"):
        raise HTTPException(400, "Mode harus 'log' atau 'block'.")
    cfg = BP.load_config()
    cfg["challenge_mode"] = challenge_mode
    BP.save_config(cfg)
    BP.regenerate_rule_file()
    tok, tmsg = PX.waf_test_config()
    if not tok:
        raise HTTPException(400, f"Config nginx/ModSecurity invalid:\n{tmsg}")
    ok, msg = PX.waf_reload()
    return {"status": "ok", "reload_msg": msg}

@app.post("/api/bot-protection/custom")
def api_bot_add_custom(email: str = Depends(require_auth),
                        section: str = Form(...), key: str = Form(...),
                        label: str = Form(...), ua_list: str = Form(...)):
    if section not in ("allow", "challenge", "block"):
        raise HTTPException(400, "Section tidak dikenal.")
    key = re.sub(r"[^a-z0-9_]", "_", key.strip().lower())
    ua = [t.strip() for t in ua_list.split(",") if t.strip()]
    if not key or not ua:
        raise HTTPException(400, "Key dan minimal 1 User-Agent pattern wajib diisi.")
    cfg = BP.load_config()
    cfg[section][key] = {"label": label.strip() or key, "ua": ua, "enabled": True}
    BP.save_config(cfg)
    BP.regenerate_rule_file()
    tok, tmsg = PX.waf_test_config()
    if not tok:
        del cfg[section][key]
        BP.save_config(cfg); BP.regenerate_rule_file()
        raise HTTPException(400, f"Config invalid, kategori dibatalkan:\n{tmsg}")
    ok, msg = PX.waf_reload()
    return {"status": "ok", "reload_msg": msg, "config": cfg}

@app.post("/api/proxy-hosts/ssl-letsencrypt")
def api_ssl_le(email: str = Depends(require_auth), domain: str = Form(...), le_email: str = Form("")):
    domain = domain.strip().lower()
    ok, msg = PX.request_letsencrypt(domain, le_email)
    if not ok: raise HTTPException(400, msg)
    hosts = PX.load_hosts()
    h = next((x for x in hosts if x["domain"] == domain), None)
    if h:
        h.setdefault("ssl", {})["enabled"] = True
        PX.save_hosts(hosts); PX.write_host_conf(h)
        tok, tmsg = PX.waf_test_config()
        if tok: PX.waf_reload()
    return {"status": "ok", "message": msg, "cert_info": PX.cert_info(domain)}

@app.post("/api/proxy-hosts/ssl-upload")
def api_ssl_upload(email: str = Depends(require_auth), domain: str = Form(...),
                   cert_pem: str = Form(...), key_pem: str = Form(...)):
    domain = domain.strip().lower()
    ok, msg = PX.save_uploaded_cert(domain, cert_pem, key_pem)
    if not ok: raise HTTPException(400, msg)
    hosts = PX.load_hosts()
    h = next((x for x in hosts if x["domain"] == domain), None)
    if h:
        h.setdefault("ssl", {})["enabled"] = True
        PX.save_hosts(hosts); PX.write_host_conf(h)
        tok, tmsg = PX.waf_test_config()
        if not tok:
            raise HTTPException(400, f"Config invalid:\n{tmsg[-300:]}")
        PX.waf_reload()
    return {"status": "ok", "message": msg, "cert_info": PX.cert_info(domain)}

# ================= ROUTES: AI INTEGRATION =================
@app.get("/api/ai-config")
def api_ai_get(email: str = Depends(require_auth)):
    return {"config": PX._masked(PX.load_ai()), "providers": PX.AI_PROVIDERS}

@app.post("/api/ai-config")
def api_ai_save(email: str = Depends(require_auth),
                provider: str = Form(...), api_key: str = Form(""),
                model: str = Form(""), endpoint: str = Form(""),
                n8n_webhook: str = Form(""), enabled: str = Form("false")):
    if provider not in PX.AI_PROVIDERS:
        raise HTTPException(400, "Provider tidak dikenal.")
    cfg = PX.load_ai()
    # jika api_key kosong & sudah ada sebelumnya (masked), pertahankan yg lama
    old = cfg.get("llm", {})
    if not api_key and old.get("api_key"):
        api_key = old["api_key"]
    cfg["llm"] = {"provider": provider, "api_key": api_key, "model": model, "endpoint": endpoint,
                  "enabled": enabled == "true"}
    cfg["n8n"] = {"webhook": n8n_webhook}
    PX.save_ai(cfg)
    return {"status": "ok", "config": PX._masked(cfg)}

@app.post("/api/ai-config/test")
def api_ai_test(email: str = Depends(require_auth),
                provider: str = Form(...), api_key: str = Form(""),
                model: str = Form(""), endpoint: str = Form("")):
    cfg = PX.load_ai()
    if not api_key and cfg.get("llm", {}).get("api_key"):
        api_key = cfg["llm"]["api_key"]
    ok, msg = PX.test_ai_connection(provider, api_key, model, endpoint)
    return {"status": "ok" if ok else "failed", "message": msg}

# ================= ROUTES: LibreNMS =================
@app.post("/api/integration/librenms")
def api_librenms_save(email: str = Depends(require_auth),
                      url: str = Form(...), token: str = Form("")):
    cfg = PX.load_ai()
    old = cfg.get("librenms", {})
    if not token and old.get("token"):
        token = old["token"]
    cfg["librenms"] = {"url": url.strip(), "token": token}
    PX.save_ai(cfg)
    return {"status": "ok", "config": PX._masked(cfg)}

@app.post("/api/integration/librenms/test")
def api_librenms_test(email: str = Depends(require_auth),
                      url: str = Form(...), token: str = Form("")):
    cfg = PX.load_ai()
    if not token and cfg.get("librenms", {}).get("token"):
        token = cfg["librenms"]["token"]
    ok, msg = PX.test_librenms(url, token)
    return {"status": "ok" if ok else "failed", "message": msg}

# ================= ROUTES: Telegram =================
@app.post("/api/integration/telegram")
def api_tg_save(email: str = Depends(require_auth),
                token: str = Form(""), chat_id: str = Form(""),
                notify_setup: str = Form("true")):
    cfg = PX.load_ai()
    old = cfg.get("telegram", {})
    if not token and old.get("token"):
        token = old["token"]
    cfg["telegram"] = {"token": token, "chat_id": chat_id.strip(),
                       "notify_setup": notify_setup == "true"}
    PX.save_ai(cfg)
    return {"status": "ok", "config": PX._masked(cfg)}

@app.post("/api/integration/telegram/test")
def api_tg_test(email: str = Depends(require_auth),
                token: str = Form(""), chat_id: str = Form("")):
    cfg = PX.load_ai()
    if not token and cfg.get("telegram", {}).get("token"):
        token = cfg["telegram"]["token"]
    ok, msg = PX.test_telegram(token, chat_id)
    return {"status": "ok" if ok else "failed", "message": msg}


# ================= ROUTES: STREAMS (TCP/UDP, NPM-like) =================
import stream_proxy as SP

@app.get("/api/streams")
def api_streams_list(email: str = Depends(require_auth)):
    return {"streams": SP.load_streams(), "stream_status": SP.status()}

@app.post("/api/streams")
def api_streams_save(email: str = Depends(require_auth),
                     name: str = Form(...), listen_port: int = Form(...),
                     protocol: str = Form("tcp"), upstream_host: str = Form(...),
                     upstream_port: int = Form(...), enabled: str = Form("true")):
    try:
        name, lp, proto, uh, up = SP.validate(name, listen_port, protocol, upstream_host, upstream_port)
    except Exception as e:
        raise HTTPException(400, str(e))
    items = SP.load_streams()
    old = next((x for x in items if x.get("name") == name), None)
    # unique listen port/protocol among enabled streams except self
    for x in items:
        if x.get("name") != name and x.get("enabled", True) and int(x.get("listen_port",0)) == lp and x.get("protocol","tcp") == proto:
            raise HTTPException(400, f"Port {lp}/{proto} sudah dipakai stream '{x.get('name')}'.")
    rec = old or {"name": name, "created": datetime.now(timezone.utc).isoformat()}
    rec.update({"listen_port": lp, "protocol": proto, "upstream_host": uh, "upstream_port": up,
                "enabled": enabled == "true", "updated": datetime.now(timezone.utc).isoformat()})
    if not old: items.append(rec)
    if rec["enabled"]: SP.write_conf(rec)
    else: SP.remove_conf(name)
    ok,msg = SP.test_config()
    if not ok:
        SP.remove_conf(name)
        raise HTTPException(400, "Config stream invalid:\n" + msg[-400:])
    SP.save_streams(items)
    rok,rmsg = SP.reload_stream()
    return {"status":"ok" if rok else "reload_failed", "reload_msg": rmsg, "stream": rec}

@app.post("/api/streams/delete")
def api_streams_delete(email: str = Depends(require_auth), name: str = Form(...)):
    items=[x for x in SP.load_streams() if x.get("name") != name]
    SP.save_streams(items); SP.remove_conf(name)
    ok,msg=SP.test_config()
    if ok: rok,rmsg=SP.reload_stream()
    else: rok,rmsg=False,msg
    return {"status":"ok" if rok else "reload_failed", "reload_msg":rmsg}


# ================= TV Teelee public HLS dashboard (no auth) =================
import base64, urllib.parse, urllib.request
from fastapi.responses import PlainTextResponse, StreamingResponse

TV_CHANNELS = [
 {"id":"tvri-nasional","name":"TVRI Nasional","group":"TVRI","url":"https://ott-balancer.tvri.go.id/live/eds/Nasional/hls/Nasional.m3u8","note":"Official TVRI HLS"},
 {"id":"tvri-world","name":"TVRI World","group":"TVRI","url":"https://ott-balancer.tvri.go.id/live/eds/TVRIWorld/hls/TVRIWorld.m3u8","note":"Official TVRI HLS"},
 {"id":"tvri-sport","name":"TVRI Sport","group":"TVRI","url":"https://ott-balancer.tvri.go.id/live/eds/SportHD/hls/SportHD.m3u8","note":"Official TVRI HLS"},
 {"id":"tvri-aceh","name":"TVRI Aceh","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Aceh/hls/Aceh.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-bali","name":"TVRI Bali","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Bali/hls/Bali.m3u8","note":"Official TVRI HLS"},
 {"id":"tvri-babel","name":"TVRI Bangka Belitung","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Babel/hls/Babel.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-bengkulu","name":"TVRI Bengkulu","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Bengkulu/hls/Bengkulu.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-gorontalo","name":"TVRI Gorontalo","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Gorontalo/hls/Gorontalo.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-jabar","name":"TVRI Jawa Barat","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Jabar/hls/Jabar.m3u8","note":"Official TVRI HLS"},
 {"id":"tvri-jateng","name":"TVRI Jawa Tengah","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Jateng/hls/Jateng.m3u8","note":"Official TVRI HLS"},
 {"id":"tvri-jatim","name":"TVRI Jawa Timur","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Jatim/hls/Jatim.m3u8","note":"Official TVRI HLS"},
 {"id":"tvri-kalbar","name":"TVRI Kalimantan Barat","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Kalbar/hls/Kalbar.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-kalsel","name":"TVRI Kalimantan Selatan","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Kalsel/hls/Kalsel.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-kalteng","name":"TVRI Kalimantan Tengah","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Kalteng/hls/Kalteng.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-kaltim","name":"TVRI Kalimantan Timur","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Kaltim/hls/Kaltim.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-lampung","name":"TVRI Lampung","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Lampung/hls/Lampung.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-maluku","name":"TVRI Maluku","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Ambon/hls/Ambon.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-sulut","name":"TVRI North Sulawesi","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Sulut/hls/Sulut.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-sumut","name":"TVRI North Sumatra","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Sumut/hls/Sumut.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-ntb","name":"TVRI Nusa Tenggara Barat","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/NTB/hls/NTB.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-ntt","name":"TVRI Nusa Tenggara Timur","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/NTT/hls/NTT.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-papua","name":"TVRI Papua","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Papua/hls/Papua.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-riau","name":"TVRI Riau","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Riau/hls/Riau.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-sulbar","name":"TVRI Sulawesi Barat","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Sulbar/hls/Sulbar.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-sulsel","name":"TVRI Sulawesi Selatan","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Sulsel/hls/Sulsel.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-sulteng","name":"TVRI Sulawesi Tengah","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Sulteng/hls/Sulteng.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-sultra","name":"TVRI Sulawesi Tenggara","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Sultra/hls/Sultra.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-sumbar","name":"TVRI Sumatera Barat","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Sumbar/hls/Sumbar.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-sumsel","name":"TVRI Sumatera Selatan","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Sumsel/hls/Sumsel.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-pabar","name":"TVRI West Papua","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Pabar/hls/Pabar.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"tvri-jogja","name":"TVRI Yogyakarta","group":"TVRI Daerah","url":"https://ott-balancer.tvri.go.id/live/eds/Jogjakarta/hls/Jogjakarta.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"sctv-video","name":"SCTV (Video)","group":"DASH","url":"https://tvratu.my.id/vid/index.mpd?id=204&type=dash","note":"DASH source dhanytv, tested playlist OK"},
 {"id":"indosiar-video","name":"Indosiar (Video)","group":"DASH","url":"https://tvratu.my.id/vid/index.mpd?id=205&type=dash","note":"DASH source dhanytv, tested playlist OK"},
 {"id":"rcti-dash","name":"RCTI","group":"DASH","url":"https://cdnbal1.indihometv.com/atm/DASH/rcti/rcti-avc1_2500000=7-3277707030000000.mpd","note":"DASH source dhanytv, tested playlist OK"},
 {"id":"kompas-tv-dash","name":"Kompas TV","group":"DASH","url":"https://cdnbal1.indihometv.com/atm/DASH/KOMPAS_TV/KOMPAS_TV-avc1_2500000=7-3277707030000000.mpd","note":"DASH source dhanytv, tested playlist OK"},
 {"id":"metro-tv","name":"Metro TV","group":"FTA News","url":"https://edge.medcom.id/live-edge/smil:metro.smil/playlist.m3u8","note":"Stable HLS"},
 {"id":"cnn-indonesia","name":"CNN Indonesia","group":"News","url":"https://live.cnnindonesia.com/livecnn/smil:cnntv.smil/playlist.m3u8","note":"Tested OK"},
 {"id":"cnbc-indonesia","name":"CNBC Indonesia","group":"News","url":"https://live.cnbcindonesia.com/livecnbc/smil:cnbctv.smil/playlist.m3u8","note":"Tested OK"},
 {"id":"rri-net","name":"RRI Net","group":"FTA Public","url":"https://private-streaming.rri.go.id/memfs/6f77c7b5-feb2-4935-9f89-e7e9fca0a54a_output_0.m3u8","note":"RRI HLS"},
 {"id":"rtv","name":"RTV","group":"FTA Lokal","url":"https://rtvstream.rtv.co.id:4555/hls/rtv.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"nusantara-tv","name":"Nusantara TV","group":"FTA Lokal","url":"https://nusantaratv.siar.us/nusantaratv/live/playlist.m3u8","note":"Tested OK"},
 {"id":"garuda-tv","name":"Garuda TV","group":"FTA Lokal","url":"https://hgmtv.com:19360/garudatvlivestreaming/480p.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"daai-tv","name":"DAAI TV","group":"FTA Lokal","url":"https://pull.daaiplus.com/live-DAAIPLUS/live-DAAIPLUS_HD.m3u8","note":"Source dhanytv alt, HLS"},
 {"id":"rodja-tv","name":"Rodja TV","group":"Religious","url":"https://rodjatv.com/rodjatv/live.m3u8","note":"Tested OK"},
 {"id":"brtv","name":"BRTV","group":"FTA Lokal","url":"https://live.artidijitalmedya.com/artidijital_brtv/brtv/playlist.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"banjar-tv","name":"BanjarTV","group":"FTA Lokal","url":"https://banjartv.siar.us/banjartv/live/playlist.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"caruban-tv","name":"CarubanTV","group":"FTA Lokal","url":"https://stream.carubantv.id/hls/0/stream.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"fgtv","name":"FGTV","group":"FTA Lokal","url":"https://fgtvlive.fgtv.com/smil:fgtv.smil/playlist.m3u8","note":"Source dhanytv, tested OK"},
 {"id":"biznet-adventure","name":"Biznet Adventure","group":"Public Channel","url":"http://livestream.biznetvideo.net/biznet_adventure/smil:adventure.smil/playlist.m3u8","note":"Tested OK"},
 {"id":"biznet-kids","name":"Biznet Kids","group":"Public Channel","url":"http://livestream.biznetvideo.net/biznet_kids/smil:kids.smil/index.m3u8","note":"Tested OK"},
 {"id":"biznet-lifestyle","name":"Biznet Lifestyle","group":"Public Channel","url":"http://livestream.biznetvideo.net/biznet_lifestyle/smil:lifestyle.smil/index.m3u8","note":"Tested OK"},
]



def _tv_chan(cid): return next((c for c in TV_CHANNELS if c["id"] == cid), None)
def _b64u(x): return base64.urlsafe_b64encode(x.encode()).decode().rstrip('=')
def _unb64u(x): return base64.urlsafe_b64decode((x+'='*(-len(x)%4)).encode()).decode()
def _tv_fetch(url):
    req=urllib.request.Request(url,headers={"User-Agent":"Mozilla/5.0 TurboShield-TV/1.0","Accept":"*/*"})
    return urllib.request.urlopen(req,timeout=20)

@app.get("/api/tv/channels")
def api_tv_channels(): return {"channels":TV_CHANNELS}

@app.get("/api/tv/playlist/{cid}")
def api_tv_playlist(cid: str):
    c=_tv_chan(cid)
    if not c: raise HTTPException(404,"channel not found")
    try: txt=_tv_fetch(c["url"]).read().decode('utf-8','replace')
    except Exception as e: raise HTTPException(502,f"upstream playlist error: {e}")
    if '.mpd' in urllib.parse.urlparse(c["url"]).path or 'type=dash' in c["url"]:
        return PlainTextResponse(txt, media_type='application/dash+xml')
    out=[]
    for line in txt.splitlines():
        st=line.strip()
        if not st or st.startswith('#'):
            if 'URI="' in line:
                def rep(m): return 'URI="/api/tv/proxy/%s?u=%s"' % (cid,_b64u(urllib.parse.urljoin(c["url"],m.group(1))))
                line=re.sub(r'URI="([^"]+)"',rep,line)
            out.append(line); continue
        out.append('/api/tv/proxy/%s?u=%s' % (cid,_b64u(urllib.parse.urljoin(c["url"],st))))
    return PlainTextResponse('\n'.join(out)+'\n',media_type='application/vnd.apple.mpegurl')

def _tv_rewrite_playlist(cid: str, base_url: str, txt: str) -> str:
    out=[]
    for line in txt.splitlines():
        st=line.strip()
        if not st or st.startswith('#'):
            if 'URI="' in line:
                def rep(m): return 'URI="/api/tv/proxy/%s?u=%s"' % (cid,_b64u(urllib.parse.urljoin(base_url,m.group(1))))
                line=re.sub(r'URI="([^"]+)"',rep,line)
            out.append(line); continue
        out.append('/api/tv/proxy/%s?u=%s' % (cid,_b64u(urllib.parse.urljoin(base_url,st))))
    return '\n'.join(out)+'\n'

@app.get("/api/tv/proxy/{cid}")
def api_tv_proxy(cid: str, u: str):
    if not _tv_chan(cid): raise HTTPException(404,"channel not found")
    try:
        url=_unb64u(u)
        if not url.startswith(('http://','https://')): raise ValueError('bad url')
        r=_tv_fetch(url)
        ctype=r.headers.get('Content-Type') or 'application/octet-stream'
        if '.m3u8' in urllib.parse.urlparse(url).path or 'mpegurl' in ctype.lower():
            txt=r.read().decode('utf-8','replace')
            return PlainTextResponse(_tv_rewrite_playlist(cid,url,txt),media_type='application/vnd.apple.mpegurl')
    except Exception as e: raise HTTPException(502,f"upstream segment error: {e}")
    return StreamingResponse(r,media_type=ctype)

@app.get("/tv", response_class=HTMLResponse)
def tv_page_public(): return HTMLResponse(Path('/app/static/tv.html').read_text())



# ================= ROUTES: SECURITY ENGINES =================
ENGINES_DB = DATA_DIR / "security_engines.json"

def _engines_default():
    return {"waf":"coraza","crowdsec":{"enabled":True,"mode":"detect"}}

def load_engines():
    if ENGINES_DB.exists():
        try: return json.loads(ENGINES_DB.read_text())
        except Exception: pass
    return _engines_default()

def save_engines(cfg):
    cfg["waf"] = "coraza"  # open-appsec skipped for now
    cfg["updated"] = datetime.now(timezone.utc).isoformat()
    ENGINES_DB.write_text(json.dumps(cfg, indent=2)); os.chmod(ENGINES_DB,0o600)

def _docker_status(name):
    try:
        r=subprocess.run(["docker","inspect","-f","{{.State.Status}}",name],capture_output=True,text=True,timeout=8)
        return r.stdout.strip() if r.returncode==0 else "not_installed"
    except Exception as e: return "error: "+str(e)

def _crowdsec_status():
    base={"container":_docker_status("ts-crowdsec"),"bouncer":_docker_status("crowdsec-firewall-bouncer")}
    try:
        r=subprocess.run(["systemctl","is-active","crowdsec-firewall-bouncer"],capture_output=True,text=True,timeout=8)
        base["bouncer_service"]=(r.stdout or r.stderr).strip() or "unknown"
    except Exception as e:
        base["bouncer_service"]="error: "+str(e)
    try:
        r=subprocess.run(["docker","exec","ts-crowdsec","cscli","metrics"],capture_output=True,text=True,timeout=15)
        base["metrics"]=(r.stdout or r.stderr).strip()
    except Exception as e:
        base["metrics"]="error: "+str(e)
    return base

@app.get("/api/security-engines")
def api_security_engines(email: str = Depends(require_auth)):
    cfg=load_engines()
    return {"config":cfg,"status":{"coraza":waf_status(),"crowdsec":_crowdsec_status()}}

@app.post("/api/security-engines")
def api_security_engines_set(email: str = Depends(require_auth), crowdsec_enabled: str = Form("true"), crowdsec_mode: str = Form("detect")):
    if crowdsec_mode not in ("detect","block"):
        crowdsec_mode="detect"
    cfg=load_engines(); cfg["waf"]="coraza"; cfg["crowdsec"]={"enabled": crowdsec_enabled == "true", "mode": crowdsec_mode}
    save_engines(cfg)
    return {"status":"ok","config":cfg,"note":"Coraza/ModSecurity tetap primary WAF. CrowdSec disimpan sebagai extra protection."}

@app.post("/api/security-engines/crowdsec/reload")
def api_security_engines_reload(email: str = Depends(require_auth)):
    out=[]
    for cmd in (["systemctl","restart","crowdsec-firewall-bouncer"],["docker","restart","ts-crowdsec"]):
        try:
            r=subprocess.run(cmd,capture_output=True,text=True,timeout=30)
            out.append({"cmd":" ".join(cmd),"code":r.returncode,"stdout":r.stdout[-400:],"stderr":r.stderr[-400:]})
        except Exception as e:
            out.append({"cmd":" ".join(cmd),"error":str(e)})
    return {"status":"ok","results":out}
