#!/usr/bin/env python3
"""TurboShield Gateway — Dashboard backend (FastAPI).
Menyediakan: setup wizard (first-run), login/session, system health, threat feed
(dari ModSecurity audit log), dan kontrol WAF (engine mode, anomaly threshold, custom rules).
"""
import os, json, secrets, hashlib, time, subprocess, re
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
    if load_admin() is None:
        return HTMLResponse(Path("/app/static/setup.html").read_text())
    if valid_session(request.cookies.get("ts_session")):
        return HTMLResponse(Path("/app/static/dashboard.html").read_text())
    return HTMLResponse(Path("/app/static/login.html").read_text())

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
                   ssl_enabled: str = Form("false"), custom_config: str = Form(""),
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
    rec.setdefault("ssl", {})
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
    hosts = [h for h in PX.load_hosts() if h["domain"] != domain.strip().lower()]
    PX.save_hosts(hosts)
    PX.remove_host_conf(domain)
    ok, msg = PX.waf_reload()
    return {"status": "ok", "reload_msg": msg}

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
