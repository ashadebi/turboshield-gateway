#!/usr/bin/env python3
"""TurboShield — Bot Protection (dipakai app.py).
3 kategori (via User-Agent, phase:1 ModSecurity rule, urutan evaluasi PENTING):
  1) ALLOW  — bot resmi (Googlebot, Bingbot, dst) -> skip rule block/challenge di
     bawahnya (ctl:ruleEngine=Off utk request ini saja, TETAP tercatat access log).
     CATATAN JUJUR: ini verifikasi berbasis User-Agent STRING saja (gampang
     dipalsukan) — bukan verified reverse-DNS/IP-range check (itu butuh
     resolver call per-request yg mahal & belum diimplementasi). Cukup utk niat
     "jangan ganggu SEO crawler", TIDAK cukup sbg security boundary IP allow.
  2) CHALLENGE — bot/tool non-jahat (curl, python-requests, go-http-client,
     scraper generik) -> TIDAK ada CAPTCHA (butuh infra JS-challenge terpisah,
     belum ada). Sebagai gantinya: rate-limit ketat + log kategori 'challenged'
     shg kelihatan di Threat Log, tapi diteruskan (fail-open, tidak blokir keras
     defaultnya) kecuali diaktifkan mode 'block'.
  3) BLOCK — scanner/exploit tool (sqlmap, nikto, nmap, dst) -> 403 langsung,
     ini yang sudah ada sejak awal (turboshield-bad-agents.data).
"""
import os, json, re
from pathlib import Path

DATA_DIR   = Path(os.environ.get("TS_DATA_DIR", "/app/data"))
BOT_DB     = DATA_DIR / "bot_protection.json"
BOT_RULE   = Path("/waf/rules/bot-protection.conf")   # mount -> opt/owasp-crs/rules/zzz2-...

DEFAULT_ALLOW = {
    "google":   {"label": "Googlebot",        "ua": ["Googlebot", "AdsBot-Google", "Mediapartners-Google"], "enabled": True},
    "bing":     {"label": "Bingbot",          "ua": ["bingbot", "BingPreview"], "enabled": True},
    "apple":    {"label": "Applebot",         "ua": ["Applebot"], "enabled": True},
    "facebook": {"label": "Facebook/Meta",    "ua": ["facebookexternalhit", "Facebot"], "enabled": True},
    "telegram": {"label": "Telegram",         "ua": ["TelegramBot"], "enabled": True},
    "slack":    {"label": "Slack",            "ua": ["Slackbot"], "enabled": True},
    "discord":  {"label": "Discord",          "ua": ["Discordbot"], "enabled": True},
}
DEFAULT_CHALLENGE = {
    "unknown_bot": {"label": "Unknown Bot (generik)", "ua": ["bot", "crawler", "spider"], "enabled": True},
    "scraper":     {"label": "Scraper generik",       "ua": ["scrapy", "HttpClient", "libwww-perl"], "enabled": True},
    "python":      {"label": "Python Requests",       "ua": ["python-requests", "python-urllib", "aiohttp"], "enabled": True},
    "curl":        {"label": "curl",                  "ua": ["curl/"], "enabled": True},
    "gohttp":      {"label": "Go-http-client",        "ua": ["Go-http-client"], "enabled": True},
}
DEFAULT_BLOCK = {
    "sqlmap":    {"label": "sqlmap",    "ua": ["sqlmap"], "enabled": True},
    "nikto":     {"label": "nikto",     "ua": ["nikto"], "enabled": True},
    "nmap":      {"label": "nmap",      "ua": ["nmap", "Nmap Scripting Engine"], "enabled": True},
    "wpscan":    {"label": "wpscan",    "ua": ["wpscan"], "enabled": True},
    "dirbuster": {"label": "dirbuster", "ua": ["dirbuster", "gobuster", "feroxbuster"], "enabled": True},
    "masscan":   {"label": "masscan",   "ua": ["masscan"], "enabled": True},
    "havij":     {"label": "havij",     "ua": ["havij"], "enabled": True},
    "acunetix":  {"label": "acunetix",  "ua": ["acunetix"], "enabled": True},
    "nessus":    {"label": "nessus",    "ua": ["nessus"], "enabled": True},
}

def _defaults():
    return {"allow": DEFAULT_ALLOW, "challenge": DEFAULT_CHALLENGE, "block": DEFAULT_BLOCK,
            "challenge_mode": "log"}   # "log" (fail-open, tercatat saja) | "block" (403 juga)

def load_config():
    if BOT_DB.exists():
        try:
            cfg = json.loads(BOT_DB.read_text())
            base = _defaults()
            for section in ("allow", "challenge", "block"):
                base[section].update(cfg.get(section, {}))
            base["challenge_mode"] = cfg.get("challenge_mode", "log")
            return base
        except Exception:
            pass
    return _defaults()

def save_config(cfg):
    BOT_DB.write_text(json.dumps(cfg, indent=2)); os.chmod(BOT_DB, 0o644)

def _pm_pattern(ua_list):
    # ModSecurity @pm butuh token dipisah spasi; escape tanda kutip ganda
    return " ".join(t.replace('"', '') for t in ua_list)

def regenerate_rule_file():
    """Generate 1 file ModSecurity utk 3 kategori. Urutan EVALUASI penting:
    ALLOW dicek duluan (skip semua rule berikutnya utk request ini), lalu BLOCK
    (403 keras), lalu CHALLENGE (log selalu; 403 juga jika challenge_mode=block).
    ID range 90400-90499 (tak bentrok dgn turboshield-custom.conf 90000-90300an).
    """
    cfg = load_config()
    lines = ["# TurboShield — Bot Protection (auto-generated, jangan edit manual)\n"]

    allow_ua = [t for e in cfg["allow"].values() if e.get("enabled") for t in e["ua"]]
    if allow_ua:
        # tiap kategori allow: kalau UA cocok, skip ke SecMarker TS_BOT_END
        # (lewati semua rule block/challenge di bawah untuk request ini)
        idx = 90401
        for key, e in cfg["allow"].items():
            if not e.get("enabled"): continue
            pat = _pm_pattern(e["ua"])
            lines.append(
                f'SecRule REQUEST_HEADERS:User-Agent "@pm {pat}" '
                f'"id:{idx},phase:1,pass,nolog,tag:\'turboshield/bot-allow/{key}\',skipAfter:TS_BOT_END"\n'
            )
            idx += 1

    idx = 90410
    for key, e in cfg["block"].items():
        if not e.get("enabled"): continue
        pat = _pm_pattern(e["ua"])
        lines.append(
            f'SecRule REQUEST_HEADERS:User-Agent "@pm {pat}" '
            f'"id:{idx},phase:1,deny,status:403,log,msg:\'TurboShield Bot-Block: {key}\',tag:\'turboshield/bot-block/{key}\'"\n'
        )
        idx += 1

    idx = 90440
    challenge_deny = cfg.get("challenge_mode", "log") == "block"
    for key, e in cfg["challenge"].items():
        if not e.get("enabled"): continue
        pat = _pm_pattern(e["ua"])
        if challenge_deny:
            lines.append(
                f'SecRule REQUEST_HEADERS:User-Agent "@pm {pat}" '
                f'"id:{idx},phase:1,deny,status:403,log,msg:\'TurboShield Bot-Challenge(block): {key}\',tag:\'turboshield/bot-challenge/{key}\'"\n'
            )
        else:
            lines.append(
                f'SecRule REQUEST_HEADERS:User-Agent "@pm {pat}" '
                f'"id:{idx},phase:1,pass,log,msg:\'TurboShield Bot-Challenge(log): {key}\',tag:\'turboshield/bot-challenge/{key}\'"\n'
            )
        idx += 1

    lines.append('SecMarker "TS_BOT_END"\n')
    BOT_RULE.write_text("".join(lines))
    try: os.chmod(BOT_RULE, 0o644)
    except Exception: pass
