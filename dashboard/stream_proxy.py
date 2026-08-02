#!/usr/bin/env python3
import json, os, re, subprocess
from pathlib import Path
from datetime import datetime, timezone
DATA_DIR=Path(os.environ.get('TS_DATA_DIR','/app/data')); DATA_DIR.mkdir(parents=True,exist_ok=True)
DB=DATA_DIR/'streams.json'
STREAM_DIR=Path('/waf/streams.d')
STREAM_CT=os.environ.get('TS_STREAM_CONTAINER','ts-stream')
STREAM_DIR.mkdir(parents=True,exist_ok=True)
def _slug(name): return re.sub(r'[^a-zA-Z0-9_.-]','_',name.strip().lower())
def load_streams():
    if DB.exists():
        try: return json.loads(DB.read_text())
        except Exception: return []
    return []
def save_streams(items):
    DB.write_text(json.dumps(items,indent=2)); os.chmod(DB,0o600)
def render(s):
    proto=s.get('protocol','tcp').lower(); udp = proto=='udp'
    listen=str(int(s['listen_port'])) + (' udp' if udp else '')
    lines=[f"# TurboShield managed stream: {s['name']}", 'server {', f'    listen {listen};', f"    proxy_pass {s['upstream_host']}:{int(s['upstream_port'])};", '    proxy_connect_timeout 10s;', '    proxy_timeout 1h;']
    if udp: lines.append('    proxy_responses 1;')
    lines.append('}'); return '\n'.join(lines)+'\n'
def write_conf(s):
    f=STREAM_DIR/(f"{_slug(s['name'])}.conf"); f.write_text(render(s)); os.chmod(f,0o644)
def remove_conf(name):
    f=STREAM_DIR/(f"{_slug(name)}.conf")
    if f.exists(): f.unlink()
def test_config():
    try:
        r=subprocess.run(['docker','exec',STREAM_CT,'nginx','-t'],capture_output=True,text=True,timeout=20)
        return r.returncode==0,(r.stderr or r.stdout).strip()
    except Exception as e: return False,str(e)
def reload_stream():
    try:
        r=subprocess.run(['docker','exec',STREAM_CT,'nginx','-s','reload'],capture_output=True,text=True,timeout=20)
        return r.returncode==0,(r.stderr or r.stdout).strip()
    except Exception as e: return False,str(e)
def status():
    try:
        r=subprocess.run(['docker','inspect','-f','{{.State.Status}}',STREAM_CT],capture_output=True,text=True,timeout=10)
        return r.stdout.strip() or 'unknown'
    except Exception as e: return 'error: '+str(e)
def validate(name, listen_port, protocol, upstream_host, upstream_port):
    name=name.strip(); protocol=protocol.lower(); upstream_host=upstream_host.strip()
    if not name: raise ValueError('Nama stream wajib diisi.')
    if protocol not in ('tcp','udp'): raise ValueError('Protocol harus tcp/udp.')
    lp=int(listen_port); up=int(upstream_port)
    if not (1 <= lp <= 65535 and 1 <= up <= 65535): raise ValueError('Port harus 1-65535.')
    if lp in (80,443,8181): raise ValueError('Port 80/443/8181 dipakai TurboShield.')
    if not re.match(r'^[a-zA-Z0-9_.:-]+$', upstream_host): raise ValueError('Upstream host tidak valid.')
    return name,lp,protocol,upstream_host,up
