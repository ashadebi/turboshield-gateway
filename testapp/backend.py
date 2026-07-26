#!/usr/bin/env python3
"""TurboShield test backend — stdlib only. Melayani halaman test + endpoint /search & /login.
Backend ini SENGAJA 'polos' (tak punya proteksi) supaya WAF di depannya yang jadi perisai.
Kalau payload serangan sampai ke sini, artinya WAF bocor."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

with open("/app/index.html", "rb") as f:
    INDEX = f.read()

class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str): body = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a): pass  # senyap

    def do_GET(self):
        u = urlparse(self.path)
        if u.path in ("/", "/index.html"):
            return self._send(200, INDEX, "text/html; charset=utf-8")
        if u.path == "/health":
            return self._send(200, json.dumps({"status": "healthy", "service": "turboshield-testapp"}))
        if u.path == "/search":
            q = parse_qs(u.query)
            term = q.get("q", [""])[0]
            return self._send(200, json.dumps({
                "status": "ok", "message": "Pencarian diproses backend (request lolos WAF)",
                "query": term, "results": [f"Hasil untuk '{term}' #{i}" for i in range(1, 4)]
            }))
        return self._send(404, json.dumps({"status": "not_found", "path": u.path}))

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        if u.path == "/login":
            data = parse_qs(raw)
            user = data.get("username", [""])[0]
            return self._send(200, json.dumps({
                "status": "ok", "message": "Login diproses backend (request lolos WAF)",
                "user": user, "note": "Ini backend demo — tidak memvalidasi kredensial sungguhan."
            }))
        return self._send(404, json.dumps({"status": "not_found", "path": u.path}))

if __name__ == "__main__":
    print("TurboShield test backend listening on :8080", flush=True)
    ThreadingHTTPServer(("0.0.0.0", 8080), H).serve_forever()
