"""Local mock CreativeStall-like target used by integration/e2e tests (no live site dependency)."""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HTML = """<!doctype html><html><head><title>Mock Marketplace</title></head>
<body ng-version="17.0.0"><a href="/search?q=logo&sort=asc">Search</a>
<a href="/asset/1001">Asset</a><a href="/login?returnUrl=/account">Login</a>
<form action="/search"><input name="q"></form>
<script>var api="/api/assets/search";</script></body></html>"""

USERS = {"user-token": {"id": 1, "role": "user"}, "admin-token": {"id": 99, "role": "admin"},
         "user2-token": {"id": 2, "role": "user"}}


class Handler(BaseHTTPRequestHandler):
    server_version = "Microsoft-IIS/10.0"
    hits: dict[str, int] = {}

    def log_message(self, *a):  # silence
        pass

    def _send(self, code=200, body="", ctype="text/html", headers=None):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "ASP.NET")
        origin = self.headers.get("Origin")
        if origin:  # deliberately vulnerable: reflects origin with credentials
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _user(self):
        auth = self.headers.get("Authorization", "")
        return USERS.get(auth.replace("Bearer ", "")) if auth else None

    def do_OPTIONS(self):
        self._send(204, "")

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        p = u.path
        if p == "/":
            return self._send(200, HTML, headers={"Cache-Control": "no-cache"})
        if p == "/robots.txt":
            return self._send(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
        if p == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain")
        if p == "/login":
            ret = q.get("returnUrl", ["/"])[0]
            return self._send(302, "", headers={"Location": ret})
        if p == "/search" or p == "/api/assets/search":
            term = q.get("q", [""])[0]
            sort = q.get("sort", ["asc"])[0]
            if "'" in term or "'" in sort:
                return self._send(500, "System.Data.SqlClient.SqlException: Unclosed quotation mark after the character string",
                                  "text/html")
            if p.startswith("/api"):
                return self._send(200, json.dumps({"results": [{"id": 1001, "title": term}], "total": 1}), "application/json")
            return self._send(200, f"<html><body>Results for {term}</body></html>")  # reflected XSS
        if p.startswith("/api/assets/") and p.endswith("/download"):
            return self._send(200, b"ORIGINALFILEBYTES" * 100, "application/octet-stream")
        if p.startswith("/api/users/"):
            user = self._user()
            if not user:
                return self._send(401, json.dumps({"error": "unauthorized"}), "application/json")
            uid = p.rsplit("/", 1)[-1]
            return self._send(200, json.dumps({"id": int(uid), "email": f"user{uid}@example.com"}), "application/json")  # IDOR
        if p.startswith("/api/admin/"):
            user = self._user()
            if not user:
                return self._send(401, "{}", "application/json")
            return self._send(200, json.dumps({"users": 10}), "application/json")  # broken RBAC
        if p == "/api/me":
            user = self._user()
            return self._send(200 if user else 401, json.dumps(user or {}), "application/json")
        if p.startswith("/asset/"):
            return self._send(200, "<html><img src='/previews/1001.jpg'></html>")
        if p.startswith("/previews/"):
            return self._send(200, b"\xff\xd8JPEG" * 50, "image/jpeg", {"Cache-Control": "public, max-age=86400"})
        return self._send(404, "Not found")

    def do_POST(self):
        u = urlparse(self.path)
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode() if length else ""
        if u.path == "/api/auth/login":
            data = json.loads(body or "{}")
            if data.get("password") == "correct-password":
                return self._send(200, json.dumps({"token": "user-token"}), "application/json",
                                  {"Set-Cookie": "session=abc123; Path=/"})
            if data.get("email") == "known@example.com":
                return self._send(401, json.dumps({"error": "Invalid password"}), "application/json")
            return self._send(401, json.dumps({"error": "User not found"}), "application/json")
        return self._send(404, "")


def start_mock_server(port: int = 0) -> tuple[ThreadingHTTPServer, str]:
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


if __name__ == "__main__":
    s, url = start_mock_server(8765)
    print("Mock site at", url)
    threading.Event().wait()
