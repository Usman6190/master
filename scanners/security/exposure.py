"""PublicExposureScanner: sensitive files, directory listing, open redirects (read-only GETs)."""
from __future__ import annotations

from urllib.parse import urljoin

from core.models import CheckStatus, Severity
from scanners.base import AuditContext, BaseScanner

# (path, content signature that confirms the file, severity)
SENSITIVE_PATHS = [
    (".env", ("APP_KEY=", "DB_PASSWORD", "SECRET", "CONNECTIONSTRING"), Severity.CRITICAL),
    (".git/HEAD", ("ref: refs/",), Severity.HIGH),
    (".git/config", ("[core]",), Severity.HIGH),
    ("web.config", ("<configuration",), Severity.HIGH),
    ("appsettings.json", ('"ConnectionStrings"', '"Logging"'), Severity.HIGH),
    ("appsettings.Development.json", ('"ConnectionStrings"', '"Logging"'), Severity.HIGH),
    (".DS_Store", ("Bud1",), Severity.LOW),
    ("backup.zip", ("PK",), Severity.HIGH),
    ("backup.sql", ("CREATE TABLE", "INSERT INTO"), Severity.CRITICAL),
    ("phpinfo.php", ("phpinfo()", "PHP Version"), Severity.MEDIUM),
    ("server-status", ("Apache Server Status",), Severity.MEDIUM),
    ("elmah.axd", ("Error Log for",), Severity.HIGH),
    ("trace.axd", ("Application Trace",), Severity.HIGH),
    ("swagger/index.html", ("swagger-ui",), Severity.INFO),
    ("swagger/v1/swagger.json", ('"openapi"', '"swagger"'), Severity.INFO),
    ("crossdomain.xml", ('domain="*"',), Severity.LOW),
    ("main.js.map", ('"sources"',), Severity.LOW),
]
REDIRECT_PARAMS = ("returnUrl", "redirect", "next", "url", "return", "redirect_uri")
PROBE_HOST = "redirect-audit-probe.example"


class PublicExposureScanner(BaseScanner):
    name = "PublicExposureScanner"
    description = "Looks for publicly exposed sensitive files, directory listing and open redirects."

    def execute(self, ctx: AuditContext) -> None:
        base = ctx.target_url
        soft404 = self._soft404_signature(ctx, base)
        for path, sigs, sev in SENSITIVE_PATHS:
            url = urljoin(base, path)
            try:
                r = ctx.client.get(url, allow_redirects=False)
            except Exception as exc:  # noqa: BLE001
                self.check(f"Exposure: /{path}", CheckStatus.ERROR, str(exc))
                continue
            body = r.text[:5000] if r.status_code == 200 else ""
            confirmed = r.status_code == 200 and any(s.lower() in body.lower() for s in sigs) and body[:200] != soft404
            if confirmed:
                self.check(f"Exposure: /{path}", CheckStatus.FAILED if sev != Severity.INFO else CheckStatus.PASSED,
                           "HTTP 200, signature matched")
                title = "API documentation publicly accessible" if sev == Severity.INFO else f"Sensitive file exposed: /{path}"
                self.finding(title, sev, url, f"/{path} is publicly retrievable and matches a content signature.",
                             f"GET {url} -> 200; first bytes: {body[:120]!r}",
                             "Exposed configuration/source may reveal secrets or internal structure."
                             if sev != Severity.INFO else "Attackers can enumerate API endpoints quickly.",
                             f"Block public access to /{path} at the web server/CDN and rotate any exposed secrets.",
                             reproduction_steps=f"curl -s {url} | head")
            else:
                self.check(f"Exposure: /{path}", CheckStatus.PASSED, f"HTTP {r.status_code}")
        self._directory_listing(ctx, base)
        self._open_redirect(ctx, base)

    def _soft404_signature(self, ctx, base) -> str:
        try:
            r = ctx.client.get(urljoin(base, "csab-nonexistent-8f3a2c.txt"), allow_redirects=False)
            return r.text[:200] if r.status_code == 200 else "\0"
        except Exception:  # noqa: BLE001
            return "\0"

    def _directory_listing(self, ctx, base):
        hit = None
        for path in ("assets/", "uploads/", "images/", "files/", "static/", "content/"):
            try:
                r = ctx.client.get(urljoin(base, path), allow_redirects=False)
            except Exception:  # noqa: BLE001
                continue
            if r.status_code == 200 and ("Index of /" in r.text or "[To Parent Directory]" in r.text):
                hit = urljoin(base, path)
                break
        if hit:
            self.check("Directory listing disabled", CheckStatus.FAILED, hit)
            self.finding("Directory listing enabled", Severity.MEDIUM, hit, "The server returns a browsable directory index.",
                         f"GET {hit} -> directory index page", "Allows enumeration and download of files, incl. assets.",
                         "Disable directory browsing on the web server and storage origin.")
        else:
            self.check("Directory listing disabled", CheckStatus.PASSED, "No directory index on common paths")

    def _open_redirect(self, ctx, base):
        candidates = [u for u, p in ctx.shared.get("query_params", []) if p.lower() in {x.lower() for x in REDIRECT_PARAMS}]
        paths = candidates[:5] or [urljoin(base, "account/login"), urljoin(base, "login")]
        found = False
        for page in paths:
            for param in REDIRECT_PARAMS:
                url = f"{page}?{param}=https://{PROBE_HOST}/"
                try:
                    r = ctx.client.get(url, allow_redirects=False)
                except Exception:  # noqa: BLE001
                    continue
                loc = r.headers.get("Location", "")
                if r.status_code in (301, 302, 303, 307, 308) and PROBE_HOST in loc:
                    found = True
                    self.finding("Open redirect", Severity.MEDIUM, url,
                                 f"The '{param}' parameter redirects to arbitrary external hosts.",
                                 f"GET {url} -> {r.status_code} Location: {loc}",
                                 "Enables convincing phishing links and OAuth token theft chains.",
                                 "Only allow relative redirect targets or an allow-list of hosts.",
                                 reproduction_steps=f"curl -sI '{url}'")
                    break
            if found:
                break
        self.check("Open redirect", CheckStatus.FAILED if found else CheckStatus.PASSED,
                   "Probed: " + ", ".join(paths[:3]))
        if not candidates:
            self.check("Open redirect (discovered params)", CheckStatus.MANUAL,
                       "No redirect-style parameters discovered; verify login/OAuth return URLs manually.")
