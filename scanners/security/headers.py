"""SecurityHeadersScanner: HTTPS/redirects, security headers, information disclosure."""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlunparse

import requests

from core.models import CheckStatus, Severity, VerificationStatus
from scanners.base import AuditContext, BaseScanner

OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"


class SecurityHeadersScanner(BaseScanner):
    name = "SecurityHeadersScanner"
    description = "HTTPS availability, HTTP->HTTPS redirect, HSTS, XCTO, framing, Referrer/Permissions policy, disclosure."

    def execute(self, ctx: AuditContext) -> None:
        url = ctx.target_url
        resp = ctx.shared.get("landing_response") or ctx.client.get(url)
        h = {k.lower(): v for k, v in resp.headers.items()}
        final = resp.url

        # HTTPS availability
        if urlparse(final).scheme == "https":
            self.check("HTTPS available", CheckStatus.PASSED, final)
        else:
            self.check("HTTPS available", CheckStatus.FAILED, final)
            self.finding("Site not served over HTTPS", Severity.HIGH, final, "The final landing URL is not HTTPS.",
                         f"Final URL: {final}", "Traffic, sessions and credentials can be intercepted.",
                         "Serve all content over HTTPS and redirect HTTP to HTTPS.")

        self._http_redirect(ctx, url)
        self._hsts(h, final)
        self._simple_header(h, final, "x-content-type-options", lambda v: v.lower() == "nosniff",
                            "X-Content-Type-Options", Severity.LOW, "Set 'X-Content-Type-Options: nosniff'.",
                            "Browsers may MIME-sniff responses, enabling content-type confusion attacks.")
        self._framing(h, final)
        self._simple_header(h, final, "referrer-policy",
                            lambda v: v.lower() in {"no-referrer", "same-origin", "strict-origin",
                                                    "strict-origin-when-cross-origin", "no-referrer-when-downgrade", "origin",
                                                    "origin-when-cross-origin"} or "," in v,
                            "Referrer-Policy", Severity.LOW, "Set 'Referrer-Policy: strict-origin-when-cross-origin'.",
                            "Full URLs (possibly containing tokens or asset identifiers) may leak to third parties.")
        self._simple_header(h, final, "permissions-policy", lambda v: bool(v.strip()), "Permissions-Policy",
                            Severity.LOW, "Define a Permissions-Policy restricting camera, microphone, geolocation, etc.",
                            "Embedded third-party content can request powerful browser features.")
        self._disclosure(h, final, resp.text)

    def _http_redirect(self, ctx: AuditContext, url: str) -> None:
        p = urlparse(url)
        http_url = urlunparse(("http", p.netloc, p.path or "/", "", "", ""))
        try:
            r = ctx.client.get(http_url, allow_redirects=False)
        except requests.RequestException as exc:
            self.check("HTTP to HTTPS redirect", CheckStatus.NOT_TESTED, f"HTTP endpoint unreachable: {exc}")
            return
        loc = r.headers.get("Location", "")
        if r.status_code in (301, 302, 307, 308) and loc.startswith("https://"):
            status = CheckStatus.PASSED
            detail = f"HTTP {r.status_code} -> {loc}"
            if r.status_code in (302, 307):
                detail += " (temporary redirect; prefer 301/308)"
            self.check("HTTP to HTTPS redirect", status, detail)
        else:
            self.check("HTTP to HTTPS redirect", CheckStatus.FAILED, f"HTTP {r.status_code} Location={loc or '-'}")
            self.finding("HTTP does not redirect to HTTPS", Severity.MEDIUM, http_url,
                         "Plain HTTP requests are not redirected to HTTPS.",
                         f"GET {http_url} -> HTTP {r.status_code}, Location: {loc or '(none)'}",
                         "Users following http:// links may transmit data in cleartext.",
                         "Return a 301/308 redirect from every HTTP URL to its HTTPS equivalent.",
                         reproduction_steps=f"curl -I {http_url}")

    def _hsts(self, h: dict, url: str) -> None:
        v = h.get("strict-transport-security")
        if not v:
            self.check("HSTS header", CheckStatus.FAILED, "Missing")
            self.finding("Missing HTTP Strict-Transport-Security header", Severity.MEDIUM, url,
                         "The response does not include an HSTS header.", "Strict-Transport-Security: (absent)",
                         "Users are exposed to SSL-stripping attacks on first visit or after redirects.",
                         "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' (consider preload).",
                         reproduction_steps=f"curl -sI {url} | grep -i strict-transport", references=OWASP_HEADERS)
            return
        m = re.search(r"max-age=(\d+)", v)
        age = int(m.group(1)) if m else 0
        if age < 15552000:
            self.check("HSTS header", CheckStatus.FAILED, f"max-age too low: {v}")
            self.finding("HSTS max-age is too short", Severity.LOW, url, "HSTS is present but max-age < 180 days.",
                         f"Strict-Transport-Security: {v}", "Protection lapses quickly between visits.",
                         "Use max-age of at least 31536000 (1 year).")
        else:
            self.check("HSTS header", CheckStatus.PASSED, v)

    def _simple_header(self, h, url, key, ok, label, sev, fix, impact):
        v = h.get(key)
        if v is not None and ok(v):
            self.check(f"{label} header", CheckStatus.PASSED, v)
            return
        self.check(f"{label} header", CheckStatus.FAILED, v or "Missing")
        self.finding(f"{'Weak' if v else 'Missing'} {label} header", sev, url,
                     f"The {label} response header is {'misconfigured' if v else 'not set'}.",
                     f"{label}: {v or '(absent)'}", impact, fix,
                     reproduction_steps=f"curl -sI {url} | grep -i {key}", references=OWASP_HEADERS)

    def _framing(self, h, url):
        xfo = h.get("x-frame-options", "")
        csp = h.get("content-security-policy", "")
        if xfo.upper() in ("DENY", "SAMEORIGIN") or "frame-ancestors" in csp.lower():
            self.check("Clickjacking / frame protection", CheckStatus.PASSED, xfo or "CSP frame-ancestors")
            return
        self.check("Clickjacking / frame protection", CheckStatus.FAILED, xfo or "Missing")
        self.finding("Missing clickjacking protection", Severity.MEDIUM, url,
                     "Neither X-Frame-Options nor CSP frame-ancestors restricts framing.",
                     f"X-Frame-Options: {xfo or '(absent)'}; CSP frame-ancestors: (absent)",
                     "The site may be embedded in a malicious frame to trick users into unintended actions.",
                     "Set 'Content-Security-Policy: frame-ancestors 'self'' and 'X-Frame-Options: DENY'.")

    def _disclosure(self, h, url, body):
        leaks = []
        for key in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-sourcefiles"):
            v = h.get(key)
            if v and (key != "server" or re.search(r"\d", v)):
                leaks.append(f"{key}: {v}")
        if leaks:
            self.check("Server information disclosure", CheckStatus.FAILED, "; ".join(leaks))
            self.finding("Server/technology version disclosure", Severity.LOW, url,
                         "Response headers reveal server software or framework versions.", "\n".join(leaks),
                         "Helps attackers fingerprint the stack and target known vulnerabilities.",
                         "Remove or genericize Server, X-Powered-By and X-AspNet-Version headers.")
        else:
            self.check("Server information disclosure", CheckStatus.PASSED, h.get("server", "no version info"))
        debug_markers = ["stack trace", "exception details", "yellow screen of death", "at system.", "debug=true",
                         "developer exception page"]
        hits = [m for m in debug_markers if m in body.lower()]
        if hits:
            self.check("Debug information leakage", CheckStatus.MANUAL, ", ".join(hits))
            self.finding("Possible debug information in response", Severity.MANUAL, url,
                         "The landing page contains strings commonly associated with debug output.",
                         f"Markers: {', '.join(hits)}", "Debug output may disclose internals.",
                         "Verify manually and disable debug/developer exception pages in production.",
                         verification_status=VerificationStatus.UNVERIFIED)
        else:
            self.check("Debug information leakage", CheckStatus.PASSED, "No debug markers on landing page")
