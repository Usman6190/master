"""CSPScanner: parses and grades Content-Security-Policy."""
from __future__ import annotations

from core.models import CheckStatus, Severity
from scanners.base import AuditContext, BaseScanner


def parse_csp(value: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            out[tokens[0].lower()] = tokens[1:]
    return out


class CSPScanner(BaseScanner):
    name = "CSPScanner"
    description = "Evaluates Content-Security-Policy presence and strength."

    def execute(self, ctx: AuditContext) -> None:
        resp = ctx.shared.get("landing_response") or ctx.client.get(ctx.target_url)
        url = resp.url
        csp = resp.headers.get("Content-Security-Policy", "")
        ro = resp.headers.get("Content-Security-Policy-Report-Only", "")
        if not csp:
            self.check("CSP header present", CheckStatus.FAILED, "Report-Only present" if ro else "Missing")
            self.finding("Missing Content-Security-Policy", Severity.MEDIUM, url,
                         "No enforced CSP header is returned" + (" (only Report-Only)." if ro else "."),
                         f"Content-Security-Policy: (absent)\nReport-Only: {ro or '(absent)'}",
                         "XSS vulnerabilities are easier to exploit without a CSP.",
                         "Deploy an enforced CSP with script-src restricted to self/nonces and object-src 'none'.",
                         reproduction_steps=f"curl -sI {url} | grep -i content-security")
            return
        self.check("CSP header present", CheckStatus.PASSED, csp[:300])
        d = parse_csp(csp)
        script = d.get("script-src", d.get("default-src", []))
        issues = []
        if not script:
            issues.append("no script-src or default-src directive")
        if "'unsafe-inline'" in script and not any(t.startswith("'nonce-") or t.startswith("'sha") for t in script):
            issues.append("script-src allows 'unsafe-inline'")
        if "'unsafe-eval'" in script:
            issues.append("script-src allows 'unsafe-eval'")
        if any(t in ("*", "http:", "https:", "data:") for t in script):
            issues.append("script-src allows broad sources (*, http:, https: or data:)")
        if "object-src" not in d and "'none'" not in d.get("default-src", []):
            issues.append("object-src not restricted")
        if "base-uri" not in d:
            issues.append("base-uri not restricted")
        if "frame-ancestors" not in d:
            issues.append("frame-ancestors not defined")
        for issue in issues:
            self.check(f"CSP: {issue}", CheckStatus.FAILED, csp[:300])
        if issues:
            sev = Severity.MEDIUM if any("script-src" in i for i in issues) else Severity.LOW
            self.finding("Weak Content-Security-Policy", sev, url, "The CSP has weaknesses: " + "; ".join(issues) + ".",
                         f"Content-Security-Policy: {csp}", "Weak CSP provides limited protection against XSS/injection.",
                         "Remove unsafe-inline/unsafe-eval, use nonces/hashes, set object-src 'none', base-uri 'self', "
                         "frame-ancestors 'self'.")
        else:
            self.check("CSP strength", CheckStatus.PASSED, "No common weaknesses detected")
