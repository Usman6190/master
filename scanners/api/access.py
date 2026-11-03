"""APISecurityScanner, RBACScanner, IDORTester, RateLimitTester (read-only requests only)."""
from __future__ import annotations

import re
import statistics

from core.models import Category, CheckStatus, Severity, VerificationStatus
from scanners.api.common import api_url, auth_headers, get_token, lines, load_openapi_paths
from scanners.base import AuditContext, BaseScanner

_PII_RE = re.compile(r'"(email|phone|address|password|passwordHash|ssn|dob|creditCard)"\s*:', re.I)


class APISecurityScanner(BaseScanner):
    name = "APISecurityScanner"
    category = Category.API_SECURITY
    description = "Unauthenticated access to protected endpoints, verbose API errors, excessive data exposure, OpenAPI exposure."
    requires = ("api_base_url",)

    def execute(self, ctx: AuditContext) -> None:
        protected = lines(ctx.config.get("protected_endpoints"))
        spec_paths = [p for m, p in load_openapi_paths(ctx) if m == "GET" and "{" not in p]
        if ctx.config.get("openapi_url"):
            self.check("OpenAPI import", CheckStatus.PASSED if spec_paths else CheckStatus.FAILED,
                       f"{len(load_openapi_paths(ctx))} operations imported")
        if not protected and not spec_paths:
            self.check("Protected endpoints require authentication", CheckStatus.NOT_TESTED,
                       "No protected_endpoints or OpenAPI document configured")
        for path in protected:
            url = api_url(ctx, path)
            r = ctx.client.get(url, allow_redirects=False)
            if r.status_code in (401, 403) or (r.status_code in (301, 302) and "login" in r.headers.get("Location", "").lower()):
                self.check(f"Unauthenticated access blocked: {path}", CheckStatus.PASSED, f"HTTP {r.status_code}")
            elif r.status_code == 200:
                self.check(f"Unauthenticated access blocked: {path}", CheckStatus.FAILED, f"HTTP 200, {len(r.content)} bytes")
                self.finding("Protected API endpoint accessible without authentication", Severity.HIGH, url,
                             f"The endpoint configured as protected ({path}) returned data without a token.",
                             f"GET {url} (no Authorization) -> 200: {r.text[:200]}",
                             "Unauthenticated users can access protected marketplace data or functions.",
                             "Enforce [Authorize] / authentication middleware on every non-public endpoint.",
                             reproduction_steps=f"curl -s {url}")
            else:
                self.check(f"Unauthenticated access blocked: {path}", CheckStatus.MANUAL, f"HTTP {r.status_code}")
        self._spec_exposure(ctx)
        self._verbose_errors(ctx)
        self._data_exposure(ctx)

    def _spec_exposure(self, ctx):
        for path in ("swagger/v1/swagger.json", "swagger/index.html", "openapi.json", "api-docs"):
            url = api_url(ctx, path)
            try:
                r = ctx.client.get(url, allow_redirects=False)
            except Exception:  # noqa: BLE001
                continue
            if r.status_code == 200 and ("swagger" in r.text.lower() or '"openapi"' in r.text):
                self.check("API documentation not publicly exposed", CheckStatus.FAILED, url)
                self.finding("Public API documentation (Swagger/OpenAPI)", Severity.LOW, url,
                             "The API specification is publicly reachable in this environment.", f"GET {url} -> 200",
                             "Speeds up attacker enumeration of endpoints and parameters.",
                             "Disable Swagger UI/spec in production or protect it with authentication.")
                return
        self.check("API documentation not publicly exposed", CheckStatus.PASSED, "No public Swagger/OpenAPI found")

    def _verbose_errors(self, ctx):
        url = api_url(ctx, "csab-probe-nonexistent/%27%22")
        r = ctx.client.get(url, allow_redirects=False)
        markers = [m for m in ("at System.", "at Microsoft.", "StackTrace", "SqlException", "NullReferenceException",
                               "   at ", "Exception:") if m in r.text]
        if markers:
            self.check("API errors do not leak stack traces", CheckStatus.FAILED, ", ".join(markers))
            self.finding("Verbose API error / stack trace disclosure", Severity.MEDIUM, url,
                         "An API error response contains .NET exception details.", r.text[:400],
                         "Discloses internal code paths, libraries and potentially SQL structure.",
                         "Use ProblemDetails with generic messages in production; disable DeveloperExceptionPage.")
        else:
            self.check("API errors do not leak stack traces", CheckStatus.PASSED, f"HTTP {r.status_code}")

    def _data_exposure(self, ctx):
        endpoints = lines(ctx.config.get("public_api_endpoints")) or ctx.shared.get("api_paths", [])[:5]
        if not endpoints:
            self.check("Excessive data exposure in public API responses", CheckStatus.NOT_TESTED, "No public endpoints known")
            return
        hits = []
        for path in endpoints[:5]:
            url = api_url(ctx, path)
            try:
                r = ctx.client.get(url)
            except Exception:  # noqa: BLE001
                continue
            if "json" in r.headers.get("Content-Type", "") and _PII_RE.search(r.text):
                hits.append((url, _PII_RE.findall(r.text)[:5]))
        if hits:
            self.check("Excessive data exposure in public API responses", CheckStatus.FAILED, str(hits))
            for url, fields in hits:
                self.finding("Sensitive fields in public API response", Severity.MEDIUM, url,
                             "An unauthenticated API response includes fields commonly considered sensitive.",
                             f"Fields: {sorted(set(fields))}", "May expose user PII (OWASP API3: Broken Object Property Level Authorization).",
                             "Return DTOs containing only fields required by the client.",
                             verification_status=VerificationStatus.UNVERIFIED)
        else:
            self.check("Excessive data exposure in public API responses", CheckStatus.PASSED,
                       f"{len(endpoints[:5])} endpoints inspected")


class RBACScanner(BaseScanner):
    name = "RBACScanner"
    category = Category.API_SECURITY
    description = "Checks that a low-privilege test account cannot reach admin/contributor-only endpoints (GET only)."
    requires = ("admin_endpoints",)

    def execute(self, ctx: AuditContext) -> None:
        tok = get_token(ctx)
        if not tok:
            self.check("Low-privilege user blocked from admin endpoints", CheckStatus.NOT_TESTED,
                       "Requires a low-privilege test account token (api_token or login credentials)")
            return
        for path in lines(ctx.config.get("admin_endpoints")):
            url = api_url(ctx, path)
            r = ctx.client.get(url, headers=auth_headers(tok), allow_redirects=False)
            label = f"Low-privilege user blocked: {path}"
            if r.status_code in (401, 403, 404):
                self.check(label, CheckStatus.PASSED, f"HTTP {r.status_code}")
            elif r.status_code == 200:
                self.check(label, CheckStatus.FAILED, f"HTTP 200, {len(r.content)} bytes")
                self.finding("Broken function-level authorization (RBAC)", Severity.HIGH, url,
                             "A low-privilege test account received HTTP 200 from an admin-only endpoint.",
                             f"GET {url} with low-privilege token -> 200: {r.text[:200]}",
                             "Regular users may perform administrative actions or view admin data (OWASP API5).",
                             "Enforce role/policy-based authorization ([Authorize(Roles=...)]) server-side.",
                             verification_status=VerificationStatus.UNVERIFIED,
                             reproduction_steps="Log in as the low-privilege test user and request the endpoint.")
            else:
                self.check(label, CheckStatus.MANUAL, f"HTTP {r.status_code}")


class IDORTester(BaseScanner):
    name = "IDORTester"
    category = Category.API_SECURITY
    description = "Requests another user's object with the test account token (read-only GET)."
    requires = ("idor_endpoint_template", "idor_other_id")

    def execute(self, ctx: AuditContext) -> None:
        tok = get_token(ctx)
        if not tok:
            self.check("Object-level authorization (IDOR)", CheckStatus.NOT_TESTED, "No test account token")
            return
        for template in lines(ctx.config.get("idor_endpoint_template")):
            own = ctx.config.get("idor_own_id")
            other = str(ctx.config["idor_other_id"])
            other_url = api_url(ctx, template.replace("{id}", other))
            r_other = ctx.client.get(other_url, headers=auth_headers(tok))
            own_status = None
            if own:
                own_status = ctx.client.get(api_url(ctx, template.replace("{id}", str(own))), headers=auth_headers(tok)).status_code
            label = f"IDOR: {template}"
            if r_other.status_code == 200 and r_other.content:
                self.check(label, CheckStatus.FAILED, f"other id {other} -> 200")
                self.finding("Insecure Direct Object Reference (IDOR)", Severity.HIGH, other_url,
                             "The test account could read an object belonging to a different user by changing the ID.",
                             f"GET {other_url} as test user -> 200 ({len(r_other.content)} bytes); own-object status: {own_status}\n"
                             f"Body preview: {r_other.text[:150]}",
                             "Attackers can enumerate IDs to access other users' data, purchases or original assets (OWASP API1).",
                             "Check resource ownership on every object access; prefer non-sequential identifiers.",
                             verification_status=VerificationStatus.UNVERIFIED,
                             reproduction_steps=f"Authenticate as test user; GET {template} with id={other}.")
            elif r_other.status_code in (401, 403, 404):
                self.check(label, CheckStatus.PASSED, f"other id {other} -> HTTP {r_other.status_code}")
            else:
                self.check(label, CheckStatus.MANUAL, f"other id {other} -> HTTP {r_other.status_code}")


class RateLimitTester(BaseScanner):
    name = "RateLimitTester"
    category = Category.API_SECURITY
    description = "Small, bounded burst against search/API endpoint to observe throttling (default 20 requests)."

    def execute(self, ctx: AuditContext) -> None:
        endpoint = ctx.config.get("search_endpoint") or "/api/assets/search?q=logo"
        url = api_url(ctx, endpoint)
        burst = max(5, min(int(ctx.config.get("rate_limit_burst", 20)), 60))
        codes, times = [], []
        saved = ctx.client.min_interval
        ctx.client.min_interval = 0.0
        try:
            for _ in range(burst):
                r = ctx.client.get(url)
                codes.append(r.status_code)
                times.append(r.elapsed.total_seconds() * 1000)
                if r.status_code == 429:
                    break
        finally:
            ctx.client.min_interval = saved
        throttled = 429 in codes
        headers = {k: v for k, v in r.headers.items() if "ratelimit" in k.lower() or k.lower() == "retry-after"}
        self.metric("Burst size", len(codes))
        self.metric("Burst median latency", round(statistics.median(times), 1), "ms")
        evidence = f"{len(codes)} rapid GETs to {url}: codes={sorted(set(codes))}; rate-limit headers={headers or 'none'}"
        if throttled or headers:
            self.check("API rate limiting observed", CheckStatus.PASSED, evidence)
        else:
            self.check("API rate limiting observed", CheckStatus.FAILED, evidence)
            self.finding("No API rate limiting observed on search endpoint", Severity.MEDIUM, url,
                         f"{len(codes)} rapid requests completed without HTTP 429 or rate-limit headers.", evidence,
                         "Search API abuse, scraping of 3.5M-asset catalogue and resource exhaustion (OWASP API4).",
                         "Apply per-IP/per-token rate limits (e.g. ASP.NET RateLimiter / CDN WAF rules) with 429 + Retry-After.",
                         verification_status=VerificationStatus.UNVERIFIED,
                         reproduction_steps=f"Send {burst} requests in quick succession to {url}.")
