"""InjectionScanner (SQLi indicators) and XSSScanner (reflected + optional DOM via Playwright).

Payloads are non-destructive: quote characters and boolean comparisons only. No UNION/stacked/time-based queries,
no data extraction or modification.
"""
from __future__ import annotations

import re
import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.models import CheckStatus, Severity, VerificationStatus
from scanners.api.common import api_url, lines
from scanners.base import AuditContext, BaseScanner

SQL_ERRORS = re.compile(
    r"(SqlException|Unclosed quotation mark|Incorrect syntax near|quoted string not properly terminated|"
    r"SQL syntax.*MySQL|PG::SyntaxError|ORA-\d{5}|SQLite3::|System\.Data\.SqlClient|Microsoft OLE DB|"
    r"ODBC SQL Server Driver|conversion failed when converting|FREETEXT|full-text)", re.I)
SORT_PARAMS = {"sort", "orderby", "order", "sortby", "sortorder", "dir"}


def _with_param(url: str, name: str, value: str) -> str:
    p = urlparse(url)
    q = dict(parse_qsl(p.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


def targets(ctx: AuditContext, limit: int = 15) -> list[tuple[str, str, str]]:
    """(base_url, param, baseline_value) tuples from discovery + configured endpoints."""
    out = []
    for base, param in ctx.shared.get("query_params", []):
        out.append((base, param, "test"))
    for ep in lines(ctx.config.get("injection_endpoints")):
        url = api_url(ctx, ep)
        for k, v in parse_qsl(urlparse(url).query, keep_blank_values=True):
            out.append((url.split("?")[0], k, v or "test"))
    if not out and ctx.config.get("search_endpoint"):
        url = api_url(ctx, ctx.config["search_endpoint"])
        for k, v in parse_qsl(urlparse(url).query):
            out.append((url.split("?")[0], k, v))
    return list(dict.fromkeys(out))[:limit]


class InjectionScanner(BaseScanner):
    name = "InjectionScanner"
    description = "Error-based and boolean-differential SQL injection indicators on search/sort/filter/pagination params."

    def execute(self, ctx: AuditContext) -> None:
        tgts = targets(ctx, int(ctx.config.get("injection_max_params", 15)))
        if not tgts:
            self.check("SQL injection indicators", CheckStatus.NOT_TESTED,
                       "No parameters discovered; configure 'injection_endpoints' (e.g. /api/assets/search?q=logo&page=1)")
            return
        for base, param, val in tgts:
            label = f"SQLi indicators: {param} @ {urlparse(base).path}"
            try:
                base_r = ctx.client.get(_with_param(base, param, val))
                hit = None
                for payload in ("'", "\"", "')", "1'--"):
                    u = _with_param(base, param, val + payload)
                    r = ctx.client.get(u)
                    m = SQL_ERRORS.search(r.text)
                    if m and not SQL_ERRORS.search(base_r.text):
                        hit = (u, r, m.group(0), payload)
                        break
                if hit:
                    u, r, marker, payload = hit
                    self.check(label, CheckStatus.FAILED, f"DB error on payload {payload!r}")
                    self.finding("SQL injection indicator (database error triggered)", Severity.HIGH, u,
                                 f"Adding {payload!r} to parameter '{param}' produced a database error message; "
                                 f"baseline request did not.",
                                 f"Baseline HTTP {base_r.status_code}; payload HTTP {r.status_code}; marker: {marker}\n"
                                 f"Response excerpt: {r.text[:300]}",
                                 "Unsanitized input reaches SQL (e.g. FREETEXT stored procedure / dynamic ORDER BY). "
                                 "May allow data extraction. Exploitability not confirmed (non-destructive test).",
                                 "Use parameterized queries/stored-procedure parameters; whitelist sort columns; "
                                 "return generic errors.", verification_status=VerificationStatus.UNVERIFIED,
                                 reproduction_steps=f"GET {u}")
                    continue
                if param.lower() in SORT_PARAMS or param.lower() in ("page", "pagesize", "limit", "offset", "id"):
                    t = ctx.client.get(_with_param(base, param, f"{val} AND 1=1" if not val.isdigit() else f"{val}-0"))
                    f_ = ctx.client.get(_with_param(base, param, f"{val} AND 1=2" if not val.isdigit() else f"{val}-{val}"))
                    if t.status_code == base_r.status_code == 200 and abs(len(t.content) - len(base_r.content)) < 20 \
                            and abs(len(f_.content) - len(base_r.content)) > max(200, len(base_r.content) * 0.3):
                        self.check(label, CheckStatus.MANUAL, "Boolean differential observed")
                        self.finding("Possible boolean-based SQL injection", Severity.MANUAL, base,
                                     f"Parameter '{param}' responses differ between true/false conditions.",
                                     f"baseline={len(base_r.content)}B true={len(t.content)}B false={len(f_.content)}B",
                                     "Could indicate SQL injection; may also be normal parsing behaviour.",
                                     "Manually verify with a DBA in staging; use parameterized queries.",
                                     verification_status=VerificationStatus.UNVERIFIED)
                        continue
                self.check(label, CheckStatus.PASSED, "No DB errors or boolean differential")
            except Exception as exc:  # noqa: BLE001
                if type(exc).__name__ == "CancelledError":
                    raise
                self.check(label, CheckStatus.ERROR, str(exc))


class XSSScanner(BaseScanner):
    name = "XSSScanner"
    description = "Reflected XSS (unescaped canary reflection) and DOM XSS indicators via headless browser when available."

    def execute(self, ctx: AuditContext) -> None:
        tgts = targets(ctx, int(ctx.config.get("xss_max_params", 15)))
        if not tgts:
            self.check("Reflected XSS", CheckStatus.NOT_TESTED, "No parameters discovered")
        for base, param, _ in tgts:
            canary = "csab" + secrets.token_hex(3)
            payload = f"{canary}<i>{canary}</i>"
            u = _with_param(base, param, payload)
            label = f"Reflected XSS: {param} @ {urlparse(base).path}"
            try:
                r = ctx.client.get(u)
            except Exception as exc:  # noqa: BLE001
                if type(exc).__name__ == "CancelledError":
                    raise
                self.check(label, CheckStatus.ERROR, str(exc))
                continue
            ctype = r.headers.get("Content-Type", "")
            if f"<i>{canary}</i>" in r.text and "html" in ctype:
                self.check(label, CheckStatus.FAILED, "Canary HTML reflected unescaped")
                idx = r.text.find(f"<i>{canary}</i>")
                self.finding("Reflected Cross-Site Scripting (XSS)", Severity.HIGH, u,
                             f"HTML supplied in parameter '{param}' is reflected without encoding.",
                             f"Payload: {payload}\nContext: ...{r.text[max(0, idx - 80): idx + 60]}...",
                             "Attackers can run JavaScript in victims' sessions (account takeover, asset theft).",
                             "Context-aware output encoding; avoid bypassSecurityTrust* in Angular; enforce strict CSP.",
                             reproduction_steps=f"Open {u} in a browser and inspect the rendered <i> element.")
            elif canary in r.text and "json" in ctype and "html" not in ctype:
                self.check(label, CheckStatus.PASSED, "Reflected only in JSON (application/json)")
            else:
                self.check(label, CheckStatus.PASSED, "Not reflected unescaped")
        self._dom_xss(ctx)
        self.check("Stored XSS (profile, comments, asset metadata)", CheckStatus.MANUAL,
                   "Requires write access to an approved test account/staging; not executed automatically.")

    def _dom_xss(self, ctx: AuditContext) -> None:
        if not ctx.config.get("browser_checks", True):
            self.check("DOM XSS (headless browser)", CheckStatus.NOT_TESTED, "Browser checks disabled in configuration")
            return
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.check("DOM XSS (headless browser)", CheckStatus.NOT_TESTED, "Playwright not installed")
            return
        canary = "csab" + secrets.token_hex(3)
        url = ctx.target_url.rstrip("/") + f"/#<img src=x onerror=window.{canary}=1>"
        search_urls = [_with_param(b, p, f"<img src=x onerror=window.{canary}=1>") for b, p, _ in targets(ctx, 5)]
        try:
            with sync_playwright() as pw:
                browser = getattr(pw, ctx.config.get("browser", "chromium")).launch(headless=True)
                page = browser.new_page()
                fired = []
                for u in [url] + search_urls:
                    ctx.client.check_control()
                    try:
                        page.goto(u, wait_until="networkidle", timeout=20000)
                        if page.evaluate(f"() => window.{canary} === 1"):
                            fired.append(u)
                    except Exception:  # noqa: BLE001
                        continue
                browser.close()
        except Exception as exc:  # noqa: BLE001
            self.check("DOM XSS (headless browser)", CheckStatus.NOT_TESTED, f"Browser unavailable: {exc}"[:300])
            return
        if fired:
            self.check("DOM XSS (headless browser)", CheckStatus.FAILED, "; ".join(fired))
            for u in fired:
                self.finding("DOM-based / reflected XSS executed in browser", Severity.HIGH, u,
                             "A harmless proof-of-execution payload set a JavaScript variable in a real browser.",
                             f"window.{canary} === 1 after loading {u}",
                             "Confirmed script execution in the victim's browser.",
                             "Sanitize DOM sinks (innerHTML, location), use Angular's built-in sanitization, add strict CSP.")
        else:
            self.check("DOM XSS (headless browser)", CheckStatus.PASSED, f"{1 + len(search_urls)} URLs tested")
