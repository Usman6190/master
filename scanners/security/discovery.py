"""WebsiteDiscovery: fetches the landing page, robots.txt and sitemap to seed later modules."""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from core.models import CheckStatus, Severity
from scanners.base import AuditContext, BaseScanner

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"'#]+)["']""", re.I)
_FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.I | re.S)
_INPUT_RE = re.compile(r"""<input\b[^>]*name\s*=\s*["']([^"']+)["']""", re.I)
_API_RE = re.compile(r"""["'](/api/[A-Za-z0-9_\-/{}.]+)["']""")


class WebsiteDiscovery(BaseScanner):
    name = "WebsiteDiscovery"
    description = "Maps reachable pages, forms, query parameters and API paths."
    max_pages = 25

    def execute(self, ctx: AuditContext) -> None:
        base = ctx.target_url
        resp = ctx.client.get(base)
        ctx.shared["landing_response"] = resp
        self.metric("Landing page status", resp.status_code)
        self.metric("Landing page size", len(resp.content), "bytes")
        self.check("Target reachable", CheckStatus.PASSED if resp.status_code < 500 else CheckStatus.FAILED,
                   f"HTTP {resp.status_code}")

        urls: set[str] = {resp.url}
        params: set[tuple[str, str]] = set()
        api_paths: set[str] = set(_API_RE.findall(resp.text))
        forms: list[dict] = []
        queue = [resp.url]
        self._extract(resp.url, resp.text, urls, params, forms, ctx)

        for extra in ("robots.txt", "sitemap.xml"):
            try:
                r = ctx.client.get(urljoin(base, extra))
                if r.status_code == 200:
                    ctx.shared[extra] = r.text
                    for loc in re.findall(r"<loc>([^<]+)</loc>", r.text)[:50]:
                        if ctx.client.scope.in_scope(loc):
                            urls.add(loc.strip())
            except Exception as exc:  # noqa: BLE001
                self.log.info("Could not fetch %s: %s", extra, exc)

        for u in list(urls)[: self.max_pages]:
            if u in queue:
                continue
            try:
                r = ctx.client.get(u)
                if "text/html" in r.headers.get("Content-Type", ""):
                    self._extract(r.url, r.text, urls, params, forms, ctx)
                    api_paths.update(_API_RE.findall(r.text))
            except Exception as exc:  # noqa: BLE001
                self.log.info("Discovery fetch failed for %s: %s", u, exc)
            queue.append(u)

        ctx.shared["discovered_urls"] = sorted(urls)
        ctx.shared["query_params"] = sorted(params)
        ctx.shared["forms"] = forms
        ctx.shared["api_paths"] = sorted(api_paths)
        self.metric("Discovered URLs", len(urls))
        self.metric("Discovered query parameters", len(params))
        self.metric("Discovered forms", len(forms))
        self.metric("Discovered API paths (static)", len(api_paths))
        if "angular" in resp.text.lower() or "ng-version" in resp.text:
            self.finding("Angular single-page application detected", Severity.INFO, base,
                         "The landing page contains Angular markers.", "ng-version / angular markers in HTML",
                         "Informational: confirms assessment assumption about the front-end stack.",
                         "No action required.")

    def _extract(self, page_url, html, urls, params, forms, ctx):
        for link in _LINK_RE.findall(html):
            full = urljoin(page_url, link.strip())
            if ctx.client.scope.in_scope(full) and urlparse(full).scheme in ("http", "https"):
                urls.add(full.split("#")[0])
                q = urlparse(full).query
                for pair in q.split("&"):
                    if "=" in pair:
                        params.add((full.split("?")[0], pair.split("=")[0]))
        for form_html in _FORM_RE.findall(html):
            forms.append({"page": page_url, "inputs": _INPUT_RE.findall(form_html)})
