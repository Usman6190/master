"""Marketplace-specific modules: AssetProtectionScanner, UploadSecurityTester, BotProtectionScanner."""
from __future__ import annotations

import time

from core.models import CheckStatus, Severity, VerificationStatus
from scanners.api.common import api_url, auth_headers, get_token, lines
from scanners.base import AuditContext, BaseScanner


class AssetProtectionScanner(BaseScanner):
    name = "AssetProtectionScanner"
    description = "Original asset download authorization, signed-URL enforcement, preview cache headers."

    def execute(self, ctx: AuditContext) -> None:
        tmpl = ctx.config.get("asset_download_template")
        asset_ids = lines(ctx.config.get("asset_test_ids")) or ["1001"]
        if not tmpl:
            self.check("Original asset download requires authorization", CheckStatus.NOT_TESTED,
                       "Configure 'asset_download_template' (e.g. /api/assets/{id}/download)")
        else:
            for aid in asset_ids[:3]:
                url = api_url(ctx, tmpl.replace("{id}", aid))
                r = ctx.client.get(url, stream=True, allow_redirects=False)
                size = int(r.headers.get("Content-Length") or 0)
                ctype = r.headers.get("Content-Type", "")
                r.close()
                label = f"Unauthenticated original download blocked (asset {aid})"
                if r.status_code in (401, 403):
                    self.check(label, CheckStatus.PASSED, f"HTTP {r.status_code}")
                elif r.status_code == 200 and "html" not in ctype:
                    self.check(label, CheckStatus.FAILED, f"HTTP 200 {ctype} {size} bytes")
                    self.finding("Original asset downloadable without authentication", Severity.CRITICAL, url,
                                 "The original-asset download endpoint returned file content without a token.",
                                 f"GET {url} (no auth) -> 200, Content-Type {ctype}, Content-Length {size}",
                                 "Paid/original assets can be harvested for free — direct revenue loss.",
                                 "Require authentication + entitlement check, then issue short-lived signed URLs.",
                                 reproduction_steps=f"curl -o out.bin {url}")
                elif r.status_code in (301, 302, 307, 308):
                    loc = r.headers.get("Location", "")
                    signed = any(k in loc.lower() for k in ("sig=", "signature=", "x-amz-signature", "se=", "token=", "expires="))
                    self.check(label, CheckStatus.MANUAL if signed else CheckStatus.FAILED,
                               f"Redirect to {'signed' if signed else 'UNSIGNED'} URL")
                    if not signed:
                        self.finding("Asset download redirects to unsigned storage URL", Severity.HIGH, url,
                                     "Unauthenticated request is redirected to a storage URL without a signature.",
                                     f"Location: {loc[:200]}", "Storage URLs can be shared/enumerated for bulk download.",
                                     "Use expiring signed URLs bound to the purchasing user.",
                                     verification_status=VerificationStatus.UNVERIFIED)
                else:
                    self.check(label, CheckStatus.MANUAL, f"HTTP {r.status_code}")
                tok = get_token(ctx)
                if tok:
                    ra = ctx.client.get(url, headers=auth_headers(tok), stream=True, allow_redirects=False)
                    ra.close()
                    self.check(f"Authenticated download behaviour (asset {aid})", CheckStatus.MANUAL,
                               f"HTTP {ra.status_code}; verify entitlement (purchased/licensed) is enforced")
        self._previews(ctx)
        self.check("Watermarking of preview images", CheckStatus.MANUAL, "Verify previews are watermarked/low-resolution.")

    def _previews(self, ctx):
        tmpl = ctx.config.get("preview_url_template")
        urls = []
        if tmpl:
            urls = [api_url(ctx, tmpl.replace("{id}", i)) for i in (lines(ctx.config.get("asset_test_ids")) or ["1001"])[:3]]
        if not urls:
            self.check("Preview cache headers", CheckStatus.NOT_TESTED, "Configure 'preview_url_template'")
            return
        for u in urls:
            r = ctx.client.get(u, allow_out_of_scope=False)
            cc = r.headers.get("Cache-Control", "")
            self.metric("Preview Cache-Control", cc or "-", context=u)
            ok = "max-age" in cc or "s-maxage" in cc
            self.check(f"Preview cacheable ({u.rsplit('/', 1)[-1]})", CheckStatus.PASSED if ok else CheckStatus.FAILED,
                       cc or "no Cache-Control")


class UploadSecurityTester(BaseScanner):
    name = "UploadSecurityTester"
    description = "Contributor upload endpoint: authentication required, dangerous file types rejected (harmless files only)."
    requires = ("upload_endpoint",)

    def execute(self, ctx: AuditContext) -> None:
        url = api_url(ctx, ctx.config["upload_endpoint"])
        harmless = ("csab-test.txt", b"CreativeStall audit harmless test file", "text/plain")
        r = ctx.client.post(url, files={"file": harmless})
        if r.status_code in (401, 403):
            self.check("Upload requires authentication", CheckStatus.PASSED, f"HTTP {r.status_code}")
        elif r.status_code < 300:
            self.check("Upload requires authentication", CheckStatus.FAILED, f"HTTP {r.status_code}")
            self.finding("Unauthenticated file upload accepted", Severity.CRITICAL, url,
                         "The upload endpoint accepted a file without authentication.",
                         f"POST {url} multipart file=csab-test.txt -> HTTP {r.status_code}: {r.text[:200]}",
                         "Anyone can store content on the platform (malware hosting, storage abuse).",
                         "Require an authenticated contributor role for uploads.")
        else:
            self.check("Upload requires authentication", CheckStatus.MANUAL, f"HTTP {r.status_code}")
        if not ctx.config.get("upload_allow_authenticated_tests"):
            self.check("Dangerous extension / content-type rejected", CheckStatus.NOT_TESTED,
                       "Authenticated upload tests disabled (enable 'upload_allow_authenticated_tests' on staging only)")
            return
        tok = get_token(ctx)
        if not tok:
            self.check("Dangerous extension / content-type rejected", CheckStatus.NOT_TESTED, "No contributor token")
            return
        cases = [("csab-test.aspx", b"<%-- harmless audit marker --%>", "text/plain"),
                 ("csab-test.svg", b'<svg xmlns="http://www.w3.org/2000/svg"><!-- audit --></svg>', "image/svg+xml"),
                 ("csab-test.jpg.exe", b"MZ-harmless-audit-marker", "image/jpeg")]
        for name, data, ctype in cases:
            r = ctx.client.post(url, files={"file": (name, data, ctype)}, headers=auth_headers(tok))
            label = f"Upload rejects {name}"
            if r.status_code in (400, 415, 422):
                self.check(label, CheckStatus.PASSED, f"HTTP {r.status_code}")
            elif r.status_code < 300:
                self.check(label, CheckStatus.FAILED, f"HTTP {r.status_code}")
                self.finding(f"Upload accepts dangerous file type ({name})", Severity.HIGH, url,
                             f"A harmless file named {name} was accepted by the upload endpoint.",
                             f"HTTP {r.status_code}: {r.text[:200]}",
                             "Executable/script uploads can lead to stored XSS or remote code execution.",
                             "Validate extension and magic bytes against an allow-list; store outside web root; "
                             "serve with Content-Disposition: attachment. Delete the test file.",
                             verification_status=VerificationStatus.UNVERIFIED)
            else:
                self.check(label, CheckStatus.MANUAL, f"HTTP {r.status_code}")


class BotProtectionScanner(BaseScanner):
    name = "BotProtectionScanner"
    description = "Scraping resistance: non-browser user agents, sequential asset page fetching, robots policy."

    def execute(self, ctx: AuditContext) -> None:
        robots = ctx.shared.get("robots.txt", "")
        self.check("robots.txt present", CheckStatus.PASSED if robots else CheckStatus.FAILED,
                   (robots[:200] if robots else "missing"))
        r = ctx.client.get(ctx.target_url, headers={"User-Agent": "python-requests/2.31 scraper-bot"})
        challenged = r.status_code in (403, 429, 503) or any(m in r.text.lower() for m in ("captcha", "challenge", "cf-chl"))
        self.check("Scripted user agent challenged/blocked", CheckStatus.PASSED if challenged else CheckStatus.FAILED,
                   f"HTTP {r.status_code}")
        tmpl = ctx.config.get("asset_page_template")
        ids = lines(ctx.config.get("asset_test_ids"))
        n = max(5, min(int(ctx.config.get("scrape_probe_count", 15)), 40))
        codes = []
        if tmpl and ids:
            start = time.monotonic()
            for i in range(n):
                u = api_url(ctx, tmpl.replace("{id}", ids[i % len(ids)]))
                rr = ctx.client.get(u, headers={"User-Agent": "python-requests/2.31 scraper-bot"})
                codes.append(rr.status_code)
                if rr.status_code in (403, 429):
                    break
            elapsed = time.monotonic() - start
            self.metric("Scrape probe requests", len(codes))
            self.metric("Scrape probe duration", round(elapsed, 1), "s")
            blocked = any(c in (403, 429) for c in codes)
            self.check("Sequential asset harvesting throttled", CheckStatus.PASSED if blocked else CheckStatus.FAILED,
                       f"codes={sorted(set(codes))}")
        else:
            self.check("Sequential asset harvesting throttled", CheckStatus.NOT_TESTED,
                       "Configure 'asset_page_template' and 'asset_test_ids'")
        if not challenged and not any(c in (403, 429) for c in codes):
            self.finding("No observable bot/scraping protection", Severity.MEDIUM, ctx.target_url,
                         "Requests with an obvious scraper user agent were served normally"
                         + (f" ({len(codes)} sequential asset pages)" if codes else "") + ".",
                         f"Landing with scraper UA -> HTTP {r.status_code}; asset probe codes={sorted(set(codes)) or 'n/a'}",
                         "Bulk harvesting of the 3.5M-asset catalogue, previews and metadata is likely feasible.",
                         "Enable bot management at the CDN/WAF, rate-limit asset pages and search per IP/session.",
                         verification_status=VerificationStatus.UNVERIFIED)
