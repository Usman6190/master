"""InfrastructureScanner: DNS, nameservers, CDN/WAF indicators, error pages, response consistency.

Only passive / single-request observations. No port scanning.
"""
from __future__ import annotations

import statistics
from urllib.parse import urljoin, urlparse

import dns.exception
import dns.resolver

from core.models import Category, CheckStatus, Severity, VerificationStatus
from scanners.base import AuditContext, BaseScanner

CDN_SIGNATURES = {
    "Cloudflare": ("cf-ray", "cf-cache-status"),
    "Akamai": ("x-akamai-transformed", "akamai-grn", "x-akamai-request-id"),
    "Amazon CloudFront": ("x-amz-cf-id", "x-amz-cf-pop"),
    "Fastly": ("x-fastly-request-id", "fastly-debug-digest"),
    "Azure Front Door": ("x-azure-ref", "x-fd-healthprobe"),
    "Azure CDN / Verizon": ("x-ec-custom-error",),
    "BunnyCDN": ("cdn-pullzone", "cdn-uid"),
    "Sucuri": ("x-sucuri-id",),
    "Imperva Incapsula": ("x-iinfo", "x-cdn"),
}
NS_HINTS = {"cloudflare": "Cloudflare", "awsdns": "AWS Route 53", "azure-dns": "Azure DNS", "akam": "Akamai",
            "googledomains": "Google", "nsone": "NS1", "domaincontrol": "GoDaddy"}


class InfrastructureScanner(BaseScanner):
    name = "InfrastructureScanner"
    category = Category.INFRASTRUCTURE
    description = "DNS, nameservers, CDN/WAF indicators, error pages and response consistency (passive)."

    def execute(self, ctx: AuditContext) -> None:
        host = urlparse(ctx.target_url).hostname or ""
        self._dns(host)
        self._cdn_waf(ctx)
        self._error_page(ctx)
        self._consistency(ctx)

    def _resolve(self, name: str, rtype: str) -> list[str]:
        try:
            return [r.to_text() for r in dns.resolver.resolve(name, rtype, lifetime=10)]
        except (dns.exception.DNSException, OSError):
            return []

    def _dns(self, host: str) -> None:
        a = self._resolve(host, "A")
        aaaa = self._resolve(host, "AAAA")
        cname = self._resolve(host, "CNAME")
        apex = ".".join(host.split(".")[-2:])
        ns = self._resolve(apex, "NS")
        caa = self._resolve(apex, "CAA")
        txt = self._resolve(apex, "TXT")
        dmarc = self._resolve(f"_dmarc.{apex}", "TXT")
        self.check("DNS resolution", CheckStatus.PASSED if a or aaaa else CheckStatus.FAILED,
                   f"A={a} AAAA={aaaa} CNAME={cname}")
        if not (a or aaaa):
            self.result.error = f"DNS resolution failed for {host}"
        self.metric("A records", ", ".join(a) or "-")
        self.metric("AAAA records", ", ".join(aaaa) or "-")
        self.metric("CNAME", ", ".join(cname) or "-")
        self.metric("Nameservers", ", ".join(ns) or "-")
        provider = next((v for k, v in NS_HINTS.items() if any(k in n.lower() for n in ns)), "unknown")
        self.metric("DNS provider (inferred from NS)", provider)
        self.check("Multiple nameservers", CheckStatus.PASSED if len(ns) >= 2 else CheckStatus.FAILED, ", ".join(ns))
        if caa:
            self.check("CAA record restricts certificate issuance", CheckStatus.PASSED, "; ".join(caa))
        else:
            self.check("CAA record restricts certificate issuance", CheckStatus.FAILED, "No CAA record")
            self.finding("No DNS CAA record", Severity.LOW, apex, "No CAA record limits which CAs may issue certificates.",
                         f"dig CAA {apex} -> (empty)", "Any public CA can issue certificates for the domain.",
                         "Add CAA records listing only the CAs you use.", category=Category.INFRASTRUCTURE)
        spf = [t for t in txt if "v=spf1" in t]
        self.check("SPF record", CheckStatus.PASSED if spf else CheckStatus.FAILED, spf[0] if spf else "Missing")
        self.check("DMARC record", CheckStatus.PASSED if dmarc else CheckStatus.FAILED, dmarc[0] if dmarc else "Missing")
        if not spf or not dmarc:
            self.finding("Email spoofing protection incomplete (SPF/DMARC)", Severity.LOW, apex,
                         "SPF and/or DMARC records are missing for the marketplace domain.",
                         f"SPF: {spf or 'missing'}; DMARC: {dmarc or 'missing'}",
                         "Attackers can more easily spoof CreativeStall emails for phishing.",
                         "Publish SPF and a DMARC policy (start with p=quarantine).", category=Category.INFRASTRUCTURE)

    def _cdn_waf(self, ctx: AuditContext) -> None:
        resp = ctx.shared.get("landing_response") or ctx.client.get(ctx.target_url)
        h = {k.lower(): v for k, v in resp.headers.items()}
        server = h.get("server", "").lower()
        detected = [name for name, keys in CDN_SIGNATURES.items() if any(k in h for k in keys)]
        if "cloudflare" in server and "Cloudflare" not in detected:
            detected.append("Cloudflare")
        ctx.shared["cdn_detected"] = detected
        evidence = "; ".join(f"{k}: {h[k]}" for keys in CDN_SIGNATURES.values() for k in keys if k in h) or f"server: {server}"
        self.metric("CDN/WAF indicators (inferred)", ", ".join(detected) or "none observed", context=evidence[:200])
        self.check("CDN/WAF indicator observed", CheckStatus.PASSED if detected else CheckStatus.MANUAL,
                   (", ".join(detected) + " (inferred from headers, not confirmed configuration)") if detected
                   else "No CDN/WAF headers observed; confirm provider configuration manually")
        if not detected:
            self.finding("No CDN/WAF indicators observed", Severity.MANUAL, ctx.target_url,
                         "Response headers do not show a recognizable CDN or WAF. This is an inference only.",
                         evidence, "Origin may be directly exposed to scraping and volumetric attacks.",
                         "Confirm whether a CDN/WAF fronts the origin and that the origin rejects direct traffic.",
                         category=Category.INFRASTRUCTURE, verification_status=VerificationStatus.UNVERIFIED)
        cache = h.get("cache-control", "")
        self.metric("Landing Cache-Control", cache or "-")

    def _error_page(self, ctx: AuditContext) -> None:
        url = urljoin(ctx.target_url, "csab-nonexistent-page-404-check")
        try:
            r = ctx.client.get(url, allow_redirects=False)
        except Exception as exc:  # noqa: BLE001
            self.check("Error page handling", CheckStatus.ERROR, str(exc))
            return
        body = r.text.lower()
        leaky = [m for m in ("stack trace", "exception", "at microsoft.", "at system.", "sql server", "iis ", "asp.net")
                 if m in body]
        self.metric("404 page status", r.status_code)
        if r.status_code == 200:
            self.check("Unknown paths return 404", CheckStatus.FAILED, "HTTP 200 for unknown path (soft 404 / SPA fallback)")
        else:
            self.check("Unknown paths return 404", CheckStatus.PASSED, f"HTTP {r.status_code}")
        if leaky:
            self.check("Error pages hide internals", CheckStatus.FAILED, ", ".join(leaky))
            self.finding("Verbose error page", Severity.LOW, url, "Error page content discloses technology details.",
                         f"Markers: {', '.join(leaky)}", "Assists attacker reconnaissance.",
                         "Use generic custom error pages in production.", category=Category.INFRASTRUCTURE)
        else:
            self.check("Error pages hide internals", CheckStatus.PASSED, "No technology markers")

    def _consistency(self, ctx: AuditContext) -> None:
        times, statuses, servers = [], set(), set()
        for _ in range(3):
            r = ctx.client.get(ctx.target_url)
            times.append(r.elapsed.total_seconds() * 1000)
            statuses.add(r.status_code)
            servers.add(r.headers.get("Server", ""))
        self.metric("Landing response time (median of 3)", round(statistics.median(times), 1), "ms")
        self.check("Consistent responses across requests", CheckStatus.PASSED if len(statuses) == 1 else CheckStatus.FAILED,
                   f"statuses={sorted(statuses)} servers={sorted(servers)}")
