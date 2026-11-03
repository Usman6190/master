"""PageSpeedAnalyzer, LighthouseAnalyzer, APIResponseAnalyzer, AssetDeliveryAnalyzer, JMeterController."""
from __future__ import annotations

import statistics
import time
from urllib.parse import urlparse

from config.settings import app_data_dir
from core.models import Category, CheckStatus, Severity, VerificationStatus
from integrations.jmeter import PROFILES, run_jmeter
from integrations.lighthouse import LighthouseMissing, run_lighthouse
from integrations.pagespeed import PageSpeedError, run_pagespeed
from scanners.api.common import api_url, lines
from scanners.base import AuditContext, BaseScanner

CWV = {"Largest Contentful Paint": (2500, 4000), "Total Blocking Time": (200, 600),
       "Cumulative Layout Shift": (0.1, 0.25), "First Contentful Paint": (1800, 3000),
       "Server Response Time (TTFB)": (800, 1800)}


def _record_psi(scanner: BaseScanner, label: str, res: dict, url: str) -> None:
    perf = res["scores"].get("performance")
    for k, v in res["scores"].items():
        scanner.metric(f"{label} {k} score", v, "/100")
    scanner.metric(f"PageSpeed performance score ({label.split()[-1].lower()})" if "PageSpeed" in label
                   else "Lighthouse performance score", perf, "/100")
    for name, m in res["metrics"].items():
        scanner.metric(f"{label}: {name}", round(m["value"], 3) if isinstance(m["value"], float) else m["value"],
                       m.get("unit", ""), context=m.get("display", ""))
        if name in CWV and m["value"] is not None:
            good, poor = CWV[name]
            st = CheckStatus.PASSED if m["value"] <= good else CheckStatus.FAILED
            scanner.check(f"{label}: {name} within 'good' threshold", st, m.get("display", ""))
            if m["value"] > poor:
                scanner.finding(f"Poor {name} ({label})", Severity.MEDIUM, url,
                                f"{name} is {m.get('display')} which is in the 'poor' range.",
                                f"{label} measured {name} = {m.get('display')} (poor > {poor})",
                                "Slower pages reduce conversions and SEO ranking.",
                                "See PageSpeed opportunities: " + ", ".join(o["title"] for o in res["opportunities"][:3]),
                                category=Category.PERFORMANCE)
    if perf is not None:
        scanner.check(f"{label} performance score >= 50", CheckStatus.PASSED if perf >= 50 else CheckStatus.FAILED,
                      f"{perf}/100")
    for o in res["opportunities"][:8]:
        scanner.metric(f"{label} opportunity: {o['title']}", o["savings_ms"], "ms", context=o["display"])
    for k, v in res.get("field_data", {}).items():
        scanner.metric(f"{label} field (CrUX) {k} p75", v["p75"], context=v["category"])


class PageSpeedAnalyzer(BaseScanner):
    name = "PageSpeedAnalyzer"
    category = Category.PERFORMANCE
    description = "Google PageSpeed Insights (mobile + desktop) lab & field data."

    def execute(self, ctx: AuditContext) -> None:
        key = ctx.secrets.get("pagespeed_api_key")
        mode = ctx.config.get("device_mode", "both")
        strategies = ["mobile", "desktop"] if mode == "both" else [mode]
        urls = [ctx.target_url] + lines(ctx.config.get("pagespeed_extra_urls"))[:3]
        errors = []
        for url in urls:
            for strat in strategies:
                ctx.client.check_control()
                try:
                    res = run_pagespeed(url, strat, key, timeout=float(ctx.config.get("pagespeed_timeout", 120)))
                except (PageSpeedError, Exception) as exc:  # noqa: BLE001
                    errors.append(f"{strat} {url}: {exc}")
                    self.check(f"PageSpeed {strat} ({url})", CheckStatus.ERROR, str(exc)[:300])
                    continue
                label = f"PageSpeed {strat.capitalize()}" if url == ctx.target_url else f"PageSpeed {strat.capitalize()} {urlparse(url).path}"
                _record_psi(self, label, res, url)
                ctx.shared.setdefault("pagespeed", {})[f"{strat}|{url}"] = res
        if errors and len(errors) == len(urls) * len(strategies):
            self.result.status = "failed"
            self.result.error = "; ".join(errors)[:500]


class LighthouseAnalyzer(BaseScanner):
    name = "LighthouseAnalyzer"
    category = Category.PERFORMANCE
    description = "Local Lighthouse run (optional; requires Node.js + Lighthouse CLI)."

    def execute(self, ctx: AuditContext) -> None:
        if not ctx.config.get("run_lighthouse", True):
            self.check("Lighthouse local run", CheckStatus.NOT_TESTED, "Disabled in configuration")
            return
        try:
            res = run_lighthouse(ctx.target_url, "desktop" if ctx.config.get("device_mode") == "desktop" else "mobile")
        except LighthouseMissing as exc:
            self.result.status = "skipped"
            self.result.error = str(exc)
            self.check("Lighthouse local run", CheckStatus.NOT_TESTED, str(exc))
            return
        _record_psi(self, "Lighthouse", res, ctx.target_url)
        self.check("Lighthouse local run", CheckStatus.PASSED, "Completed")


class APIResponseAnalyzer(BaseScanner):
    name = "APIResponseAnalyzer"
    category = Category.PERFORMANCE
    description = "Sequential response-time sampling (p50/p95) for landing, search and configured API endpoints."

    def execute(self, ctx: AuditContext) -> None:
        samples = max(3, min(int(ctx.config.get("response_samples", 10)), 50))
        threshold = float(ctx.config.get("response_threshold_ms", 1000))
        endpoints = [ctx.target_url]
        if ctx.config.get("search_endpoint"):
            endpoints.append(api_url(ctx, ctx.config["search_endpoint"]))
        endpoints += [api_url(ctx, e) for e in lines(ctx.config.get("perf_endpoints"))]
        summary = {}
        for url in dict.fromkeys(endpoints):
            times, sizes, codes = [], [], []
            for _ in range(samples):
                t0 = time.perf_counter()
                r = ctx.client.get(url)
                _ = r.content
                times.append((time.perf_counter() - t0) * 1000)
                sizes.append(len(r.content))
                codes.append(r.status_code)
            times.sort()
            p50 = statistics.median(times)
            p95 = times[min(len(times) - 1, int(0.95 * len(times)))]
            errs = sum(1 for c in codes if c >= 400)
            path = urlparse(url).path or "/"
            summary[path] = {"p50": round(p50, 1), "p95": round(p95, 1), "errors": errs}
            self.metric(f"{path} p50", round(p50, 1), "ms", context=f"{samples} sequential samples")
            self.metric(f"{path} p95", round(p95, 1), "ms")
            self.metric(f"{path} avg size", int(statistics.mean(sizes)), "bytes")
            self.metric(f"{path} error rate", round(100 * errs / samples, 1), "%")
            ok = p95 <= threshold and errs == 0
            self.check(f"Response time p95 <= {int(threshold)} ms: {path}", CheckStatus.PASSED if ok else CheckStatus.FAILED,
                       f"p50={p50:.0f}ms p95={p95:.0f}ms errors={errs}/{samples}")
            if p95 > threshold * 2:
                self.finding(f"Slow response time: {path}", Severity.MEDIUM if p95 > threshold * 3 else Severity.LOW, url,
                             f"95th percentile response time is {p95:.0f} ms (threshold {threshold:.0f} ms).",
                             f"{samples} samples: p50={p50:.0f}ms p95={p95:.0f}ms max={times[-1]:.0f}ms",
                             "Slow search/API responses degrade user experience and indicate scalability limits.",
                             "Profile the endpoint (SQL FREETEXT query plans, caching, Redis Search migration).",
                             category=Category.PERFORMANCE)
        ctx.shared["api_response_summary"] = summary


class AssetDeliveryAnalyzer(BaseScanner):
    name = "AssetDeliveryAnalyzer"
    category = Category.PERFORMANCE
    description = "Preview/asset delivery time, size, cache headers and CDN cache indicators."

    def execute(self, ctx: AuditContext) -> None:
        tmpl = ctx.config.get("preview_url_template")
        ids = lines(ctx.config.get("asset_test_ids"))
        urls = [api_url(ctx, tmpl.replace("{id}", i)) for i in ids[:5]] if tmpl and ids else []
        if not urls:
            landing = ctx.shared.get("landing_response")
            import re
            if landing is not None:
                imgs = re.findall(r"""<img[^>]+src=["']([^"']+)["']""", landing.text, re.I)
                from urllib.parse import urljoin
                urls = [urljoin(ctx.target_url, s) for s in imgs if ctx.client.scope.in_scope(urljoin(ctx.target_url, s))][:5]
        if not urls:
            self.check("Asset delivery measured", CheckStatus.NOT_TESTED,
                       "No preview URLs configured or discovered (set 'preview_url_template' + 'asset_test_ids')")
            return
        for u in urls:
            t0 = time.perf_counter()
            r = ctx.client.get(u)
            ms = (time.perf_counter() - t0) * 1000
            h = {k.lower(): v for k, v in r.headers.items()}
            cache_ind = {k: h[k] for k in ("cf-cache-status", "x-cache", "age", "x-cache-status", "cdn-cache") if k in h}
            name = u.rsplit("/", 1)[-1][:40]
            self.metric(f"Asset {name} delivery time", round(ms, 1), "ms")
            self.metric(f"Asset {name} size", len(r.content), "bytes")
            self.metric(f"Asset {name} cache indicators", str(cache_ind) or "none",
                        context="Inferred from response headers; not a confirmed cache hit unless header says HIT")
            cc = h.get("cache-control", "")
            self.check(f"Asset {name} has long-lived Cache-Control", CheckStatus.PASSED if "max-age" in cc else CheckStatus.FAILED,
                       cc or "missing")
            self.check(f"Asset {name} delivered successfully", CheckStatus.PASSED if r.status_code == 200 else CheckStatus.FAILED,
                       f"HTTP {r.status_code}")


class JMeterController(BaseScanner):
    name = "JMeterController"
    category = Category.PERFORMANCE
    description = "Controlled load test via Apache JMeter (disabled unless explicitly enabled; production needs extra confirmation)."

    def execute(self, ctx: AuditContext) -> None:
        cfg = ctx.config
        if not cfg.get("load_test_enabled"):
            self.check("Load test", CheckStatus.NOT_TESTED, "Load testing disabled (enable in Performance settings)")
            return
        env = cfg.get("load_test_environment", "staging")
        if env == "production" and not (cfg.get("production_load_confirmed") and cfg.get("production_traffic_ceiling")):
            self.check("Load test", CheckStatus.NOT_TESTED,
                       "Production load test requires explicit confirmation and an approved traffic ceiling")
            self.result.error = "Production load test not confirmed"
            return
        profile = cfg.get("load_profile", "Baseline")
        users = int(cfg.get("load_custom_users", 10)) if profile == "Custom" else PROFILES.get(profile, 10)
        if env == "production":
            users = min(users, int(cfg["production_traffic_ceiling"]))
        target = cfg.get("load_test_target_url") or ctx.target_url
        ctx.client.scope.require(target)
        urls = [target] + [api_url(ctx, e) for e in lines(cfg.get("perf_endpoints"))][:5]
        res = run_jmeter(urls, users, int(cfg.get("load_ramp_s", 60)), int(cfg.get("load_duration_s", 300)),
                         app_data_dir() / "jmeter", cancel_check=ctx.client.cancel_event.is_set,
                         max_error_rate_stop=float(cfg.get("load_error_stop_pct", 20)))
        for k in ("samples", "errors", "error_rate", "avg_ms", "p50_ms", "p90_ms", "p95_ms", "p99_ms", "max_ms", "throughput_rps"):
            if k in res:
                self.metric(f"Load {profile} ({users} users) {k}", res[k], context=env)
        if res.get("stopped_reason"):
            self.metric("Load test stopped", res["stopped_reason"])
        if not res.get("samples"):
            self.check("Load test executed", CheckStatus.ERROR, "No samples recorded")
            return
        ok = res["error_rate"] <= 1 and res["p95_ms"] <= float(cfg.get("response_threshold_ms", 1000)) * 2
        self.check(f"Load {profile} ({users} users): error rate <=1% and p95 within SLA",
                   CheckStatus.PASSED if ok else CheckStatus.FAILED,
                   f"error_rate={res['error_rate']}% p95={res['p95_ms']}ms throughput={res['throughput_rps']} rps")
        if not ok:
            self.finding(f"Degradation under {profile} load ({users} users)", Severity.MEDIUM, target,
                         "Load test exceeded error-rate or response-time thresholds.",
                         str({k: res[k] for k in ('samples', 'error_rate', 'p95_ms', 'throughput_rps')}),
                         "Users may experience errors/slowness at this concurrency. Test profile ≠ guaranteed capacity.",
                         "Investigate bottlenecks (DB, search, CDN offload) and re-test.",
                         category=Category.PERFORMANCE, verification_status=VerificationStatus.UNVERIFIED)
