"""Google PageSpeed Insights v5 API client."""
from __future__ import annotations

from typing import Any

import requests

PSI_URL = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"


class PageSpeedError(RuntimeError):
    pass


def run_pagespeed(url: str, strategy: str, api_key: str | None = None, timeout: float = 120,
                  session: requests.Session | None = None) -> dict[str, Any]:
    params: list[tuple[str, str]] = [("url", url), ("strategy", strategy)]
    for c in ("performance", "accessibility", "best-practices", "seo"):
        params.append(("category", c))
    if api_key:
        params.append(("key", api_key))
    s = session or requests.Session()
    r = s.get(PSI_URL, params=params, timeout=timeout)
    if r.status_code == 400 and "API key not valid" in r.text:
        raise PageSpeedError("Invalid Google PageSpeed API key")
    if r.status_code == 429:
        raise PageSpeedError("PageSpeed API quota exceeded (HTTP 429). Configure an API key or retry later.")
    if r.status_code != 200:
        raise PageSpeedError(f"PageSpeed API HTTP {r.status_code}: {r.text[:200]}")
    return parse_pagespeed(r.json())


AUDIT_KEYS = {
    "first-contentful-paint": "First Contentful Paint",
    "largest-contentful-paint": "Largest Contentful Paint",
    "total-blocking-time": "Total Blocking Time",
    "cumulative-layout-shift": "Cumulative Layout Shift",
    "speed-index": "Speed Index",
    "interactive": "Time to Interactive",
    "server-response-time": "Server Response Time (TTFB)",
}


def parse_pagespeed(data: dict[str, Any]) -> dict[str, Any]:
    lh = data.get("lighthouseResult", {})
    cats = lh.get("categories", {})
    audits = lh.get("audits", {})
    out: dict[str, Any] = {
        "scores": {k: round((v.get("score") or 0) * 100) for k, v in cats.items()},
        "metrics": {},
        "opportunities": [],
        "field_data": {},
    }
    for key, label in AUDIT_KEYS.items():
        a = audits.get(key)
        if a:
            out["metrics"][label] = {"value": a.get("numericValue"), "display": a.get("displayValue", ""),
                                     "unit": a.get("numericUnit", "")}
    for key, a in audits.items():
        det = a.get("details") or {}
        if det.get("type") == "opportunity" and (a.get("score") is not None and a["score"] < 0.9):
            out["opportunities"].append({"id": key, "title": a.get("title"), "savings_ms": det.get("overallSavingsMs", 0),
                                         "display": a.get("displayValue", "")})
    out["opportunities"].sort(key=lambda o: o["savings_ms"] or 0, reverse=True)
    le = data.get("loadingExperience", {}).get("metrics", {})
    for k, v in le.items():
        out["field_data"][k] = {"p75": v.get("percentile"), "category": v.get("category")}
    return out
