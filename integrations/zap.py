"""OWASP ZAP integration via its local REST API (spider + passive scan only; no active attacks)."""
from __future__ import annotations

import threading
import time
from typing import Any

import requests


class ZAPError(RuntimeError):
    pass


class ZAPClient:
    def __init__(self, api_url: str = "http://127.0.0.1:8080", api_key: str = "", timeout: float = 30.0):
        self.base = api_url.rstrip("/")
        self.key = api_key
        self.timeout = timeout

    def _get(self, path: str, **params: Any) -> dict[str, Any]:
        if self.key:
            params["apikey"] = self.key
        try:
            r = requests.get(f"{self.base}/JSON/{path}/", params=params, timeout=self.timeout)
        except requests.RequestException as exc:
            raise ZAPError(f"Cannot reach ZAP API at {self.base}: {exc.__class__.__name__}. "
                           "Start ZAP (zap.bat -daemon -port 8080) and set the API key.") from exc
        if r.status_code != 200:
            raise ZAPError(f"ZAP API {path} returned HTTP {r.status_code}: {r.text[:200]}")
        return r.json()

    def version(self) -> str:
        return self._get("core/view/version").get("version", "")

    def spider(self, url: str, max_children: int = 50, max_minutes: float = 10,
               cancel: threading.Event | None = None) -> int:
        self._get("core/action/accessUrl", url=url, followRedirects="true")
        sid = self._get("spider/action/scan", url=url, maxChildren=max_children, recurse="true",
                        subtreeOnly="true").get("scan")
        deadline = time.monotonic() + max_minutes * 60
        while time.monotonic() < deadline:
            if cancel is not None and cancel.is_set():
                self._get("spider/action/stop", scanId=sid)
                raise ZAPError("Cancelled")
            if int(self._get("spider/view/status", scanId=sid).get("status", 0)) >= 100:
                break
            time.sleep(2)
        else:
            self._get("spider/action/stop", scanId=sid)
        return len(self._get("spider/view/results", scanId=sid).get("results", []))

    def wait_passive(self, max_minutes: float = 5, cancel: threading.Event | None = None) -> None:
        deadline = time.monotonic() + max_minutes * 60
        while time.monotonic() < deadline and not (cancel is not None and cancel.is_set()):
            if int(self._get("pscan/view/recordsToScan").get("recordsToScan", 0)) == 0:
                return
            time.sleep(2)

    def alerts(self, base_url: str) -> list[dict[str, Any]]:
        out, start = [], 0
        while True:
            batch = self._get("core/view/alerts", baseurl=base_url, start=start, count=500).get("alerts", [])
            out += batch
            if len(batch) < 500:
                return out
            start += 500


def group_alerts(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Group ZAP alerts by plugin/alert name; drop false positives."""
    groups: dict[str, dict[str, Any]] = {}
    for a in alerts:
        if a.get("confidence") == "False Positive":
            continue
        key = f"{a.get('pluginId')}|{a.get('alert') or a.get('name')}"
        g = groups.setdefault(key, {**a, "urls": []})
        if a.get("url") and a["url"] not in g["urls"]:
            g["urls"].append(a["url"])
    return list(groups.values())
