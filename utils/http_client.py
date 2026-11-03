"""Scope-enforcing, rate-limited HTTP client shared by scanners."""
from __future__ import annotations

import logging
import threading
import time
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from config.settings import USER_AGENT
from security.scope_validator import ScopeValidator

log = logging.getLogger(__name__)


class CancelledError(Exception):
    pass


class AuditHTTPClient:
    def __init__(self, scope: ScopeValidator, timeout: float = 20.0, max_rps: float = 5.0,
                 verify_tls: bool = True, cancel_event: threading.Event | None = None,
                 pause_event: threading.Event | None = None):
        self.scope = scope
        self.timeout = timeout
        self.min_interval = 1.0 / max_rps if max_rps > 0 else 0
        self.verify_tls = verify_tls
        self.cancel_event = cancel_event or threading.Event()
        self.pause_event = pause_event
        self._last = 0.0
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers["User-Agent"] = USER_AGENT
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=(502, 503, 504), allowed_methods={"GET", "HEAD", "OPTIONS"})
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.request_count = 0

    def set_bearer(self, token: str | None) -> None:
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
        else:
            self.session.headers.pop("Authorization", None)

    def check_control(self) -> None:
        if self.cancel_event.is_set():
            raise CancelledError("Audit cancelled")
        if self.pause_event is not None:
            while not self.pause_event.is_set():
                if self.cancel_event.is_set():
                    raise CancelledError("Audit cancelled")
                time.sleep(0.2)

    def _throttle(self) -> None:
        with self._lock:
            wait = self.min_interval - (time.monotonic() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()

    def request(self, method: str, url: str, *, allow_out_of_scope: bool = False, **kw: Any) -> requests.Response:
        self.check_control()
        if not allow_out_of_scope:
            self.scope.require(url)
        self._throttle()
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("verify", self.verify_tls)
        kw.setdefault("allow_redirects", True)
        self.request_count += 1
        log.debug("%s %s", method, url)
        return self.session.request(method, url, **kw)

    def get(self, url: str, **kw: Any) -> requests.Response:
        return self.request("GET", url, **kw)

    def head(self, url: str, **kw: Any) -> requests.Response:
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw: Any) -> requests.Response:
        return self.request("OPTIONS", url, **kw)

    def post(self, url: str, **kw: Any) -> requests.Response:
        return self.request("POST", url, **kw)
