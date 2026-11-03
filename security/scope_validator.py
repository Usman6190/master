"""Guards that keep every request inside the user-approved scope."""
from __future__ import annotations

from urllib.parse import urlparse


class ScopeError(ValueError):
    pass


def normalize_url(url: str) -> str:
    url = (url or "").strip()
    if not url:
        raise ScopeError("URL is empty")
    if "://" not in url:
        url = "https://" + url
    p = urlparse(url)
    if p.scheme not in ("http", "https") or not p.hostname:
        raise ScopeError(f"Invalid URL: {url}")
    return url if url.endswith("/") or p.path else url + "/"


def registrable_domain(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


class ScopeValidator:
    def __init__(self, target_url: str, extra_hosts: list[str] | None = None, include_subdomains: bool = True):
        self.target_url = normalize_url(target_url)
        self.base_host = urlparse(self.target_url).hostname or ""
        self.root = registrable_domain(self.base_host)
        self.include_subdomains = include_subdomains
        self.extra = {h.strip().lower() for h in (extra_hosts or []) if h.strip()}

    def in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if host == self.base_host or host in self.extra:
            return True
        if self.include_subdomains and (host == self.root or host.endswith("." + self.root)):
            return True
        return False

    def require(self, url: str) -> None:
        if not self.in_scope(url):
            raise ScopeError(f"Out of scope: {url}")
