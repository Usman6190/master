"""Pre-flight environment validation (dependencies, connectivity, disk, permissions)."""
from __future__ import annotations

import importlib
import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from config.settings import app_data_dir, reports_dir


@dataclass
class EnvCheck:
    name: str
    ok: bool
    detail: str
    required: bool = True
    fix: str = ""


def _which(*names: str) -> str | None:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def find_lighthouse() -> str | None:
    return os.environ.get("CSAB_LIGHTHOUSE") or _which("lighthouse", "lighthouse.cmd")


def find_jmeter() -> str | None:
    env = os.environ.get("JMETER_HOME")
    if env:
        for n in ("bin/jmeter.bat", "bin/jmeter"):
            p = Path(env) / n
            if p.exists():
                return str(p)
    return _which("jmeter", "jmeter.bat")


def playwright_browser_ok() -> tuple[bool, str]:
    try:
        importlib.import_module("playwright")
    except ImportError:
        return False, "playwright package not installed"
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            path = p.chromium.executable_path
        return Path(path).exists(), path
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def validate(target_url: str = "", check_browser: bool = True) -> list[EnvCheck]:
    out: list[EnvCheck] = []
    out.append(EnvCheck("Python runtime", sys.version_info >= (3, 10), sys.version.split()[0]))
    for mod in ("PySide6", "requests", "cryptography", "reportlab", "openpyxl", "dns"):
        try:
            importlib.import_module(mod)
            out.append(EnvCheck(f"Library: {mod}", True, "installed"))
        except ImportError:
            out.append(EnvCheck(f"Library: {mod}", False, "missing", fix="Reinstall the application."))
    if target_url:
        parsed = urlparse(target_url if "://" in target_url else "https://" + target_url)
        host = parsed.hostname or ""
        port = parsed.port or (80 if parsed.scheme == "http" else 443)
        try:
            socket.getaddrinfo(host, 443)
            out.append(EnvCheck("DNS resolution of target", True, host))
            try:
                socket.create_connection((host, port), timeout=8).close()
                out.append(EnvCheck("Internet connectivity to target", True, f"{host}:{port} reachable"))
            except OSError as exc:
                out.append(EnvCheck("Internet connectivity to target", False, str(exc),
                                    fix="Check internet connection, proxy or firewall."))
        except OSError as exc:
            out.append(EnvCheck("DNS resolution of target", False, str(exc),
                                fix="Check the URL and your internet/DNS settings."))
    free = shutil.disk_usage(reports_dir()).free // (1024 * 1024)
    out.append(EnvCheck("Disk space for reports", free > 200, f"{free} MB free", fix="Free at least 200 MB."))
    try:
        t = app_data_dir() / ".write_test"
        t.write_text("ok")
        t.unlink()
        out.append(EnvCheck("App data folder writable", True, str(app_data_dir())))
    except OSError as exc:
        out.append(EnvCheck("App data folder writable", False, str(exc), fix="Run with a user that can write AppData."))
    if check_browser:
        ok, detail = playwright_browser_ok()
        out.append(EnvCheck("Playwright Chromium (DOM XSS / browser checks)", ok, detail, required=False,
                            fix="Settings > Install browser, or run: playwright install chromium"))
    lh = find_lighthouse()
    out.append(EnvCheck("Lighthouse CLI (optional)", bool(lh), lh or "not found", required=False,
                        fix="Install Node.js LTS then: npm install -g lighthouse"))
    if lh:
        out[-1].detail = lh
    jm = find_jmeter()
    out.append(EnvCheck("Apache JMeter (optional, load tests)", bool(jm), jm or "not found", required=False,
                        fix="Install Java 17+ and JMeter, then set JMETER_HOME."))
    java = _which("java")
    if jm and not java:
        out.append(EnvCheck("Java runtime for JMeter", False, "java not on PATH", required=False,
                            fix="Install a Java 17+ runtime."))
    return out


def run_version(cmd: list[str]) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return f"error: {exc}"
