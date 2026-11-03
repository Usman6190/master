"""testssl.sh and Qualys SSL Labs (API v4) integrations for deep TLS assessment."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

import requests

SSLLABS_API = "https://api.ssllabs.com/api/v4/analyze"


class ToolMissing(RuntimeError):
    pass


def find_testssl(configured: str = "") -> list[str] | None:
    if configured and Path(configured).exists():
        p = Path(configured)
        if p.suffix == ".sh" and shutil.which("bash"):
            return [shutil.which("bash") or "bash", str(p)]
        return [str(p)]
    for name in ("testssl.sh", "testssl"):
        exe = shutil.which(name)
        if exe:
            return [exe]
    return None


def run_testssl(host: str, configured: str = "", timeout: int = 900) -> list[dict[str, Any]]:
    cmd = find_testssl(configured)
    if not cmd:
        raise ToolMissing("testssl.sh not found. Install it (https://testssl.sh; on Windows via Git Bash/WSL) "
                          "and set its path in configuration.")
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "testssl.json"
        proc = subprocess.run(cmd + ["--quiet", "--warnings", "batch", "--color", "0", "--jsonfile", str(out), host],
                              capture_output=True, text=True, timeout=timeout, shell=False)
        if not out.exists():
            raise RuntimeError(f"testssl.sh failed (exit {proc.returncode}): {(proc.stderr or proc.stdout)[-400:]}")
        return json.loads(out.read_text(encoding="utf-8") or "[]")


def ssllabs_analyze(host: str, email: str, max_minutes: float = 15,
                    cancel: threading.Event | None = None) -> dict[str, Any]:
    """Run an SSL Labs assessment (publish=off). API v4 requires a registered email."""
    if not email:
        raise ToolMissing("SSL Labs API v4 requires a registered email (register at https://api.ssllabs.com/api/v4/register).")
    headers = {"email": email}
    params = {"host": host, "publish": "off", "all": "done", "startNew": "on"}
    deadline = time.monotonic() + max_minutes * 60
    while True:
        r = requests.get(SSLLABS_API, params=params, headers=headers, timeout=60)
        if r.status_code in (429, 529):
            time.sleep(30)
            continue
        if r.status_code != 200:
            raise RuntimeError(f"SSL Labs API HTTP {r.status_code}: {r.text[:200]}")
        data = r.json()
        if data.get("status") in ("READY", "ERROR"):
            if data.get("status") == "ERROR":
                raise RuntimeError(f"SSL Labs error: {data.get('statusMessage')}")
            return data
        if time.monotonic() > deadline:
            raise RuntimeError("SSL Labs assessment timed out")
        if cancel is not None and cancel.is_set():
            raise RuntimeError("Cancelled")
        params.pop("startNew", None)
        time.sleep(10)
