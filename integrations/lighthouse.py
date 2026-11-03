"""Lighthouse CLI integration (requires Node.js + `npm i -g lighthouse`)."""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from engine.environment import find_lighthouse
from integrations.pagespeed import parse_pagespeed


class LighthouseMissing(RuntimeError):
    pass


def run_lighthouse(url: str, form_factor: str = "desktop", timeout: int = 240, chrome_path: str | None = None) -> dict[str, Any]:
    exe = find_lighthouse()
    if not exe:
        raise LighthouseMissing("Lighthouse CLI not found. Install Node.js LTS and run: npm install -g lighthouse")
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "lh.json"
        cmd = [exe, url, "--output=json", f"--output-path={out}", "--quiet",
               "--chrome-flags=--headless=new --no-sandbox", "--only-categories=performance,accessibility,best-practices,seo"]
        if form_factor == "desktop":
            cmd.append("--preset=desktop")
        env = None
        if chrome_path:
            import os
            env = dict(os.environ, CHROME_PATH=chrome_path)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, shell=False)
        if proc.returncode != 0 or not out.exists():
            raise RuntimeError(f"Lighthouse failed (exit {proc.returncode}): {proc.stderr[-400:]}")
        data = json.loads(out.read_text(encoding="utf-8"))
    return parse_pagespeed({"lighthouseResult": data})
