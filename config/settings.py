"""Application paths and defaults."""
from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "CreativeStall Audit Bot"
APP_SLUG = "CreativeStallAuditBot"
APP_VERSION = "1.0.0"
DEFAULT_TARGET = "https://www.creativestall.com/"
USER_AGENT = f"{APP_SLUG}/{APP_VERSION} (authorized security audit)"


def app_data_dir() -> Path:
    override = os.environ.get("CSAB_DATA_DIR")
    if override:
        base = Path(override)
    elif sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_SLUG
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support" / APP_SLUG
    else:
        base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / APP_SLUG
    base.mkdir(parents=True, exist_ok=True)
    return base


def reports_dir() -> Path:
    override = os.environ.get("CSAB_REPORTS_DIR")
    d = Path(override) if override else Path.home() / "Documents" / "CreativeStall Audit Reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


def logs_dir() -> Path:
    d = app_data_dir() / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d


def db_path() -> Path:
    return app_data_dir() / "audit_history.sqlite3"


def resource_path(relative: str) -> Path:
    """Resolve bundled resources for both source runs and PyInstaller builds."""
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
    return base / relative
