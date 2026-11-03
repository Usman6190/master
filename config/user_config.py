"""Persistent non-secret configuration (JSON). Secrets go through CredentialManager."""
from __future__ import annotations

import json
from typing import Any

from config.settings import DEFAULT_TARGET, app_data_dir

DEFAULTS: dict[str, Any] = {
    "target_url": DEFAULT_TARGET, "api_base_url": "", "login_endpoint": "", "login_username": "",
    "login_user_field": "email", "login_pass_field": "password", "logout_endpoint": "", "auth_probe_endpoint": "",
    "test_roles": "user", "protected_endpoints": "", "admin_endpoints": "", "public_api_endpoints": "",
    "idor_endpoint_template": "", "idor_own_id": "", "idor_other_id": "", "openapi_url": "",
    "search_endpoint": "", "injection_endpoints": "", "asset_download_template": "", "asset_page_template": "",
    "preview_url_template": "", "asset_test_ids": "", "upload_endpoint": "", "upload_allow_authenticated_tests": False,
    "include_subdomains": True, "extra_scope_hosts": "", "browser": "chromium", "browser_checks": True,
    "device_mode": "both", "run_lighthouse": True, "pagespeed_extra_urls": "", "timeout": 20, "max_rps": 5,
    "verify_tls": True, "response_samples": 10, "response_threshold_ms": 1000, "perf_endpoints": "",
    "bruteforce_attempts": 8, "rate_limit_burst": 20, "scrape_probe_count": 15,
    "load_test_enabled": False, "load_test_environment": "staging", "load_test_target_url": "",
    "load_profile": "Baseline", "load_custom_users": 10, "load_ramp_s": 60, "load_duration_s": 300,
    "load_error_stop_pct": 20, "production_load_confirmed": False, "production_traffic_ceiling": 0,
    "authorization_confirmed": False, "zap_enabled": False, "zap_api_url": "http://127.0.0.1:8080",
    "zap_max_children": 50, "zap_max_minutes": 10, "testssl_enabled": False, "testssl_path": "",
    "ssllabs_enabled": False, "ssllabs_email": "",
}
SECRET_KEYS = ("api_token", "login_password", "pagespeed_api_key", "zap_api_key")


def _path():
    return app_data_dir() / "config.json"


def load_config() -> dict[str, Any]:
    cfg = dict(DEFAULTS)
    try:
        cfg.update({k: v for k, v in json.loads(_path().read_text(encoding="utf-8")).items() if k not in SECRET_KEYS})
    except (OSError, ValueError):
        pass
    return cfg


def save_config(cfg: dict[str, Any]) -> None:
    _path().write_text(json.dumps({k: v for k, v in cfg.items() if k not in SECRET_KEYS}, indent=2), encoding="utf-8")
