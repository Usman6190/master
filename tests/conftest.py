import os
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
_tmp = tempfile.mkdtemp(prefix="csab_test_")
os.environ.setdefault("CSAB_DATA_DIR", _tmp)
os.environ.setdefault("CSAB_REPORTS_DIR", os.path.join(_tmp, "reports"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def mock_site():
    from tests.mock_site import start_mock_server
    srv, url = start_mock_server()
    yield url
    srv.shutdown()


@pytest.fixture
def db(tmp_path):
    from database.db_manager import DBManager
    return DBManager(tmp_path / "t.db")


@pytest.fixture
def ctx_factory(mock_site):
    import threading
    from scanners.base import AuditContext
    from security.scope_validator import ScopeValidator
    from utils.http_client import AuditHTTPClient

    def make(config=None, secrets=None):
        cfg = {"target_url": mock_site, "api_base_url": mock_site, **(config or {})}
        client = AuditHTTPClient(ScopeValidator(mock_site), timeout=5, max_rps=0, cancel_event=threading.Event())
        return AuditContext(target_url=mock_site, client=client, config=cfg, secrets=secrets or {})
    return make


FULL_CFG = {"login_endpoint": "/api/auth/login", "login_username": "known@example.com",
            "protected_endpoints": "/api/me", "admin_endpoints": "/api/admin/users",
            "idor_endpoint_template": "/api/users/{id}", "idor_own_id": "1", "idor_other_id": "2",
            "search_endpoint": "/api/assets/search?q=logo&sort=asc", "asset_download_template": "/api/assets/{id}/download",
            "asset_test_ids": "1001", "asset_page_template": "/asset/{id}", "preview_url_template": "/previews/{id}.jpg",
            "bruteforce_attempts": 4, "rate_limit_burst": 6, "response_samples": 3, "browser_checks": False,
            "run_lighthouse": False, "timeout": 5, "max_rps": 0}
FULL_SECRETS = {"api_token": "user-token", "login_password": "correct-password"}
