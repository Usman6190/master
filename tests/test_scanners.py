"""Scanner tests against the local mock marketplace (deliberately vulnerable) — no live site needed."""
from unittest import mock

from core.models import CheckStatus
from tests.conftest import FULL_CFG, FULL_SECRETS


def _titles(res):
    return {f.title for f in res.findings}


def _run(cls, ctx):
    return cls().run(ctx)


def test_discovery_and_headers(ctx_factory):
    from scanners.security.discovery import WebsiteDiscovery
    from scanners.security.headers import SecurityHeadersScanner
    ctx = ctx_factory()
    d = _run(WebsiteDiscovery, ctx)
    assert d.status == "completed" and ctx.shared["query_params"]
    h = _run(SecurityHeadersScanner, ctx)
    t = _titles(h)
    assert "Missing HTTP Strict-Transport-Security header" in t and "Server/technology version disclosure" in t


def test_cors_csp_exposure(ctx_factory):
    from scanners.security.cors import CORSScanner
    from scanners.security.csp import CSPScanner
    from scanners.security.exposure import PublicExposureScanner
    ctx = ctx_factory()
    assert "CORS trusts arbitrary origin with credentials" in _titles(_run(CORSScanner, ctx))
    assert "Missing Content-Security-Policy" in _titles(_run(CSPScanner, ctx))
    ex = _titles(_run(PublicExposureScanner, ctx))
    assert "Sensitive file exposed: /.git/HEAD" in ex and "Open redirect" in ex
    assert not any("/.env" in x for x in ex)  # 404 on mock -> must not be reported


def test_api_modules_detect_mock_vulns(ctx_factory):
    from scanners.api.access import IDORTester, RateLimitTester, RBACScanner
    from scanners.api.auth import AuthenticationTester, SessionSecurityTester
    ctx = ctx_factory(FULL_CFG, FULL_SECRETS)
    a = _titles(_run(AuthenticationTester, ctx))
    assert "Account enumeration via login response" in a and "No observable login rate limiting" in a
    assert any("Cookie 'session'" in t for t in _titles(_run(SessionSecurityTester, ctx)))
    assert "Broken function-level authorization (RBAC)" in _titles(_run(RBACScanner, ctx))
    assert "Insecure Direct Object Reference (IDOR)" in _titles(_run(IDORTester, ctx))
    assert "No API rate limiting observed on search endpoint" in _titles(_run(RateLimitTester, ctx))


def test_injection_and_xss(ctx_factory):
    from scanners.security.discovery import WebsiteDiscovery
    from scanners.security.injection import InjectionScanner, XSSScanner
    ctx = ctx_factory(FULL_CFG, FULL_SECRETS)
    _run(WebsiteDiscovery, ctx)
    assert "SQL injection indicator (database error triggered)" in _titles(_run(InjectionScanner, ctx))
    assert "Reflected Cross-Site Scripting (XSS)" in _titles(_run(XSSScanner, ctx))


def test_marketplace_and_missing_config(ctx_factory):
    from scanners.assets.marketplace import AssetProtectionScanner, UploadSecurityTester
    ctx = ctx_factory(FULL_CFG, FULL_SECRETS)
    assert "Original asset downloadable without authentication" in _titles(_run(AssetProtectionScanner, ctx))
    up = _run(UploadSecurityTester, ctx)
    assert up.status == "skipped" and up.checks[0].status == CheckStatus.NOT_TESTED


def test_pagespeed_mocked(ctx_factory):
    from scanners.performance.performance import PageSpeedAnalyzer
    fake = {"scores": {"performance": 35}, "opportunities": [], "field_data": {},
            "metrics": {"Largest Contentful Paint": {"value": 6000.0, "display": "6.0 s", "unit": "ms"}}}
    ctx = ctx_factory({"device_mode": "mobile"})
    with mock.patch("scanners.performance.performance.run_pagespeed", return_value=fake):
        r = _run(PageSpeedAnalyzer, ctx)
    names = {m.name: m.value for m in r.metrics}
    assert names["PageSpeed performance score (mobile)"] == 35
    assert "Poor Largest Contentful Paint (PageSpeed Mobile)" in _titles(r)


def test_pagespeed_failure_recorded_not_silent(ctx_factory):
    from integrations.pagespeed import PageSpeedError
    from scanners.performance.performance import PageSpeedAnalyzer
    with mock.patch("scanners.performance.performance.run_pagespeed", side_effect=PageSpeedError("Invalid Google PageSpeed API key")):
        r = _run(PageSpeedAnalyzer, ctx_factory({"device_mode": "desktop"}))
    assert r.status == "failed" and "Invalid" in r.error and r.checks[0].status == CheckStatus.ERROR


def test_jmeter_disabled_and_production_guard(ctx_factory):
    from scanners.performance.performance import JMeterController
    r = _run(JMeterController, ctx_factory())
    assert r.checks[0].status == CheckStatus.NOT_TESTED
    r = _run(JMeterController, ctx_factory({"load_test_enabled": True, "load_test_environment": "production"}))
    assert r.checks[0].status == CheckStatus.NOT_TESTED and "confirmation" in r.checks[0].detail


def test_lighthouse_missing_is_reported(ctx_factory):
    from scanners.performance.performance import LighthouseAnalyzer
    with mock.patch("integrations.lighthouse.find_lighthouse", return_value=None):
        r = _run(LighthouseAnalyzer, ctx_factory({"run_lighthouse": True}))
    assert r.status == "skipped" and "Lighthouse CLI not found" in r.error


def test_out_of_scope_request_blocked(ctx_factory):
    import pytest
    from security.scope_validator import ScopeError
    with pytest.raises(ScopeError):
        ctx_factory().client.get("https://example.org/")
