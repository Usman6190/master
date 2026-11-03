"""ZAP / testssl / SSL Labs modules with mocked tools."""
from unittest import mock

from core.models import CheckStatus, Severity


def test_zap_disabled_is_not_tested(ctx_factory):
    from scanners.security.external_tools import ZAPScanner
    r = ZAPScanner().run(ctx_factory())
    assert r.status == "skipped" and r.checks[0].status == CheckStatus.NOT_TESTED


def test_zap_unreachable_recorded(ctx_factory):
    from scanners.security.external_tools import ZAPScanner
    r = ZAPScanner().run(ctx_factory({"zap_enabled": True, "zap_api_url": "http://127.0.0.1:1"}))
    assert r.status == "failed" and r.checks[0].status == CheckStatus.ERROR and "Cannot reach ZAP" in r.error


def test_zap_alerts_mapped(ctx_factory, mock_site):
    from scanners.security.external_tools import ZAPScanner
    alerts = [{"pluginId": "10038", "alert": "CSP Header Not Set", "risk": "Medium", "confidence": "High",
               "url": mock_site, "description": "d", "solution": "s"},
              {"pluginId": "10038", "alert": "CSP Header Not Set", "risk": "Medium", "confidence": "High",
               "url": mock_site + "search", "description": "d", "solution": "s"},
              {"pluginId": "1", "alert": "FP", "risk": "High", "confidence": "False Positive", "url": mock_site},
              {"pluginId": "2", "alert": "Out of scope", "risk": "High", "confidence": "High", "url": "https://evil.example/"}]
    with mock.patch("integrations.zap.ZAPClient.version", return_value="2.16"), \
         mock.patch("integrations.zap.ZAPClient.spider", return_value=7), \
         mock.patch("integrations.zap.ZAPClient.wait_passive"), \
         mock.patch("integrations.zap.ZAPClient.alerts", return_value=alerts):
        r = ZAPScanner().run(ctx_factory({"zap_enabled": True}))
    assert [f.title for f in r.findings] == ["ZAP: CSP Header Not Set"]
    assert r.findings[0].severity == Severity.MEDIUM and "2 URL(s)" in r.findings[0].evidence
    assert r.checks[0].status == CheckStatus.FAILED


def test_testssl_and_ssllabs(ctx_factory):
    from scanners.security.external_tools import TLSDeepScanner
    items = [{"id": "TLS1", "severity": "LOW", "finding": "offered"}, {"id": "SSLv3", "severity": "OK", "finding": "not offered"}]
    labs = {"endpoints": [{"ipAddress": "1.2.3.4", "grade": "B"}]}
    with mock.patch("scanners.security.external_tools.run_testssl", return_value=items), \
         mock.patch("scanners.security.external_tools.ssllabs_analyze", return_value=labs):
        r = TLSDeepScanner().run(ctx_factory({"testssl_enabled": True, "ssllabs_enabled": True, "ssllabs_email": "a@b.c"}))
    titles = {f.title: f.severity for f in r.findings}
    assert titles == {"testssl.sh: TLS1": Severity.LOW, "SSL Labs grade below A": Severity.MEDIUM}


def test_testssl_missing_not_tested(ctx_factory):
    from scanners.security.external_tools import TLSDeepScanner
    with mock.patch("integrations.tls_tools.find_testssl", return_value=None):
        r = TLSDeepScanner().run(ctx_factory({"testssl_enabled": True}))
    assert r.checks[0].status == CheckStatus.NOT_TESTED and "not found" in r.checks[0].detail
