"""Unit tests: models, scope, credentials, redaction, scoring, normalization, parsers, DB."""
import json

import pytest

from core.models import Category, CheckResult, CheckStatus, Finding, ModuleResult, Severity
from engine.result_normalizer import normalize
from engine.scoring import compute_scores
from integrations.jmeter import build_jmx, parse_jtl
from integrations.pagespeed import parse_pagespeed
from security.credential_manager import CredentialManager
from security.scope_validator import ScopeError, ScopeValidator, normalize_url
from scanners.security.csp import parse_csp
from utils.logging_setup import redact, register_secret


def _f(title="t", sev=Severity.HIGH, url="https://x/", module="M"):
    return Finding(title=title, severity=sev, affected_url=url, description="d", evidence="e", impact="i",
                   recommendation="r", module=module)


def test_severity_rank_order():
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.MEDIUM.rank < Severity.LOW.rank < Severity.INFO.rank


def test_finding_fingerprint_stable_and_dict():
    a, b = _f(), _f()
    assert a.fingerprint == b.fingerprint and a.finding_id != b.finding_id
    d = a.to_dict()
    assert d["severity"] == "High" and d["verification_status"] == "Confirmed" and "fingerprint" in d


def test_scope_validator():
    s = ScopeValidator("https://www.creativestall.com/")
    assert s.in_scope("https://www.creativestall.com/a")
    assert s.in_scope("https://api.creativestall.com/x")
    assert not s.in_scope("https://evil.com/")
    assert not s.in_scope("https://creativestall.com.evil.com/")
    with pytest.raises(ScopeError):
        s.require("https://google.com")
    assert normalize_url("creativestall.com") == "https://creativestall.com/"
    with pytest.raises(ScopeError):
        normalize_url("ftp://x")


def test_credential_roundtrip_and_encrypted_at_rest(tmp_path):
    cm = CredentialManager(tmp_path)
    cm.save({"api_token": "SuperSecretToken123", "login_password": "P@ssw0rd!!"})
    raw = (tmp_path / "credentials.enc").read_text()
    assert "SuperSecretToken123" not in raw and "P@ssw0rd!!" not in raw
    assert CredentialManager(tmp_path).load() == {"api_token": "SuperSecretToken123", "login_password": "P@ssw0rd!!"}
    cm.clear()
    assert CredentialManager(tmp_path).load() == {}


def test_redaction():
    register_secret("my-registered-secret-value")
    s = redact("Authorization: Bearer abc.def.ghi password=hunter2 url?api_key=XYZ my-registered-secret-value")
    assert "abc.def" not in s and "hunter2" not in s and "XYZ" not in s and "my-registered-secret-value" not in s


def test_normalizer_dedup_and_redacts():
    seen = set()
    r = ModuleResult("M", findings=[_f(sev=Severity.LOW), _f(sev=Severity.LOW), _f("other", Severity.CRITICAL)])
    r.findings[0].evidence = "token=SECRETVALUE"
    out = normalize(r, seen)
    assert len(out.findings) == 2 and out.findings[0].severity == Severity.CRITICAL
    assert "SECRETVALUE" not in out.findings[1].evidence


def test_scoring_untested_not_counted_as_passed():
    checks = [CheckResult("a", CheckStatus.PASSED, "m").to_dict(), CheckResult("b", CheckStatus.NOT_TESTED, "m").to_dict(),
              CheckResult("c", CheckStatus.MANUAL, "m").to_dict()]
    s = compute_scores(checks, [], [])
    assert s["Security"] == 100.0 and s["API Security"] is None and s["Coverage"] == pytest.approx(33.3)
    checks.append(CheckResult("d", CheckStatus.FAILED, "m").to_dict())
    s = compute_scores(checks, [_f(sev=Severity.HIGH).to_dict()], [])
    assert s["Security"] == 50 - 12
    only_untested = compute_scores([CheckResult("x", CheckStatus.NOT_TESTED, "m", Category.API_SECURITY).to_dict()], [], [])
    assert only_untested["API Security"] is None


def test_csp_parser():
    d = parse_csp("default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'")
    assert d["script-src"] == ["'self'", "'unsafe-inline'"] and d["object-src"] == ["'none'"]


def test_pagespeed_parser():
    data = {"lighthouseResult": {"categories": {"performance": {"score": 0.42}, "seo": {"score": 0.9}},
            "audits": {"largest-contentful-paint": {"numericValue": 5100.0, "displayValue": "5.1 s", "numericUnit": "millisecond"},
                       "render-blocking-resources": {"score": 0.3, "title": "Eliminate render-blocking",
                                                     "details": {"type": "opportunity", "overallSavingsMs": 800}}}},
            "loadingExperience": {"metrics": {"LARGEST_CONTENTFUL_PAINT_MS": {"percentile": 3200, "category": "AVERAGE"}}}}
    p = parse_pagespeed(data)
    assert p["scores"] == {"performance": 42, "seo": 90}
    assert p["metrics"]["Largest Contentful Paint"]["value"] == 5100.0
    assert p["opportunities"][0]["savings_ms"] == 800
    assert p["field_data"]["LARGEST_CONTENTFUL_PAINT_MS"]["p75"] == 3200


def test_jmeter_jmx_and_jtl(tmp_path):
    jmx = build_jmx(["https://www.creativestall.com/search?q=a&b=1"], 10, 30, 60)
    assert "<stringProp name=\"ThreadGroup.num_threads\">10</stringProp>" in jmx and "&amp;b=1" in jmx
    jtl = tmp_path / "r.jtl"
    jtl.write_text("timeStamp,elapsed,label,responseCode,success\n" +
                   "\n".join(f"{1000 + i * 100},{100 + i},home,200,{'false' if i == 9 else 'true'}" for i in range(10)))
    r = parse_jtl(jtl)
    assert r["samples"] == 10 and r["errors"] == 1 and r["error_rate"] == 10.0 and r["max_ms"] == 109


def test_db_operations_and_compare(db):
    a1 = db.create_audit("https://x/", "full", {"api_token": "SECRET", "target_url": "https://x/"})
    assert "SECRET" not in json.dumps(db.get_audit(a1))
    r = ModuleResult("M", findings=[_f("one"), _f("two")], checks=[CheckResult("c", CheckStatus.PASSED, "M")])
    db.save_module_result(a1, r)
    db.finish_audit(a1, "completed", 1.0, {})
    a2 = db.create_audit("https://x/", "full", {})
    db.save_module_result(a2, ModuleResult("M", findings=[_f("two"), _f("three")]))
    cmp = db.compare(a1, a2)
    assert [f["title"] for f in cmp["new"]] == ["three"] and [f["title"] for f in cmp["resolved"]] == ["one"]
    assert len(db.list_audits(search="x")) == 2 and db.stats()["total_audits"] == 2
    db.delete_audit(a1)
    assert db.get_findings(a1) == [] and len(db.list_audits()) == 1
