"""OWASP ZAP passive scan and deep TLS (testssl.sh / SSL Labs) modules."""
from __future__ import annotations

import json
from urllib.parse import urlparse

from core.models import CheckStatus, Severity, VerificationStatus
from integrations.tls_tools import ToolMissing, run_testssl, ssllabs_analyze
from integrations.zap import ZAPClient, ZAPError, group_alerts
from scanners.base import AuditContext, BaseScanner

ZAP_RISK = {"High": Severity.HIGH, "Medium": Severity.MEDIUM, "Low": Severity.LOW, "Informational": Severity.INFO}
TESTSSL_SEV = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}


class ZAPScanner(BaseScanner):
    name = "ZAPScanner"
    description = "OWASP ZAP spider + passive scan via local ZAP API (no active attacks)."

    def execute(self, ctx: AuditContext) -> None:
        if not ctx.config.get("zap_enabled"):
            self.result.status = "skipped"
            self.check("OWASP ZAP passive scan", CheckStatus.NOT_TESTED, "Disabled in configuration")
            return
        zap = ZAPClient(ctx.config.get("zap_api_url") or "http://127.0.0.1:8080", ctx.secrets.get("zap_api_key", ""))
        cancel = ctx.client.cancel_event
        try:
            ver = zap.version()
            ctx.progress(f"ZAP {ver}: spidering {ctx.target_url}")
            urls = zap.spider(ctx.target_url, int(ctx.config.get("zap_max_children", 50)),
                              float(ctx.config.get("zap_max_minutes", 10)), cancel)
            zap.wait_passive(5, cancel)
            alerts = group_alerts(zap.alerts(ctx.target_url))
        except ZAPError as exc:
            self.result.status = "failed"
            self.result.error = str(exc)
            self.check("OWASP ZAP passive scan", CheckStatus.ERROR, str(exc))
            return
        self.metric("ZAP URLs spidered", urls)
        self.metric("ZAP distinct alerts", len(alerts))
        for a in alerts:
            if not ctx.client.scope.in_scope(a.get("url", ctx.target_url)):
                continue
            sev = ZAP_RISK.get(a.get("risk", ""), Severity.INFO)
            vs = VerificationStatus.UNVERIFIED if a.get("confidence") in ("Low", None) else VerificationStatus.CONFIRMED
            self.finding(f"ZAP: {a.get('alert') or a.get('name')}", sev, a.get("url", ctx.target_url),
                         a.get("description", ""),
                         f"ZAP pluginId {a.get('pluginId')}, confidence {a.get('confidence')}; evidence: "
                         f"{(a.get('evidence') or '')[:300]}; param: {a.get('param', '')}; "
                         f"{len(a['urls'])} URL(s): " + ", ".join(a["urls"][:5]),
                         "See ZAP alert description.", a.get("solution", ""),
                         verification_status=vs, references=a.get("reference", ""))
        self.check("OWASP ZAP passive scan", CheckStatus.FAILED if any(
            ZAP_RISK.get(a.get("risk", "")) in (Severity.HIGH, Severity.MEDIUM) for a in alerts) else CheckStatus.PASSED,
            f"{urls} URLs, {len(alerts)} distinct alerts")


class TLSDeepScanner(BaseScanner):
    name = "TLSDeepScanner"
    description = "Deep TLS assessment with testssl.sh and/or Qualys SSL Labs (when enabled)."

    def execute(self, ctx: AuditContext) -> None:
        host = urlparse(ctx.target_url).hostname or ""
        ran = False
        if ctx.config.get("testssl_enabled"):
            ran = True
            try:
                self._testssl(ctx, run_testssl(host, ctx.config.get("testssl_path", "")))
            except ToolMissing as exc:
                self.check("testssl.sh assessment", CheckStatus.NOT_TESTED, str(exc))
            except Exception as exc:  # noqa: BLE001
                self.check("testssl.sh assessment", CheckStatus.ERROR, str(exc)[:300])
        if ctx.config.get("ssllabs_enabled"):
            ran = True
            try:
                self._ssllabs(ctx, ssllabs_analyze(host, ctx.config.get("ssllabs_email", ""),
                                                   cancel=ctx.client.cancel_event))
            except ToolMissing as exc:
                self.check("SSL Labs assessment", CheckStatus.NOT_TESTED, str(exc))
            except Exception as exc:  # noqa: BLE001
                self.check("SSL Labs assessment", CheckStatus.ERROR, str(exc)[:300])
        if not ran:
            self.result.status = "skipped"
            self.check("Deep TLS assessment (testssl.sh / SSL Labs)", CheckStatus.NOT_TESTED, "Disabled in configuration")

    def _testssl(self, ctx: AuditContext, items: list[dict]) -> None:
        bad = [i for i in items if i.get("severity") in TESTSSL_SEV]
        for i in bad:
            self.finding(f"testssl.sh: {i.get('id')}", TESTSSL_SEV[i["severity"]], ctx.target_url,
                         f"testssl.sh reported: {i.get('finding')}", json.dumps(i)[:500],
                         "Weak TLS configuration can enable downgrade, interception or known TLS attacks.",
                         "Harden the TLS configuration per Mozilla 'intermediate' guidelines.",
                         references=i.get("cve", "") or "https://testssl.sh")
        self.check("testssl.sh assessment", CheckStatus.FAILED if bad else CheckStatus.PASSED,
                   f"{len(items)} items, {len(bad)} LOW+ issues")

    def _ssllabs(self, ctx: AuditContext, data: dict) -> None:
        grades = [(e.get("ipAddress"), e.get("grade") or e.get("statusMessage")) for e in data.get("endpoints", [])]
        for ip, g in grades:
            self.metric(f"SSL Labs grade ({ip})", g)
        worst = [g for _, g in grades if g and g[0] in "BCDEFT"]
        if worst:
            sev = Severity.HIGH if any(g[0] in "FT" for g in worst) else Severity.MEDIUM
            self.finding("SSL Labs grade below A", sev, ctx.target_url,
                         f"SSL Labs grades: {grades}", json.dumps(grades),
                         "Below-A grades indicate weak protocols, ciphers or certificate chain issues.",
                         "Review the SSL Labs report and remediate listed issues.",
                         references="https://www.ssllabs.com/ssltest/")
        self.check("SSL Labs assessment", CheckStatus.FAILED if worst else CheckStatus.PASSED, f"Grades: {grades}")



