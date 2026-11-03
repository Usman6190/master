"""Assembles everything a report needs from the database."""
from __future__ import annotations

import json
from typing import Any

from database.db_manager import DBManager
from engine.scoring import METHODOLOGY, compute_scores

SEV_ORDER = ["Critical", "High", "Medium", "Low", "Needs Manual Verification", "Informational"]

LIMITATIONS = [
    "Automated, non-destructive testing only. Results do not replace a manual penetration test.",
    "SQL injection and XSS tests use detection payloads only; exploitability was not attempted.",
    "Findings marked 'Needs Verification' are indicators and must be confirmed before being treated as vulnerabilities.",
    "CDN/WAF observations are inferred from public response headers, not from provider configuration.",
    "No port scanning or infrastructure intrusion was performed.",
    "Checks marked 'Not Tested' were not executed (missing configuration, credentials or tools) and are not counted as passed.",
    "Load-test profiles are test scenarios, not guaranteed production capacity.",
]

PRIOR_ASSESSMENT = (
    "A previous CreativeStall security assessment reported 26 gaps (2 Critical, 12 High, 10 Medium, 2 Low). "
    "Only the production CORS and CSP violations were directly observed in that assessment; other items were marked "
    "for verification. That assessment provided no JMeter results or measured performance baselines. This report "
    "contains only results from checks executed by this tool."
)


def load_report_data(db: DBManager, audit_id: int) -> dict[str, Any]:
    audit = db.get_audit(audit_id)
    if not audit:
        raise ValueError(f"Audit {audit_id} not found")
    findings = db.get_findings(audit_id)
    findings.sort(key=lambda f: SEV_ORDER.index(f["severity"]) if f["severity"] in SEV_ORDER else 99)
    checks = db.get_checks(audit_id)
    metrics = db.get_metrics(audit_id)
    scores = json.loads(audit.get("scores_json") or "{}") or compute_scores(checks, findings, metrics)
    return {
        "audit": audit,
        "config": json.loads(audit.get("config_json") or "{}"),
        "findings": findings,
        "checks": checks,
        "metrics": metrics,
        "modules": db.get_module_runs(audit_id),
        "errors": db.get_errors(audit_id),
        "scores": scores,
        "methodology": METHODOLOGY,
        "limitations": LIMITATIONS,
        "prior_assessment": PRIOR_ASSESSMENT,
    }


def executive_summary(d: dict[str, Any]) -> str:
    sc = d["scores"].get("severity_counts", {})
    cc = d["scores"].get("check_counts", {})
    a = d["audit"]
    sec = d["scores"].get("Security")
    return (f"{a['audit_type'].capitalize()} audit of {a['target_url']} finished with status '{a['status']}' in "
            f"{a.get('duration_s') or 0:.0f}s. {sum(cc.values())} checks were recorded: {cc.get('Passed', 0)} passed, "
            f"{cc.get('Failed', 0)} failed, {cc.get('Not Tested', 0)} not tested, "
            f"{cc.get('Needs Manual Verification', 0)} need manual verification, {cc.get('Error', 0)} errored. "
            f"Findings: {sc.get('Critical', 0)} Critical, {sc.get('High', 0)} High, {sc.get('Medium', 0)} Medium, "
            f"{sc.get('Low', 0)} Low, {sc.get('Needs Manual Verification', 0)} need verification. "
            f"Security score: {'Not tested' if sec is None else f'{sec}/100'}; coverage {d['scores'].get('Coverage', 0)}%.")


def remediation_roadmap(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    horizon = {"Critical": "Immediately (24-72h)", "High": "Within 2 weeks", "Medium": "Within 30 days",
               "Low": "Within 90 days", "Needs Manual Verification": "Verify within 2 weeks", "Informational": "Backlog"}
    return [{"priority": i + 1, "severity": f["severity"], "title": f["title"], "affected_url": f["affected_url"],
             "recommendation": f["recommendation"], "timeline": horizon.get(f["severity"], "Backlog"),
             "verification_status": f["verification_status"]}
            for i, f in enumerate(f for f in findings if f["severity"] != "Informational")]
