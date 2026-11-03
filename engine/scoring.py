"""Scoring. Untested checks never count as passed.

Per category:
  score = 100 * passed / (passed + failed + error)   -- only executed, applicable checks
  then deduct finding penalties: Critical 25, High 12, Medium 5, Low 2 (floor 0)
Coverage = executed checks / (all checks excluding Not Applicable).
A category with zero executed checks gets score = None ("Not tested").
"""
from __future__ import annotations

from typing import Any, Iterable

PENALTY = {"Critical": 25, "High": 12, "Medium": 5, "Low": 2}
CATEGORIES = ("Security", "API Security", "Performance", "Infrastructure")

METHODOLOGY = (
    "Each category score = 100 x passed / executed checks (Passed + Failed + Error), minus finding penalties "
    "(Critical 25, High 12, Medium 5, Low 2; minimum 0). Checks marked Not Tested or Needs Manual Verification are "
    "excluded from the pass rate and are never counted as passed. Coverage = executed checks / applicable checks. "
    "Performance score uses the PageSpeed/Lighthouse performance score when available. A category with no executed "
    "checks is reported as 'Not tested' rather than 0 or 100."
)


def status_counts(checks: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {"Passed": 0, "Failed": 0, "Not Applicable": 0, "Not Tested": 0, "Needs Manual Verification": 0, "Error": 0}
    for c in checks:
        counts[c["status"]] = counts.get(c["status"], 0) + 1
    return counts


def severity_counts(findings: Iterable[dict[str, Any]]) -> dict[str, int]:
    out = {s: 0 for s in ("Critical", "High", "Medium", "Low", "Informational", "Needs Manual Verification")}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def compute_scores(checks: list[dict[str, Any]], findings: list[dict[str, Any]], metrics: list[dict[str, Any]]) -> dict[str, Any]:
    scores: dict[str, Any] = {}
    for cat in CATEGORIES:
        cs = [c for c in checks if c["category"] == cat]
        cnt = status_counts(cs)
        executed = cnt["Passed"] + cnt["Failed"] + cnt["Error"]
        if executed == 0:
            scores[cat] = None
            continue
        base = 100.0 * cnt["Passed"] / executed
        penalty = sum(PENALTY.get(f["severity"], 0) for f in findings
                      if f["category"] == cat and f.get("verification_status") != "False Positive")
        scores[cat] = max(0.0, round(base - penalty, 1))
    perf = [m for m in metrics if m["name"] in ("PageSpeed performance score (mobile)", "PageSpeed performance score (desktop)",
                                                "Lighthouse performance score")]
    vals = [float(m["value"]) for m in perf if m["value"] not in (None, "", "None")]
    if vals:
        scores["Performance"] = round(sum(vals) / len(vals), 1)
    cnt = status_counts(checks)
    applicable = sum(cnt.values()) - cnt["Not Applicable"]
    executed = cnt["Passed"] + cnt["Failed"] + cnt["Error"]
    scores["Coverage"] = round(100.0 * executed / applicable, 1) if applicable else 0.0
    scores["check_counts"] = cnt
    scores["severity_counts"] = severity_counts(findings)
    scores["methodology"] = METHODOLOGY
    return scores
