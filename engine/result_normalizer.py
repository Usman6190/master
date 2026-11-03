"""Normalizes and de-duplicates findings across modules."""
from __future__ import annotations

from core.models import Finding, ModuleResult
from utils.logging_setup import redact


def normalize(result: ModuleResult, seen: set[str]) -> ModuleResult:
    unique: list[Finding] = []
    for f in result.findings:
        f.evidence = redact(f.evidence or "")[:4000]
        f.reproduction_steps = redact(f.reproduction_steps or "")
        f.affected_url = redact(f.affected_url or "")
        if f.fingerprint in seen:
            continue
        seen.add(f.fingerprint)
        unique.append(f)
    result.findings = sorted(unique, key=lambda x: x.severity.rank)
    for c in result.checks:
        c.detail = redact(c.detail or "")[:1000]
    result.error = redact(result.error or "")
    return result
