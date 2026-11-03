"""Common result schema shared by every scanner module."""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Informational"
    MANUAL = "Needs Manual Verification"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.MANUAL: 4,
    Severity.INFO: 5,
}


class CheckStatus(str, Enum):
    PASSED = "Passed"
    FAILED = "Failed"
    NOT_APPLICABLE = "Not Applicable"
    NOT_TESTED = "Not Tested"
    MANUAL = "Needs Manual Verification"
    ERROR = "Error"


class VerificationStatus(str, Enum):
    CONFIRMED = "Confirmed"
    UNVERIFIED = "Needs Verification"
    FALSE_POSITIVE = "False Positive"


class Category(str, Enum):
    SECURITY = "Security"
    API_SECURITY = "API Security"
    PERFORMANCE = "Performance"
    INFRASTRUCTURE = "Infrastructure"


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    title: str
    severity: Severity
    affected_url: str
    description: str
    evidence: str
    impact: str
    recommendation: str
    module: str
    category: Category = Category.SECURITY
    reproduction_steps: str = ""
    verification_status: VerificationStatus = VerificationStatus.CONFIRMED
    references: str = ""
    finding_id: str = field(default_factory=lambda: f"F-{uuid.uuid4().hex[:8].upper()}")
    timestamp: str = field(default_factory=utcnow_iso)

    @property
    def fingerprint(self) -> str:
        key = f"{self.module}|{self.title}|{self.affected_url}".lower()
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        d["verification_status"] = self.verification_status.value
        d["fingerprint"] = self.fingerprint
        return d


@dataclass
class CheckResult:
    """One individual check (e.g. 'HSTS header present')."""

    name: str
    status: CheckStatus
    module: str
    category: Category = Category.SECURITY
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "module": self.module,
            "category": self.category.value,
            "detail": self.detail,
        }


@dataclass
class Metric:
    name: str
    value: float | str | None
    unit: str = ""
    module: str = ""
    context: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ModuleResult:
    module: str
    status: str = "completed"  # completed | failed | skipped | cancelled
    findings: list[Finding] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    metrics: list[Metric] = field(default_factory=list)
    error: str = ""
    started_at: str = field(default_factory=utcnow_iso)
    finished_at: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
