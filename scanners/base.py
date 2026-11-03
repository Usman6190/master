"""Base class for every audit module."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable

from core.models import Category, CheckResult, CheckStatus, Finding, Metric, ModuleResult, Severity, utcnow_iso
from utils.http_client import AuditHTTPClient


@dataclass
class AuditContext:
    target_url: str
    client: AuditHTTPClient
    config: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, str] = field(default_factory=dict)
    shared: dict[str, Any] = field(default_factory=dict)  # data passed between modules (e.g. discovered URLs)
    progress: Callable[[str], None] = lambda msg: None


class BaseScanner:
    name: str = "BaseScanner"
    category: Category = Category.SECURITY
    description: str = ""
    requires: tuple[str, ...] = ()  # config keys that must be present, otherwise module is Not Tested

    def __init__(self) -> None:
        self.log = logging.getLogger(f"scanner.{self.name}")
        self.result = ModuleResult(module=self.name)

    # helpers -------------------------------------------------------------
    def finding(self, title: str, severity: Severity, url: str, description: str, evidence: str,
                impact: str, recommendation: str, **kw: Any) -> Finding:
        f = Finding(title=title, severity=severity, affected_url=url, description=description, evidence=evidence,
                    impact=impact, recommendation=recommendation, module=self.name,
                    category=kw.pop("category", self.category), **kw)
        self.result.findings.append(f)
        return f

    def check(self, name: str, status: CheckStatus, detail: str = "", category: Category | None = None) -> None:
        self.result.checks.append(CheckResult(name=name, status=status, module=self.name,
                                              category=category or self.category, detail=detail))

    def metric(self, name: str, value: Any, unit: str = "", context: str = "") -> None:
        self.result.metrics.append(Metric(name=name, value=value, unit=unit, module=self.name, context=context))

    def missing_requirements(self, ctx: AuditContext) -> list[str]:
        return [k for k in self.requires if not (ctx.config.get(k) or ctx.secrets.get(k))]

    # entry point ---------------------------------------------------------
    def run(self, ctx: AuditContext) -> ModuleResult:
        self.result = ModuleResult(module=self.name)
        missing = self.missing_requirements(ctx)
        if missing:
            self.result.status = "skipped"
            self.result.error = f"Not tested: missing configuration {', '.join(missing)}"
            self.check(f"{self.name} execution", CheckStatus.NOT_TESTED, self.result.error)
        else:
            self.execute(ctx)
        self.result.finished_at = utcnow_iso()
        return self.result

    def execute(self, ctx: AuditContext) -> None:  # pragma: no cover - abstract
        raise NotImplementedError
