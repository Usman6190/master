"""AuditManager: runs modules sequentially with isolation, cancellation, pause/resume, persistence."""
from __future__ import annotations

import logging
import threading
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable

from core.models import CheckStatus, ModuleResult, utcnow_iso
from database.db_manager import DBManager
from engine import registry
from engine.result_normalizer import normalize
from engine.scoring import compute_scores
from scanners.base import AuditContext, BaseScanner
from security.scope_validator import ScopeValidator, normalize_url
from utils.http_client import AuditHTTPClient, CancelledError
from utils.logging_setup import redact, register_secret

log = logging.getLogger(__name__)


@dataclass
class AuditCallbacks:
    on_progress: Callable[[int, int, str, str], None] = lambda i, n, module, msg: None
    on_module_done: Callable[[ModuleResult], None] = lambda r: None
    on_log: Callable[[str], None] = lambda msg: None


@dataclass
class AuditOutcome:
    audit_id: int
    status: str
    duration_s: float
    scores: dict[str, Any]
    module_results: list[ModuleResult] = field(default_factory=list)
    pdf_path: str | None = None
    xlsx_path: str | None = None


class AuditManager:
    def __init__(self, db: DBManager, config: dict[str, Any], secrets: dict[str, str],
                 audit_type: str = "full", callbacks: AuditCallbacks | None = None,
                 modules: list[type[BaseScanner]] | None = None, resume_from: int | None = None):
        self.db = db
        self.config = dict(config)
        self.secrets = dict(secrets)
        for v in self.secrets.values():
            register_secret(v)
        self.audit_type = audit_type
        self.cb = callbacks or AuditCallbacks()
        self.modules = modules or registry.modules_for(audit_type)
        self.resume_from = resume_from
        self.cancel_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()

    # controls ------------------------------------------------------------
    def cancel(self) -> None:
        self.cancel_event.set()
        self.pause_event.set()

    def pause(self) -> None:
        self.pause_event.clear()

    def resume(self) -> None:
        self.pause_event.set()

    @property
    def paused(self) -> bool:
        return not self.pause_event.is_set()

    # run -----------------------------------------------------------------
    def run(self) -> AuditOutcome:
        target = normalize_url(self.config.get("target_url", ""))
        self.config["target_url"] = target
        scope = ScopeValidator(target, extra_hosts=self._extra_hosts(),
                               include_subdomains=bool(self.config.get("include_subdomains", True)))
        client = AuditHTTPClient(scope, timeout=float(self.config.get("timeout", 20)),
                                 max_rps=float(self.config.get("max_rps", 5)),
                                 verify_tls=bool(self.config.get("verify_tls", True)),
                                 cancel_event=self.cancel_event, pause_event=self.pause_event)
        ctx = AuditContext(target_url=target, client=client, config=self.config, secrets=self.secrets,
                           progress=self.cb.on_log)

        done_modules: set[str] = set()
        if self.resume_from:
            audit_id = self.resume_from
            prev = self.db.get_audit(audit_id) or {}
            import json
            done_modules = set(json.loads(prev.get("state_json") or "{}").get("completed_modules", []))
            self.cb.on_log(f"Resuming audit #{audit_id}; skipping {len(done_modules)} completed modules")
        else:
            audit_id = self.db.create_audit(target, self.audit_type, self.config)
        start = time.monotonic()
        seen: set[str] = set()
        results: list[ModuleResult] = []
        status = "completed"
        total = len(self.modules)

        for i, mod_cls in enumerate(self.modules, start=1):
            if self.cancel_event.is_set():
                status = "cancelled"
                break
            scanner = mod_cls()
            if scanner.name in done_modules:
                continue
            self.cb.on_progress(i - 1, total, scanner.name, f"Running {scanner.name}")
            self.cb.on_log(f"[{i}/{total}] {scanner.name}: {scanner.description}")
            try:
                res = scanner.run(ctx)
            except CancelledError:
                res = scanner.result
                res.status = "cancelled"
                res.error = "Cancelled by user"
                status = "cancelled"
            except Exception as exc:  # noqa: BLE001 - module isolation
                res = scanner.result
                res.status = "failed"
                res.error = redact(f"{type(exc).__name__}: {exc}")
                res.checks.append(_failed_check(scanner, res.error))
                log.error("Module %s failed: %s\n%s", scanner.name, exc, redact(traceback.format_exc()))
            res.finished_at = res.finished_at or utcnow_iso()
            res = normalize(res, seen)
            self.db.save_module_result(audit_id, res)
            results.append(res)
            if res.status in ("completed", "skipped"):
                done_modules.add(scanner.name)
            self.db.save_state(audit_id, {"completed_modules": sorted(done_modules)})
            self.cb.on_module_done(res)
            msg = f"{scanner.name}: {res.status} - {len(res.findings)} findings, {len(res.checks)} checks"
            if res.error:
                msg += f" ({res.error})"
            self.cb.on_log(msg)
            if status == "cancelled":
                break

        duration = round(time.monotonic() - start, 1)
        scores = compute_scores(self.db.get_checks(audit_id), self.db.get_findings(audit_id), self.db.get_metrics(audit_id))
        scores["requests_sent"] = client.request_count
        self.db.finish_audit(audit_id, status, duration, scores)
        self.cb.on_progress(total, total, "", f"Audit {status}")
        return AuditOutcome(audit_id, status, duration, scores, results)

    def _extra_hosts(self) -> list[str]:
        from urllib.parse import urlparse
        hosts = [h.strip() for h in str(self.config.get("extra_scope_hosts", "")).split(",") if h.strip()]
        api = self.config.get("api_base_url")
        if api:
            hosts.append(urlparse(normalize_url(api)).hostname or "")
        return hosts


def _failed_check(scanner: BaseScanner, error: str):
    from core.models import CheckResult
    return CheckResult(name=f"{scanner.name} execution", status=CheckStatus.ERROR, module=scanner.name,
                       category=scanner.category, detail=error)
