"""Background audit worker (QThread) so the GUI never blocks."""
from __future__ import annotations

import traceback

from PySide6.QtCore import QObject, Qt, QThread, Signal

from database.db_manager import DBManager
from engine.audit_manager import AuditCallbacks, AuditManager
from reporting.generator import generate_reports
from utils.logging_setup import redact


class AuditWorker(QObject):
    progress = Signal(int, int, str, str)
    log = Signal(str)
    module_done = Signal(str, str, int)
    finished = Signal(int, str, str, str)  # audit_id, status, pdf, xlsx
    failed = Signal(str)

    def __init__(self, db: DBManager, config: dict, secrets: dict, audit_type: str, resume_from: int | None = None):
        super().__init__()
        cb = AuditCallbacks(on_progress=lambda i, n, m, msg: self.progress.emit(i, n, m, msg),
                            on_module_done=lambda r: self.module_done.emit(r.module, r.status, len(r.findings)),
                            on_log=lambda s: self.log.emit(redact(s)))
        self.db = db
        self.manager = AuditManager(db, config, secrets, audit_type, cb, resume_from=resume_from)

    def run(self) -> None:
        try:
            out = self.manager.run()
            pdf = xlsx = ""
            if out.status in ("completed", "cancelled"):
                self.log.emit("Generating PDF and Excel reports...")
                try:
                    pdf, xlsx = generate_reports(self.db, out.audit_id)
                    self.log.emit(f"Reports saved: {pdf} | {xlsx}")
                except Exception as exc:  # noqa: BLE001
                    self.db.log_error(out.audit_id, "ReportGenerator", redact(str(exc)))
                    self.log.emit(f"Report generation failed: {redact(str(exc))}")
            self.finished.emit(out.audit_id, out.status, pdf, xlsx)
        except Exception as exc:  # noqa: BLE001
            self.failed.emit(redact(f"{exc}\n{traceback.format_exc()}"))


def start_worker(worker: AuditWorker) -> QThread:
    th = QThread()
    worker.moveToThread(th)
    th.started.connect(worker.run)
    # Direct connection: quit must not wait on the (possibly blocked) GUI event loop.
    worker.finished.connect(th.quit, Qt.ConnectionType.DirectConnection)
    worker.failed.connect(th.quit, Qt.ConnectionType.DirectConnection)
    th.start()
    return th
