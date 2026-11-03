"""Main application window: navigation, audit controls, real-time progress."""
from __future__ import annotations

import sys
import time

from PySide6.QtCore import QThread, QTimer
from PySide6.QtGui import QIcon
from PySide6.QtWidgets import (QApplication, QHBoxLayout, QLabel, QListWidget, QMainWindow, QMessageBox,
                               QPlainTextEdit, QProgressBar, QPushButton, QStackedWidget, QVBoxLayout, QWidget)

from config.settings import APP_NAME, APP_VERSION, resource_path
from database.db_manager import DBManager
from engine.environment import validate
from gui.views import (CategoryView, ConfigView, DashboardView, FindingsView, HistoryView, ReportsView, SettingsView,
                       open_path)
from gui.worker import AuditWorker, start_worker
from security.credential_manager import CredentialManager
from security.scope_validator import ScopeError, normalize_url

STYLE = """
QMainWindow, QWidget { font-family: 'Segoe UI', sans-serif; font-size: 13px; }
QListWidget#nav { background:#263238; color:#ECEFF1; border:none; font-size:14px; }
QListWidget#nav::item { padding:10px 14px; }
QListWidget#nav::item:selected { background:#1565C0; color:white; }
QPushButton { padding:6px 12px; }
QPushButton#primary { background:#1565C0; color:white; font-weight:bold; padding:8px 16px; border-radius:4px; }
QPushButton#primary:disabled { background:#90A4AE; }
QProgressBar { height:18px; text-align:center; }
"""
PAGES = ["Dashboard", "New Audit", "Security Scanner", "Performance Scanner", "API Testing", "Infrastructure",
         "Findings", "Reports", "Audit History", "Settings"]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        self.setWindowIcon(QIcon(str(resource_path("assets/app.png"))))
        self.resize(1360, 860)
        self.db = DBManager()
        self.creds = CredentialManager()
        self.worker: AuditWorker | None = None
        self.current_thread: QThread | None = None
        self.last_audit_id: int | None = None
        self.started_at = 0.0
        self._orphans: list[QThread] = []

        self.dashboard = DashboardView(self.db)
        self.config_view = ConfigView(self.creds)
        self.security_view = CategoryView(self.db, "Security Scanner", ("Security",),
                                          ("WebsiteDiscovery", "SecurityHeadersScanner", "TLSScanner", "CORSScanner",
                                           "CSPScanner", "PublicExposureScanner", "AssetProtectionScanner",
                                           "BotProtectionScanner"))
        self.performance_view = CategoryView(self.db, "Performance Scanner", ("Performance",),
                                             ("PageSpeedAnalyzer", "LighthouseAnalyzer", "APIResponseAnalyzer",
                                              "AssetDeliveryAnalyzer", "JMeterController"))
        self.api_view = CategoryView(self.db, "API Testing", ("API Security",),
                                     ("AuthenticationTester", "SessionSecurityTester", "APISecurityScanner", "RBACScanner",
                                      "IDORTester", "RateLimitTester"))
        self.infra_view = CategoryView(self.db, "Infrastructure", ("Infrastructure",), ("InfrastructureScanner",))
        self.findings_view = FindingsView(self.db)
        self.reports_view = ReportsView(self.db)
        self.history_view = HistoryView(self.db)
        self.settings_view = SettingsView(self.creds)
        self.history_view.open_audit.connect(self.show_audit)

        self.stack = QStackedWidget()
        for w in (self.dashboard, self.config_view, self.security_view, self.performance_view, self.api_view,
                  self.infra_view, self.findings_view, self.reports_view, self.history_view, self.settings_view):
            self.stack.addWidget(w)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.addItems(PAGES)
        self.nav.setFixedWidth(200)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)
        self.nav.setCurrentRow(0)

        right = QVBoxLayout()
        right.addWidget(self._controls())
        right.addWidget(self.stack, 1)
        right.addWidget(self._progress_panel())
        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.addWidget(self.nav)
        rw = QWidget()
        rw.setLayout(right)
        body.addWidget(rw, 1)
        root = QWidget()
        root.setLayout(body)
        self.setCentralWidget(root)
        self.setStyleSheet(STYLE)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        latest = self.db.stats()["latest"]
        if latest:
            self.show_audit(latest["id"], switch=False)
        QTimer.singleShot(300, self._first_run_check)

    # --- layout -----------------------------------------------------------
    def _controls(self) -> QWidget:
        w = QWidget()
        h = QHBoxLayout(w)
        self.btn_full = QPushButton("Start Full Audit")
        self.btn_full.setObjectName("primary")
        self.btn_sec = QPushButton("Start Security Audit")
        self.btn_perf = QPushButton("Start Performance Audit")
        self.btn_pause = QPushButton("Pause")
        self.btn_resume = QPushButton("Resume")
        self.btn_cancel = QPushButton("Cancel")
        self.btn_prev = QPushButton("View Previous Audits")
        self.btn_pdf = QPushButton("Export PDF")
        self.btn_xlsx = QPushButton("Export Excel")
        self.btn_full.clicked.connect(lambda: self.start_audit("full"))
        self.btn_sec.clicked.connect(lambda: self.start_audit("security"))
        self.btn_perf.clicked.connect(lambda: self.start_audit("performance"))
        self.btn_pause.clicked.connect(self.pause)
        self.btn_resume.clicked.connect(self.resume)
        self.btn_cancel.clicked.connect(self.cancel)
        self.btn_prev.clicked.connect(lambda: self.nav.setCurrentRow(PAGES.index("Audit History")))
        self.btn_pdf.clicked.connect(lambda: self.export("pdf"))
        self.btn_xlsx.clicked.connect(lambda: self.export("xlsx"))
        for b in (self.btn_full, self.btn_sec, self.btn_perf, self.btn_pause, self.btn_resume, self.btn_cancel,
                  self.btn_prev, self.btn_pdf, self.btn_xlsx):
            h.addWidget(b)
        h.addStretch()
        self._set_running(False)
        return w

    def _progress_panel(self) -> QWidget:
        w = QWidget()
        v = QVBoxLayout(w)
        top = QHBoxLayout()
        self.status_label = QLabel("Idle")
        self.module_label = QLabel("")
        self.elapsed_label = QLabel("")
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        top.addWidget(self.status_label)
        top.addWidget(self.module_label, 1)
        top.addWidget(self.elapsed_label)
        v.addLayout(top)
        v.addWidget(self.progress_bar)
        self.log_view = QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setMaximumHeight(150)
        self.log_view.setMaximumBlockCount(5000)
        v.addWidget(self.log_view)
        return w

    def _set_running(self, running: bool):
        for b in (self.btn_full, self.btn_sec, self.btn_perf):
            b.setEnabled(not running)
        self.btn_pause.setEnabled(running)
        self.btn_resume.setEnabled(False)
        self.btn_cancel.setEnabled(running)

    # --- audit lifecycle --------------------------------------------------
    def _first_run_check(self):
        missing = [c for c in validate(check_browser=False) if c.required and not c.ok]
        if missing:
            QMessageBox.warning(self, "Environment problem",
                                "\n".join(f"• {c.name}: {c.detail} — {c.fix}" for c in missing))

    def start_audit(self, audit_type: str):
        if self.current_thread is not None:
            return
        self.config_view.save()
        cfg, secrets = self.config_view.values()
        try:
            cfg["target_url"] = normalize_url(cfg["target_url"])
            if cfg.get("api_base_url"):
                cfg["api_base_url"] = normalize_url(cfg["api_base_url"])
        except ScopeError as exc:
            QMessageBox.warning(self, "Invalid URL", f"{exc}\n\nEnter a full URL such as https://www.creativestall.com/")
            return
        if not cfg.get("authorization_confirmed"):
            QMessageBox.warning(self, "Authorization required",
                                "Confirm you are authorized to test this target (New Audit → Target → "
                                "'I am authorized to test this target').")
            self.nav.setCurrentRow(PAGES.index("New Audit"))
            return
        checks = self.settings_view.validate(cfg["target_url"])
        blocking = [c for c in checks if c.required and not c.ok]
        if blocking:
            QMessageBox.warning(self, "Cannot start audit", "Fix these problems first:\n\n" +
                                "\n".join(f"• {c.name}: {c.detail}\n   → {c.fix}" for c in blocking))
            return
        optional = [c for c in checks if not c.required and not c.ok]
        if optional:
            self.log(" | ".join(f"Optional dependency missing: {c.name} ({c.fix})" for c in optional))
        if cfg.get("load_test_enabled") and cfg.get("load_test_environment") == "production":
            if QMessageBox.question(self, "Production load test",
                                    f"Run a load test against PRODUCTION capped at "
                                    f"{cfg.get('production_traffic_ceiling')} users with emergency stop at "
                                    f"{cfg.get('load_error_stop_pct')}% errors?") != QMessageBox.StandardButton.Yes:
                return
        self.log_view.clear()
        self.progress_bar.setValue(0)
        self.status_label.setText(f"Running {audit_type} audit…")
        self.worker = AuditWorker(self.db, cfg, secrets, audit_type)
        self.worker.progress.connect(self._on_progress)
        self.worker.log.connect(self.log)
        self.worker.finished.connect(self._on_finished)
        self.worker.failed.connect(self._on_failed)
        self.started_at = time.monotonic()
        self.timer.start(1000)
        self._set_running(True)
        self.current_thread = start_worker(self.worker)

    def pause(self):
        if self.worker:
            self.worker.manager.pause()
            self.status_label.setText("Paused")
            self.btn_pause.setEnabled(False)
            self.btn_resume.setEnabled(True)

    def resume(self):
        if self.worker:
            self.worker.manager.resume()
            self.status_label.setText("Running…")
            self.btn_pause.setEnabled(True)
            self.btn_resume.setEnabled(False)

    def cancel(self):
        if self.worker and QMessageBox.question(self, "Cancel audit", "Cancel the running audit?") == QMessageBox.StandardButton.Yes:
            self.worker.manager.cancel()
            self.status_label.setText("Cancelling…")

    def _on_progress(self, i, n, module, msg):
        self.progress_bar.setValue(int(100 * i / max(1, n)))
        self.module_label.setText(f"Module {min(i + 1, n)}/{n}: {module}" if module else msg)

    def _tick(self):
        s = int(time.monotonic() - self.started_at)
        self.elapsed_label.setText(f"Elapsed {s // 60:02d}:{s % 60:02d}")

    def log(self, msg: str):
        self.log_view.appendPlainText(f"{time.strftime('%H:%M:%S')}  {msg}")

    def _cleanup(self):
        self.timer.stop()
        self._set_running(False)
        th = self.current_thread
        if th:
            th.wait(30000)
            if th.isRunning():
                self._orphans.append(th)
        self.current_thread = None
        self.worker = None

    def _on_finished(self, audit_id: int, status: str, pdf: str, xlsx: str):
        self._cleanup()
        self.progress_bar.setValue(100)
        self.status_label.setText(f"Audit #{audit_id} {status}")
        self.show_audit(audit_id)
        self.reports_view.refresh()
        self.history_view.refresh()
        if pdf:
            QMessageBox.information(self, "Audit finished", f"Audit {status}.\n\nPDF: {pdf}\nExcel: {xlsx}")

    def _on_failed(self, err: str):
        self._cleanup()
        self.status_label.setText("Audit failed")
        self.log(err)
        QMessageBox.warning(self, "Audit failed", err[:1500])

    def show_audit(self, audit_id: int, switch: bool = True):
        self.last_audit_id = audit_id
        self.dashboard.refresh(audit_id)
        for v in (self.security_view, self.performance_view, self.api_view, self.infra_view, self.findings_view):
            v.load(audit_id)
        if switch:
            self.nav.setCurrentRow(PAGES.index("Dashboard"))

    def export(self, kind: str):
        if not self.last_audit_id:
            QMessageBox.information(self, "Export", "Run or open an audit first.")
            return
        a = self.db.get_audit(self.last_audit_id)
        path = a.get("pdf_path" if kind == "pdf" else "xlsx_path")
        if not path:
            from reporting.generator import generate_reports
            pdf, xlsx = generate_reports(self.db, self.last_audit_id)
            path = pdf if kind == "pdf" else xlsx
        open_path(path)

    def closeEvent(self, e):
        if self.worker:
            self.worker.manager.cancel()
            if self.current_thread:
                self.current_thread.wait(10000)
        super().closeEvent(e)


def run_app() -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    w = MainWindow()
    w.show()
    return app.exec()
