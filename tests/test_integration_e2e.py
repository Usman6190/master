"""Engine/DB/report integration and GUI end-to-end tests (offscreen Qt, mock target)."""
import threading
import time
from unittest import mock

from openpyxl import load_workbook

from engine.audit_manager import AuditCallbacks, AuditManager
from reporting.generator import generate_reports
from scanners.base import BaseScanner
from tests.conftest import FULL_CFG, FULL_SECRETS

PSI_FAKE = {"scores": {"performance": 71}, "metrics": {}, "opportunities": [], "field_data": {}}


def _cfg(url):
    return {"target_url": url, "api_base_url": url, **FULL_CFG}


def test_full_audit_persists_and_reports(db, mock_site, tmp_path):
    with mock.patch("scanners.performance.performance.run_pagespeed", return_value=PSI_FAKE):
        out = AuditManager(db, _cfg(mock_site), FULL_SECRETS, "full").run()
    assert out.status == "completed"
    runs = db.get_module_runs(out.audit_id)
    assert len(runs) == 25 and all(r["status"] in ("completed", "skipped", "failed") for r in runs)
    assert out.scores["Performance"] == 71.0 and out.scores["severity_counts"]["Critical"] >= 1
    pdf, xlsx = generate_reports(db, out.audit_id, tmp_path)
    assert open(pdf, "rb").read(4) == b"%PDF"
    wb = load_workbook(xlsx)
    for sheet in ("Executive Summary", "Security Findings", "Critical Findings", "High Findings", "Medium Findings",
                  "Low Findings", "Performance Results", "PageSpeed Results", "API Test Results", "Infrastructure Results",
                  "Failed Checks", "Manual Verification", "Remediation Roadmap"):
        assert sheet in wb.sheetnames
    dump = open(xlsx, "rb").read() + open(pdf, "rb").read()
    assert b"correct-password" not in dump and b"user-token" not in dump
    assert db.get_audit(out.audit_id)["pdf_path"] == pdf


def test_module_failure_isolated(db, mock_site):
    class Boom(BaseScanner):
        name = "Boom"

        def execute(self, ctx):
            raise RuntimeError("kaboom")
    from scanners.security.csp import CSPScanner
    out = AuditManager(db, {"target_url": mock_site}, {}, "security", modules=[Boom, CSPScanner]).run()
    runs = {r["module"]: r for r in db.get_module_runs(out.audit_id)}
    assert runs["Boom"]["status"] == "failed" and "kaboom" in runs["Boom"]["error"]
    assert runs["CSPScanner"]["status"] == "completed" and out.status == "completed"


def test_cancel_and_resume(db, mock_site):
    from scanners.security.csp import CSPScanner
    from scanners.security.headers import SecurityHeadersScanner
    started = threading.Event()

    class Slow(BaseScanner):
        name = "Slow"

        def execute(self, ctx):
            started.set()
            for _ in range(50):
                ctx.client.get(ctx.target_url)
                time.sleep(0.05)
    mgr = AuditManager(db, {"target_url": mock_site, "max_rps": 0}, {}, "security",
                       modules=[CSPScanner, Slow, SecurityHeadersScanner])
    th = threading.Thread(target=lambda: setattr(mgr, "_out", mgr.run()))
    th.start()
    started.wait(10)
    mgr.cancel()
    th.join(20)
    assert mgr._out.status == "cancelled"
    aid = mgr._out.audit_id
    out2 = AuditManager(db, {"target_url": mock_site}, {}, "security",
                        modules=[CSPScanner, SecurityHeadersScanner], resume_from=aid).run()
    mods = [r["module"] for r in db.get_module_runs(aid)]
    assert mods.count("CSPScanner") == 1 and "SecurityHeadersScanner" in mods and out2.status == "completed"


def test_pause_resume(db, mock_site):
    from scanners.security.csp import CSPScanner
    logs = []
    mgr = AuditManager(db, {"target_url": mock_site}, {}, "security", modules=[CSPScanner],
                       callbacks=AuditCallbacks(on_log=logs.append))
    mgr.pause()
    th = threading.Thread(target=lambda: setattr(mgr, "_out", mgr.run()))
    th.start()
    time.sleep(0.8)
    assert th.is_alive() and mgr.paused
    mgr.resume()
    th.join(10)
    assert mgr._out.status == "completed"


def test_gui_end_to_end(qtbot, mock_site, monkeypatch):
    """Launch GUI, configure target + credentials, Start Full Audit, see progress, findings, reports, reopen history."""
    from PySide6.QtWidgets import QMessageBox
    from gui.main_window import MainWindow
    monkeypatch.setattr(QMessageBox, "question", lambda *a, **k: QMessageBox.StandardButton.Yes)
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    monkeypatch.setattr(QMessageBox, "warning", lambda *a, **k: None)
    with mock.patch("scanners.performance.performance.run_pagespeed", return_value=PSI_FAKE):
        w = MainWindow()
        qtbot.addWidget(w)
        w.show()
        cfgv = w.config_view
        cfgv.set_values({**_cfg(mock_site), "authorization_confirmed": True}, FULL_SECRETS)
        cfgv.save()
        w.start_audit("full")
        qtbot.waitUntil(lambda: w.progress_bar.value() > 0, timeout=20000)
        qtbot.waitUntil(lambda: w.current_thread is None, timeout=120000)
    assert "completed" in w.status_label.text().lower()
    aid = w.last_audit_id
    assert w.findings_view.table.rowCount() > 0
    assert w.dashboard.cards["Critical"].value_label.text() != "0"
    audit = w.db.get_audit(aid)
    assert audit["pdf_path"] and audit["xlsx_path"]
    w.history_view.refresh()
    assert w.history_view.table.rowCount() >= 1
    w.history_view.table.selectRow(0)
    w.history_view.open_selected()
    assert w.findings_view.audit_id == aid
