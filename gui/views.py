"""GUI pages: dashboard, configuration, findings, category results, reports, history, settings."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QComboBox, QFormLayout, QFrame, QGridLayout, QGroupBox,
                               QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMessageBox, QPlainTextEdit, QPushButton,
                               QScrollArea, QSpinBox, QSplitter, QTableWidget, QTableWidgetItem, QTextEdit, QVBoxLayout,
                               QWidget)

from config.settings import reports_dir
from config.user_config import DEFAULTS, SECRET_KEYS, load_config, save_config
from database.db_manager import DBManager
from security.credential_manager import CredentialManager

SEV_COLORS = {"Critical": "#C62828", "High": "#EF6C00", "Medium": "#F9A825", "Low": "#1565C0",
              "Informational": "#757575", "Needs Manual Verification": "#6A1B9A"}
STATUS_COLORS = {"Passed": "#2E7D32", "Failed": "#C62828", "Error": "#AD1457", "Not Tested": "#757575",
                 "Needs Manual Verification": "#6A1B9A", "Not Applicable": "#9E9E9E"}


def open_path(path: str) -> None:
    if not path or not Path(path).exists():
        QMessageBox.warning(None, "File not found", f"The file does not exist:\n{path}")
        return
    QDesktopServices.openUrl(QUrl.fromLocalFile(path))


def make_table(headers: list[str]) -> QTableWidget:
    t = QTableWidget(0, len(headers))
    t.setHorizontalHeaderLabels(headers)
    t.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    t.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    t.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    t.setAlternatingRowColors(True)
    t.setSortingEnabled(True)
    t.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)
    t.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
    t.horizontalHeader().setStretchLastSection(True)
    t.verticalHeader().setVisible(False)
    return t


def fill_table(t: QTableWidget, rows: list[list], color_col: int | None = None, colors: dict | None = None):
    t.setSortingEnabled(False)
    t.setRowCount(0)
    for r in rows:
        i = t.rowCount()
        t.insertRow(i)
        for j, v in enumerate(r):
            it = QTableWidgetItem("" if v is None else str(v))
            if color_col == j and colors and str(v) in colors:
                it.setBackground(QColor(colors[str(v)]))
                it.setForeground(QColor("white"))
            t.setItem(i, j, it)
    t.setSortingEnabled(True)
    t.resizeColumnsToContents()
    for j in range(t.columnCount()):
        t.setColumnWidth(j, min(t.columnWidth(j), 380))


class Card(QFrame):
    def __init__(self, title: str, color: str = "#263238"):
        super().__init__()
        self.setObjectName("card")
        self.setStyleSheet(f"#card{{background:{color};border-radius:8px;}} QLabel{{color:white;}}")
        lay = QVBoxLayout(self)
        t = QLabel(title)
        t.setStyleSheet("font-size:11px;")
        self.value_label = QLabel("—")
        self.value_label.setStyleSheet("font-size:22px;font-weight:bold;")
        lay.addWidget(t)
        lay.addWidget(self.value_label)

    def set(self, v):
        self.value_label.setText("—" if v is None else str(v))


class DashboardView(QWidget):
    CARDS = [("Total audits", "#263238"), ("Latest audit", "#37474F"), ("Status", "#455A64"),
             ("Security findings", "#263238"), ("Critical", SEV_COLORS["Critical"]), ("High", SEV_COLORS["High"]),
             ("Medium", SEV_COLORS["Medium"]), ("Low", SEV_COLORS["Low"]), ("Security score", "#1B5E20"),
             ("Performance score", "#004D40"), ("PageSpeed mobile", "#00695C"), ("PageSpeed desktop", "#00796B"),
             ("API p95 (search)", "#01579B"), ("Coverage", "#4A148C"), ("API Security score", "#0D47A1"),
             ("Infrastructure score", "#3E2723")]

    def __init__(self, db: DBManager):
        super().__init__()
        self.db = db
        lay = QVBoxLayout(self)
        h = QLabel("Dashboard")
        h.setStyleSheet("font-size:20px;font-weight:bold;")
        lay.addWidget(h)
        grid = QGridLayout()
        self.cards: dict[str, Card] = {}
        for i, (name, color) in enumerate(self.CARDS):
            c = Card(name, color)
            self.cards[name] = c
            grid.addWidget(c, i // 4, i % 4)
        lay.addLayout(grid)
        self.checks_label = QLabel()
        self.checks_label.setWordWrap(True)
        lay.addWidget(self.checks_label)
        self.api_table = make_table(["Endpoint", "p50 ms", "p95 ms", "Errors"])
        lay.addWidget(QLabel("API response-time summary (latest audit)"))
        lay.addWidget(self.api_table)
        self.refresh()

    def refresh(self, audit_id: int | None = None):
        st = self.db.stats()
        self.cards["Total audits"].set(st["total_audits"])
        a = self.db.get_audit(audit_id) if audit_id else st["latest"]
        if not a:
            return
        scores = json.loads(a.get("scores_json") or "{}")
        sc = scores.get("severity_counts", {})
        self.cards["Latest audit"].set((a["started_at"] or "")[:19].replace("T", " "))
        self.cards["Status"].set(a["status"])
        self.cards["Security findings"].set(sum(v for k, v in sc.items() if k != "Informational"))
        for k in ("Critical", "High", "Medium", "Low"):
            self.cards[k].set(sc.get(k, 0))
        fmt = lambda v: "Not tested" if v is None else v  # noqa: E731
        self.cards["Security score"].set(fmt(scores.get("Security")))
        self.cards["Performance score"].set(fmt(scores.get("Performance")))
        self.cards["API Security score"].set(fmt(scores.get("API Security")))
        self.cards["Infrastructure score"].set(fmt(scores.get("Infrastructure")))
        self.cards["Coverage"].set(f"{scores.get('Coverage', 0)}%")
        metrics = self.db.get_metrics(a["id"])
        m = {x["name"]: x["value"] for x in metrics}
        self.cards["PageSpeed mobile"].set(m.get("PageSpeed performance score (mobile)", "Not tested"))
        self.cards["PageSpeed desktop"].set(m.get("PageSpeed performance score (desktop)", "Not tested"))
        rows, p95s = [], {}
        for x in metrics:
            if x["module"] == "APIResponseAnalyzer" and x["name"].endswith(" p95"):
                p95s[x["name"][:-4]] = x["value"]
        for x in metrics:
            if x["module"] == "APIResponseAnalyzer" and x["name"].endswith(" p50"):
                ep = x["name"][:-4]
                rows.append([ep, x["value"], p95s.get(ep), m.get(f"{ep} error rate", "")])
        fill_table(self.api_table, rows)
        self.cards["API p95 (search)"].set(next((r[2] for r in rows if "search" in r[0]), rows[0][2] if rows else "Not tested"))
        cc = scores.get("check_counts", {})
        self.checks_label.setText("Checks — " + ", ".join(f"{k}: {v}" for k, v in cc.items()))


FIELDS = [
    ("Target", [("target_url", "Website URL", "text"), ("api_base_url", "API base URL", "text"),
                ("include_subdomains", "Include subdomains in scope", "bool"),
                ("extra_scope_hosts", "Extra in-scope hosts (comma separated)", "text"),
                ("authorization_confirmed", "I am authorized to test this target", "bool")]),
    ("Credentials (encrypted locally)", [("api_token", "API authentication token", "secret"),
                                         ("login_username", "Login username (test account)", "text"),
                                         ("login_password", "Login password", "secret"),
                                         ("pagespeed_api_key", "Google PageSpeed API key", "secret"),
                                         ("test_roles", "Test account roles", "text")]),
    ("API endpoints", [("login_endpoint", "Login endpoint (POST JSON)", "text"),
                       ("login_user_field", "Login username field", "text"), ("login_pass_field", "Login password field", "text"),
                       ("logout_endpoint", "Logout endpoint", "text"), ("auth_probe_endpoint", "Authenticated probe endpoint", "text"),
                       ("openapi_url", "OpenAPI/Swagger URL or file", "text"),
                       ("protected_endpoints", "Protected endpoints (one per line)", "multi"),
                       ("admin_endpoints", "Admin-only endpoints (one per line)", "multi"),
                       ("public_api_endpoints", "Public API endpoints (one per line)", "multi"),
                       ("idor_endpoint_template", "IDOR template e.g. /api/users/{id}", "text"),
                       ("idor_own_id", "Own object ID", "text"), ("idor_other_id", "Other user's object ID", "text"),
                       ("search_endpoint", "Search endpoint e.g. /api/assets/search?q=logo", "text"),
                       ("injection_endpoints", "Extra injection test URLs (one per line)", "multi")]),
    ("Marketplace", [("asset_download_template", "Original download template /api/assets/{id}/download", "text"),
                     ("asset_page_template", "Asset page template /asset/{id}", "text"),
                     ("preview_url_template", "Preview URL template", "text"),
                     ("asset_test_ids", "Asset test IDs (comma separated)", "text"),
                     ("upload_endpoint", "Contributor upload endpoint", "text"),
                     ("upload_allow_authenticated_tests", "Allow authenticated upload tests (staging only)", "bool")]),
    ("Scan scope & browser", [("browser", "Browser type", ["chromium", "firefox", "webkit"]),
                              ("browser_checks", "Run headless browser (DOM XSS) checks", "bool"),
                              ("device_mode", "Mobile/Desktop testing", ["both", "mobile", "desktop"]),
                              ("timeout", "Request timeout (s)", (5, 120)), ("max_rps", "Max requests/second", (1, 50)),
                              ("verify_tls", "Verify TLS certificates", "bool"),
                              ("bruteforce_attempts", "Login brute-force probe attempts", (3, 20)),
                              ("rate_limit_burst", "Rate-limit burst size", (5, 60)),
                              ("scrape_probe_count", "Scraping probe requests", (5, 40))]),
    ("External security tools", [("zap_enabled", "Run OWASP ZAP passive scan (ZAP must be running)", "bool"),
                                 ("zap_api_url", "ZAP API URL", "text"), ("zap_api_key", "ZAP API key", "secret"),
                                 ("zap_max_children", "ZAP spider max children", (5, 500)),
                                 ("zap_max_minutes", "ZAP spider max minutes", (1, 120)),
                                 ("testssl_enabled", "Run testssl.sh", "bool"), ("testssl_path", "testssl.sh path", "text"),
                                 ("ssllabs_enabled", "Run Qualys SSL Labs (publish=off)", "bool"),
                                 ("ssllabs_email", "SSL Labs registered email", "text")]),
    ("Performance", [("run_lighthouse", "Run local Lighthouse", "bool"),
                     ("pagespeed_extra_urls", "Extra PageSpeed URLs (one per line)", "multi"),
                     ("response_samples", "Response-time samples", (3, 50)),
                     ("response_threshold_ms", "Response-time threshold (ms)", (100, 10000)),
                     ("perf_endpoints", "Extra perf endpoints (one per line)", "multi"),
                     ("load_test_enabled", "Enable JMeter load test", "bool"),
                     ("load_test_environment", "Load test environment", ["staging", "production"]),
                     ("load_test_target_url", "Load test target URL (staging)", "text"),
                     ("load_profile", "Load profile", ["Baseline", "Low Load", "Medium Load", "High Load", "Custom"]),
                     ("load_custom_users", "Custom users", (1, 2000)), ("load_ramp_s", "Ramp-up (s)", (0, 3600)),
                     ("load_duration_s", "Duration (s)", (10, 14400)),
                     ("load_error_stop_pct", "Emergency stop at error rate %", (1, 100)),
                     ("production_load_confirmed", "I confirm production load test is approved", "bool"),
                     ("production_traffic_ceiling", "Approved production user ceiling", (0, 2000))]),
]


class ConfigView(QWidget):
    saved = Signal()

    def __init__(self, creds: CredentialManager):
        super().__init__()
        self.creds = creds
        self.widgets: dict[str, QWidget] = {}
        outer = QVBoxLayout(self)
        h = QLabel("New Audit — Configuration")
        h.setStyleSheet("font-size:20px;font-weight:bold;")
        outer.addWidget(h)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        inner = QWidget()
        lay = QVBoxLayout(inner)
        for group, fields in FIELDS:
            box = QGroupBox(group)
            form = QFormLayout(box)
            for key, label, kind in fields:
                w = self._make(kind)
                self.widgets[key] = w
                form.addRow(label, w)
            lay.addWidget(box)
        scroll.setWidget(inner)
        outer.addWidget(scroll)
        row = QHBoxLayout()
        b = QPushButton("Save configuration")
        b.clicked.connect(self.save)
        row.addStretch()
        row.addWidget(b)
        outer.addLayout(row)
        self.set_values(load_config(), creds.load())

    def _make(self, kind):
        if kind == "bool":
            return QCheckBox()
        if kind == "secret":
            w = QLineEdit()
            w.setEchoMode(QLineEdit.EchoMode.Password)
            w.setPlaceholderText("stored encrypted")
            return w
        if kind == "multi":
            w = QPlainTextEdit()
            w.setFixedHeight(60)
            return w
        if isinstance(kind, list):
            w = QComboBox()
            w.addItems(kind)
            return w
        if isinstance(kind, tuple):
            w = QSpinBox()
            w.setRange(*kind)
            return w
        return QLineEdit()

    def set_values(self, cfg: dict, secrets: dict):
        for k, w in self.widgets.items():
            v = secrets.get(k, "") if k in SECRET_KEYS else cfg.get(k, DEFAULTS.get(k))
            if isinstance(w, QCheckBox):
                w.setChecked(bool(v))
            elif isinstance(w, QPlainTextEdit):
                w.setPlainText(str(v or ""))
            elif isinstance(w, QComboBox):
                w.setCurrentText(str(v))
            elif isinstance(w, QSpinBox):
                w.setValue(int(v or 0))
            else:
                w.setText(str(v or ""))

    def values(self) -> tuple[dict, dict]:
        cfg, sec = {}, {}
        for k, w in self.widgets.items():
            if isinstance(w, QCheckBox):
                v = w.isChecked()
            elif isinstance(w, QPlainTextEdit):
                v = w.toPlainText().strip()
            elif isinstance(w, QComboBox):
                v = w.currentText()
            elif isinstance(w, QSpinBox):
                v = w.value()
            else:
                v = w.text().strip()
            (sec if k in SECRET_KEYS else cfg)[k] = v
        return cfg, sec

    def save(self):
        cfg, sec = self.values()
        save_config(cfg)
        self.creds.save(sec)
        self.saved.emit()


class FindingsView(QWidget):
    COLS = ["finding_id", "severity", "title", "affected_url", "module", "category", "verification_status"]

    def __init__(self, db: DBManager):
        super().__init__()
        self.db = db
        self.audit_id: int | None = None
        self.rows: list[dict] = []
        lay = QVBoxLayout(self)
        h = QLabel("Findings")
        h.setStyleSheet("font-size:20px;font-weight:bold;")
        lay.addWidget(h)
        bar = QHBoxLayout()
        self.sev = QComboBox()
        self.sev.addItems(["All severities"] + list(SEV_COLORS))
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search findings…")
        self.sev.currentTextChanged.connect(self._render)
        self.search.textChanged.connect(self._render)
        bar.addWidget(self.sev)
        bar.addWidget(self.search)
        lay.addLayout(bar)
        sp = QSplitter(Qt.Orientation.Vertical)
        self.table = make_table([c.replace("_", " ").title() for c in self.COLS])
        self.table.itemSelectionChanged.connect(self._detail)
        self.detail = QTextEdit()
        self.detail.setReadOnly(True)
        sp.addWidget(self.table)
        sp.addWidget(self.detail)
        lay.addWidget(sp)

    def load(self, audit_id: int):
        self.audit_id = audit_id
        order = list(SEV_COLORS)
        self.rows = sorted(self.db.get_findings(audit_id),
                           key=lambda r: order.index(r["severity"]) if r["severity"] in order else 99)
        self._render()

    def _render(self):
        sev, q = self.sev.currentText(), self.search.text().lower()
        self.visible = [r for r in self.rows if (sev == "All severities" or r["severity"] == sev)
                        and (not q or q in json.dumps(r).lower())]
        fill_table(self.table, [[r[c] for c in self.COLS] for r in self.visible], 1, SEV_COLORS)

    def _detail(self):
        sel = self.table.selectedItems()
        if not sel:
            return
        fid = self.table.item(sel[0].row(), 0).text()
        f = next((r for r in self.rows if r["finding_id"] == fid), None)
        if not f:
            return
        from html import escape
        parts = [f"<h3 style='color:{SEV_COLORS.get(f['severity'])}'>[{f['severity']}] {escape(f['title'])}</h3>"]
        for k in ("affected_url", "verification_status", "description", "evidence", "reproduction_steps", "impact",
                  "recommendation", "references", "timestamp"):
            parts.append(f"<b>{k.replace('_', ' ').title()}:</b><pre style='white-space:pre-wrap'>{escape(str(f.get(k) or '-'))}</pre>")
        self.detail.setHtml("".join(parts))


class CategoryView(QWidget):
    """Security Scanner / Performance Scanner / API Testing / Infrastructure pages."""

    def __init__(self, db: DBManager, title: str, categories: tuple[str, ...], modules: tuple[str, ...] = ()):
        super().__init__()
        self.db, self.categories, self.modules = db, categories, modules
        lay = QVBoxLayout(self)
        h = QLabel(title)
        h.setStyleSheet("font-size:20px;font-weight:bold;")
        lay.addWidget(h)
        self.summary = QLabel()
        lay.addWidget(self.summary)
        sp = QSplitter(Qt.Orientation.Vertical)
        self.checks = make_table(["Module", "Check", "Status", "Detail"])
        self.metrics = make_table(["Module", "Metric", "Value", "Unit", "Context"])
        sp.addWidget(self.checks)
        sp.addWidget(self.metrics)
        lay.addWidget(sp)

    def load(self, audit_id: int):
        cs = [c for c in self.db.get_checks(audit_id) if c["category"] in self.categories]
        fill_table(self.checks, [[c["module"], c["name"], c["status"], c["detail"]] for c in cs], 2, STATUS_COLORS)
        ms = [m for m in self.db.get_metrics(audit_id) if not self.modules or m["module"] in self.modules]
        fill_table(self.metrics, [[m["module"], m["name"], m["value"], m["unit"], m["context"]] for m in ms])
        from collections import Counter
        cnt = Counter(c["status"] for c in cs)
        self.summary.setText(" | ".join(f"{k}: {v}" for k, v in cnt.items()) or "No checks recorded for this audit")


class HistoryView(QWidget):
    open_audit = Signal(int)

    def __init__(self, db: DBManager):
        super().__init__()
        self.db = db
        lay = QVBoxLayout(self)
        h = QLabel("Audit History")
        h.setStyleSheet("font-size:20px;font-weight:bold;")
        lay.addWidget(h)
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search by URL or type…")
        self.status = QComboBox()
        self.status.addItems(["", "completed", "cancelled", "running", "failed"])
        self.search.textChanged.connect(self.refresh)
        self.status.currentTextChanged.connect(self.refresh)
        bar.addWidget(self.search)
        bar.addWidget(QLabel("Status:"))
        bar.addWidget(self.status)
        lay.addLayout(bar)
        self.table = make_table(["ID", "Target", "Type", "Status", "Started", "Duration (s)", "Critical", "High", "PDF", "Excel"])
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.table.doubleClicked.connect(self.open_selected)
        lay.addWidget(self.table)
        btns = QHBoxLayout()
        for label, fn in (("Open audit", self.open_selected), ("Open PDF", lambda: self._open_file(8)),
                          ("Open Excel", lambda: self._open_file(9)), ("Compare 2 selected", self.compare),
                          ("Delete selected", self.delete_selected), ("Delete ALL history", self.delete_all)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            btns.addWidget(b)
        lay.addLayout(btns)
        self.compare_out = QTextEdit()
        self.compare_out.setReadOnly(True)
        self.compare_out.setMaximumHeight(200)
        lay.addWidget(self.compare_out)
        self.refresh()

    def refresh(self, *_):
        rows = []
        for a in self.db.list_audits(self.search.text(), self.status.currentText()):
            sc = json.loads(a.get("scores_json") or "{}").get("severity_counts", {})
            rows.append([a["id"], a["target_url"], a["audit_type"], a["status"], (a["started_at"] or "")[:19],
                         a.get("duration_s"), sc.get("Critical", 0), sc.get("High", 0), a.get("pdf_path") or "",
                         a.get("xlsx_path") or ""])
        fill_table(self.table, rows)

    def _selected_ids(self) -> list[int]:
        return sorted({int(self.table.item(i.row(), 0).text()) for i in self.table.selectedIndexes()})

    def open_selected(self, *_):
        ids = self._selected_ids()
        if ids:
            self.open_audit.emit(ids[0])

    def _open_file(self, col):
        sel = self.table.selectedIndexes()
        if sel:
            open_path(self.table.item(sel[0].row(), col).text())

    def compare(self):
        ids = self._selected_ids()
        if len(ids) != 2:
            QMessageBox.information(self, "Compare", "Select exactly two audits (Ctrl+click).")
            return
        c = self.db.compare(ids[0], ids[1])
        txt = [f"Comparison #{ids[0]} → #{ids[1]}: {len(c['new'])} new, {len(c['resolved'])} resolved, "
               f"{len(c['persisting'])} persisting"]
        for k in ("new", "resolved", "persisting"):
            txt += [f"\n{k.upper()}:"] + [f"  [{f['severity']}] {f['title']} — {f['affected_url']}" for f in c[k]]
        self.compare_out.setPlainText("\n".join(txt))

    def delete_selected(self):
        ids = self._selected_ids()
        if ids and QMessageBox.question(self, "Delete", f"Delete audits {ids} from local history?") == QMessageBox.StandardButton.Yes:
            for i in ids:
                self.db.delete_audit(i)
            self.refresh()

    def delete_all(self):
        if QMessageBox.question(self, "Delete ALL", "Permanently delete ALL local audit history? Report files are kept.") \
                == QMessageBox.StandardButton.Yes:
            self.db.delete_all()
            self.refresh()


class ReportsView(QWidget):
    def __init__(self, db: DBManager):
        super().__init__()
        self.db = db
        lay = QVBoxLayout(self)
        h = QLabel("Reports")
        h.setStyleSheet("font-size:20px;font-weight:bold;")
        lay.addWidget(h)
        lay.addWidget(QLabel(f"Report folder: {reports_dir()}"))
        self.table = make_table(["File", "Size (KB)", "Modified"])
        self.table.doubleClicked.connect(lambda *_: self._open())
        lay.addWidget(self.table)
        row = QHBoxLayout()
        for label, fn in (("Open selected", self._open), ("Open report folder", lambda: open_path(str(reports_dir()))),
                          ("Refresh", self.refresh)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        lay.addLayout(row)
        self.refresh()

    def refresh(self):
        import datetime
        files = sorted(reports_dir().glob("CreativeStall_Audit_*"), key=lambda p: p.stat().st_mtime, reverse=True)
        fill_table(self.table, [[str(p), round(p.stat().st_size / 1024, 1),
                                 datetime.datetime.fromtimestamp(p.stat().st_mtime).strftime("%Y-%m-%d %H:%M")] for p in files])

    def _open(self):
        sel = self.table.selectedIndexes()
        if sel:
            open_path(self.table.item(sel[0].row(), 0).text())


class SettingsView(QWidget):
    def __init__(self, creds: CredentialManager):
        super().__init__()
        self.creds = creds
        lay = QVBoxLayout(self)
        h = QLabel("Settings & Environment")
        h.setStyleSheet("font-size:20px;font-weight:bold;")
        lay.addWidget(h)
        self.table = make_table(["Component", "Status", "Detail", "Required", "How to fix"])
        lay.addWidget(self.table)
        row = QHBoxLayout()
        for label, fn in (("Validate environment", self.validate), ("Install Playwright Chromium", self.install_browser),
                          ("Clear stored credentials", self.clear_creds), ("Open logs folder", self.open_logs)):
            b = QPushButton(label)
            b.clicked.connect(fn)
            row.addWidget(b)
        lay.addLayout(row)
        self.out = QPlainTextEdit()
        self.out.setReadOnly(True)
        self.out.setMaximumHeight(150)
        lay.addWidget(self.out)

    def validate(self, target: str = ""):
        from engine.environment import validate
        checks = validate(target or load_config().get("target_url", ""))
        fill_table(self.table, [[c.name, "OK" if c.ok else "MISSING", c.detail, "yes" if c.required else "optional",
                                 "" if c.ok else c.fix] for c in checks])
        for i, c in enumerate(checks):
            self.table.item(i, 1).setBackground(QColor("#2E7D32" if c.ok else ("#C62828" if c.required else "#F9A825")))
        return checks

    def install_browser(self):
        self.out.appendPlainText("Installing Playwright Chromium (this may take a few minutes)…")
        try:
            if getattr(sys, "frozen", False):
                from playwright._impl._driver import compute_driver_executable, get_driver_env
                drv = compute_driver_executable()
                cmd = list(drv) if isinstance(drv, tuple) else [str(drv)]
                env = get_driver_env()
            else:
                cmd, env = [sys.executable, "-m", "playwright"], dict(os.environ)
            p = subprocess.run(cmd + ["install", "chromium"], capture_output=True, text=True, env=env, timeout=900)
            self.out.appendPlainText((p.stdout + p.stderr)[-2000:] or "Done")
        except Exception as exc:  # noqa: BLE001
            self.out.appendPlainText(f"Browser install failed: {exc}")

    def clear_creds(self):
        if QMessageBox.question(self, "Clear credentials", "Delete all locally stored encrypted credentials?") == QMessageBox.StandardButton.Yes:
            self.creds.clear()
            self.out.appendPlainText("Stored credentials deleted.")

    def open_logs(self):
        from config.settings import logs_dir
        open_path(str(logs_dir()))
