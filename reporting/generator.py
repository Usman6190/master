"""ReportGenerator: produces both reports for an audit and records their locations."""
from __future__ import annotations

from pathlib import Path

from config.settings import reports_dir
from database.db_manager import DBManager
from reporting.excel_report import generate_excel
from reporting.pdf_report import generate_pdf
from reporting.report_data import load_report_data


def generate_reports(db: DBManager, audit_id: int, out_dir: Path | None = None, sample_label: str = "") -> tuple[str, str]:
    d = load_report_data(db, audit_id)
    out_dir = out_dir or reports_dir()
    stamp = (d["audit"]["started_at"] or "").replace(":", "").replace("-", "")[:15]
    base = out_dir / f"CreativeStall_Audit_{audit_id}_{stamp}"
    pdf = generate_pdf(d, base.with_suffix(".pdf"), sample_label)
    xlsx = generate_excel(d, base.with_suffix(".xlsx"))
    db.set_report_paths(audit_id, str(pdf), str(xlsx))
    return str(pdf), str(xlsx)
