"""Excel report (OpenPyXL) with one worksheet per required section."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from reporting.report_data import executive_summary, remediation_roadmap

SEV_FILL = {"Critical": "C62828", "High": "EF6C00", "Medium": "F9A825", "Low": "1565C0",
            "Informational": "757575", "Needs Manual Verification": "6A1B9A"}
HEADER_FILL = PatternFill("solid", fgColor="263238")
FINDING_COLS = ["finding_id", "severity", "title", "affected_url", "module", "category", "description", "evidence",
                "reproduction_steps", "impact", "recommendation", "verification_status", "timestamp"]


def _sheet(wb: Workbook, title: str, headers: list[str], rows: list[list[Any]], sev_col: int | None = None):
    ws = wb.create_sheet(title[:31])
    ws.append([h.replace("_", " ").title() for h in headers])
    for c in ws[1]:
        c.font = Font(bold=True, color="FFFFFF")
        c.fill = HEADER_FILL
    for r in rows:
        ws.append(["" if v is None else (v if isinstance(v, (int, float)) else str(v)[:32000]) for v in r])
    for i, h in enumerate(headers, start=1):
        width = 60 if h in ("description", "evidence", "recommendation", "impact", "detail", "reproduction_steps") else 22
        ws.column_dimensions[get_column_letter(i)].width = width
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")
        if sev_col is not None:
            sev = row[sev_col].value
            if sev in SEV_FILL:
                row[sev_col].fill = PatternFill("solid", fgColor=SEV_FILL[sev])
                row[sev_col].font = Font(bold=True, color="FFFFFF")
    ws.freeze_panes = "A2"
    if rows:
        ws.auto_filter.ref = ws.dimensions
    return ws


def generate_excel(d: dict[str, Any], out: Path) -> Path:
    wb = Workbook()
    ws = wb.active
    ws.title = "Executive Summary"
    a, s = d["audit"], d["scores"]
    rows = [("Report", "CreativeStall Security & Performance Audit"), ("Target", a["target_url"]),
            ("Audit type", a["audit_type"]), ("Status", a["status"]), ("Started", a["started_at"]),
            ("Finished", a.get("finished_at")), ("Duration (s)", a.get("duration_s")), ("", ""),
            ("Summary", executive_summary(d)), ("", "")]
    for k in ("Security", "API Security", "Performance", "Infrastructure", "Coverage"):
        v = s.get(k)
        rows.append((f"{k} score", "Not tested" if v is None else v))
    rows.append(("", ""))
    for k, v in s.get("severity_counts", {}).items():
        rows.append((f"Findings: {k}", v))
    for k, v in s.get("check_counts", {}).items():
        rows.append((f"Checks: {k}", v))
    rows += [("", ""), ("Scoring methodology", d["methodology"]), ("Prior assessment context", d["prior_assessment"])]
    for r in rows:
        ws.append(list(r))
    ws.column_dimensions["A"].width = 30
    ws.column_dimensions["B"].width = 120
    for row in ws.iter_rows():
        row[0].font = Font(bold=True)
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")

    f = d["findings"]
    frow = lambda items: [[x.get(c) for c in FINDING_COLS] for x in items]  # noqa: E731
    _sheet(wb, "Security Findings", FINDING_COLS, frow(f), 1)
    for sev in ("Critical", "High", "Medium", "Low"):
        _sheet(wb, f"{sev} Findings", FINDING_COLS, frow([x for x in f if x["severity"] == sev]), 1)
    perf_m = [m for m in d["metrics"] if m["module"] in ("APIResponseAnalyzer", "AssetDeliveryAnalyzer", "JMeterController",
                                                          "LighthouseAnalyzer", "InfrastructureScanner")]
    mcols = ["module", "name", "value", "unit", "context"]
    _sheet(wb, "Performance Results", mcols, [[m[c] for c in mcols] for m in perf_m])
    _sheet(wb, "PageSpeed Results", mcols, [[m[c] for c in mcols] for m in d["metrics"] if m["module"] == "PageSpeedAnalyzer"])
    ccols = ["module", "category", "name", "status", "detail"]
    _sheet(wb, "API Test Results", ccols, [[c[k] for k in ccols] for c in d["checks"] if c["category"] == "API Security"])
    infra = [[c[k] for k in ccols] for c in d["checks"] if c["category"] == "Infrastructure"]
    infra += [[m["module"], "Infrastructure (metric)", m["name"], m["value"], m["context"]] for m in d["metrics"]
              if m["module"] == "InfrastructureScanner"]
    _sheet(wb, "Infrastructure Results", ccols, infra)
    failed = [[c[k] for k in ccols] for c in d["checks"] if c["status"] in ("Failed", "Error")]
    failed += [[m["module"], "Module", "Module run", m["status"], m["error"]] for m in d["modules"] if m["status"] == "failed"]
    _sheet(wb, "Failed Checks", ccols, failed)
    manual = [[c[k] for k in ccols] for c in d["checks"] if c["status"] in ("Needs Manual Verification", "Not Tested")]
    manual += [[x["module"], x["category"], x["title"], x["verification_status"], x["evidence"]] for x in f
               if x["verification_status"] == "Needs Verification"]
    _sheet(wb, "Manual Verification", ccols, manual)
    rm = remediation_roadmap(f)
    rcols = ["priority", "severity", "title", "affected_url", "recommendation", "timeline", "verification_status"]
    _sheet(wb, "Remediation Roadmap", rcols, [[r[c] for c in rcols] for r in rm], 1)
    _sheet(wb, "All Checks", ccols, [[c[k] for k in ccols] for c in d["checks"]])
    out.parent.mkdir(parents=True, exist_ok=True)
    wb.save(out)
    return out
