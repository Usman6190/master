"""PDF report (ReportLab)."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.graphics.charts.barcharts import VerticalBarChart
from reportlab.graphics.shapes import Drawing
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle)

from reporting.report_data import executive_summary, remediation_roadmap

SEV_COLOR = {"Critical": colors.HexColor("#C62828"), "High": colors.HexColor("#EF6C00"),
             "Medium": colors.HexColor("#F9A825"), "Low": colors.HexColor("#1565C0"),
             "Informational": colors.HexColor("#757575"), "Needs Manual Verification": colors.HexColor("#6A1B9A")}

_ss = getSampleStyleSheet()
H1 = ParagraphStyle("H1", parent=_ss["Heading1"], textColor=colors.HexColor("#263238"))
H2 = ParagraphStyle("H2", parent=_ss["Heading2"], textColor=colors.HexColor("#37474F"))
BODY = ParagraphStyle("B", parent=_ss["BodyText"], fontSize=9, leading=12)
HEAD = ParagraphStyle("TH", parent=BODY, textColor=colors.white, fontName="Helvetica-Bold")
SMALL = ParagraphStyle("S", parent=BODY, fontSize=7.5, leading=9.5, fontName="Courier")


def P(text: Any, style=BODY) -> Paragraph:
    return Paragraph(escape(str(text if text is not None else "")).replace("\n", "<br/>"), style)


def _table(rows: list[list[Any]], widths: list[float], header=True) -> Table:
    data = [[c if isinstance(c, Paragraph) else P(c, HEAD if header and i == 0 else BODY) for c in r]
            for i, r in enumerate(rows)]
    t = Table(data, colWidths=widths, repeatRows=1 if header else 0)
    style = [("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("VALIGN", (0, 0), (-1, -1), "TOP")]
    if header:
        style += [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#263238")), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white)]
    t.setStyle(TableStyle(style))
    return t


def _sev_chart(counts: dict[str, int]) -> Drawing:
    labels = ["Critical", "High", "Medium", "Low", "Needs Manual Verification", "Informational"]
    d = Drawing(16 * cm, 5 * cm)
    ch = VerticalBarChart()
    ch.x, ch.y, ch.width, ch.height = 30, 20, 14 * cm, 3.6 * cm
    ch.data = [[counts.get(lbl, 0) for lbl in labels]]
    ch.categoryAxis.categoryNames = ["Crit", "High", "Med", "Low", "Verify", "Info"]
    ch.valueAxis.valueMin = 0
    ch.bars.strokeWidth = 0
    for i, lbl in enumerate(labels):
        ch.bars[(0, i)].fillColor = SEV_COLOR[lbl]
    d.add(ch)
    return d


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7)
    canvas.drawString(1.5 * cm, 1 * cm, "CreativeStall Security & Performance Audit — Confidential")
    canvas.drawRightString(A4[0] - 1.5 * cm, 1 * cm, f"Page {doc.page}")
    canvas.restoreState()


def generate_pdf(d: dict[str, Any], out: Path, sample_label: str = "") -> Path:
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(out), pagesize=A4, leftMargin=1.5 * cm, rightMargin=1.5 * cm,
                            topMargin=1.5 * cm, bottomMargin=1.8 * cm, title="CreativeStall Audit Report")
    a, s, W = d["audit"], d["scores"], A4[0] - 3 * cm
    el: list = [Paragraph("CreativeStall Security &amp; Performance Audit Report", H1)]
    if sample_label:
        el.append(P(sample_label, ParagraphStyle("warn", parent=BODY, textColor=colors.red, fontSize=11)))
    el += [Spacer(1, 6), Paragraph("1. Executive summary", H2), P(executive_summary(d)), Spacer(1, 6),
           P(d["prior_assessment"])]
    el += [Paragraph("2. Website details", H2),
           _table([["Field", "Value"], ["Target URL", a["target_url"]], ["API base URL", d["config"].get("api_base_url", "-")],
                   ["Browser", d["config"].get("browser", "chromium")], ["Device mode", d["config"].get("device_mode", "both")]],
                  [5 * cm, W - 5 * cm])]
    el += [Paragraph("3. Audit date and duration", H2),
           _table([["Started", "Finished", "Duration", "Status", "Requests sent"],
                   [a["started_at"], a.get("finished_at") or "-", f"{a.get('duration_s') or 0:.0f} s", a["status"],
                    s.get("requests_sent", "-")]], [W / 5] * 5)]
    el += [Paragraph("4. Audit scope", H2),
           _table([["Module", "Status", "Error / note"]] + [[m["module"], m["status"], m["error"] or ""] for m in d["modules"]],
                  [5 * cm, 2.5 * cm, W - 7.5 * cm])]
    sc = s.get("severity_counts", {})
    el += [Paragraph("5. Security findings summary &amp; scores", H2),
           _table([["Category", "Score"]] + [[k, "Not tested" if s.get(k) is None else f"{s.get(k)}/100"]
                                             for k in ("Security", "API Security", "Performance", "Infrastructure")]
                  + [["Audit coverage", f"{s.get('Coverage', 0)}%"]], [8 * cm, 4 * cm]),
           Spacer(1, 4),
           _table([["Passed", "Failed", "Not applicable", "Not tested", "Needs manual verification", "Error"],
                   [s.get("check_counts", {}).get(k, 0) for k in
                    ("Passed", "Failed", "Not Applicable", "Not Tested", "Needs Manual Verification", "Error")]], [W / 6] * 6),
           Spacer(1, 4), P("Methodology: " + d["methodology"])]
    el += [Paragraph("6. Severity distribution", H2), _sev_chart(sc),
           _table([list(sc.keys()), list(sc.values())], [W / max(1, len(sc))] * max(1, len(sc)))]
    el += [PageBreak(), Paragraph("7. Detailed findings (with evidence)", H2)]
    if not d["findings"]:
        el.append(P("No findings were produced by executed checks."))
    for f in d["findings"]:
        color = SEV_COLOR.get(f["severity"], colors.grey)
        head = Table([[P(f"{f['finding_id']}  [{f['severity']}]  {f['title']}",
                         ParagraphStyle("fh", parent=BODY, textColor=colors.white, fontName="Helvetica-Bold"))]],
                     colWidths=[W])
        head.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), color)]))
        body = _table([["Affected", f["affected_url"]], ["Module / category", f"{f['module']} / {f['category']}"],
                       ["Verification", f["verification_status"]], ["Description", f["description"]],
                       ["Evidence", P(f["evidence"], SMALL)], ["Reproduction", P(f["reproduction_steps"] or "-", SMALL)],
                       ["Impact", f["impact"]], ["Recommended fix", f["recommendation"]], ["Timestamp", f["timestamp"]]],
                      [3.5 * cm, W - 3.5 * cm], header=False)
        el += [KeepTogether([head, body]), Spacer(1, 8)]
    def mt(filter_fn, title):
        rows = [[m["name"], f"{m['value']} {m['unit'] or ''}", m["context"] or ""] for m in d["metrics"] if filter_fn(m)]
        return [Paragraph(title, H2), _table([["Metric", "Value", "Context"]] + rows, [8 * cm, 4 * cm, W - 12 * cm])
                if rows else P("Not tested / no data.")]
    el += [PageBreak()]
    el += mt(lambda m: m["module"] in ("APIResponseAnalyzer", "AssetDeliveryAnalyzer", "JMeterController", "LighthouseAnalyzer"),
             "8. Performance metrics")
    el += mt(lambda m: m["module"] == "PageSpeedAnalyzer", "9. PageSpeed results")
    api_checks = [[c["module"], c["name"], c["status"], c["detail"]] for c in d["checks"] if c["category"] == "API Security"]
    el += [Paragraph("10. API test results", H2),
           _table([["Module", "Check", "Status", "Detail"]] + api_checks, [3.5 * cm, 5 * cm, 2.5 * cm, W - 11 * cm])
           if api_checks else P("Not tested.")]
    el += mt(lambda m: m["module"] == "InfrastructureScanner", "11. Infrastructure observations")
    el += [Paragraph("12. Evidence: all executed checks", H2),
           _table([["Module", "Check", "Status", "Detail"]] + [[c["module"], c["name"], c["status"], P(c["detail"], SMALL)]
                                                               for c in d["checks"]],
                  [3.5 * cm, 5 * cm, 2.5 * cm, W - 11 * cm])]
    rm = remediation_roadmap(d["findings"])
    el += [Paragraph("13-14. Recommended remediation &amp; risk prioritization", H2),
           _table([["#", "Severity", "Finding", "Fix", "Timeline"]] +
                  [[r["priority"], r["severity"], r["title"], r["recommendation"], r["timeline"]] for r in rm],
                  [0.8 * cm, 2.2 * cm, 4.5 * cm, W - 10.5 * cm, 3 * cm]) if rm else P("No remediation items.")]
    not_tested = [[c["module"], c["name"], c["status"], c["detail"]] for c in d["checks"]
                  if c["status"] in ("Not Tested", "Needs Manual Verification")]
    el += [Paragraph("15. Limitations and untested areas", H2)] + [P("• " + x) for x in d["limitations"]]
    if not_tested:
        el += [Spacer(1, 4), _table([["Module", "Check", "Status", "Reason"]] + not_tested,
                                    [3.5 * cm, 5 * cm, 2.5 * cm, W - 11 * cm])]
    doc.build(el, onFirstPage=_footer, onLaterPages=_footer)
    return out
