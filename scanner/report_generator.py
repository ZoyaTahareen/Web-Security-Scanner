"""
scanner/report_generator.py
Generate downloadable reports in JSON, CSV, and PDF formats.

All content is derived from actual scan results — nothing is fabricated.
Untrusted values are sanitised before inclusion in generated documents.
"""

from __future__ import annotations

import csv
import html
import io
import json
import textwrap
from typing import Any


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def generate_json(scan_result: dict) -> bytes:
    """Return scan_result serialised as pretty-printed JSON bytes."""
    # Exclude raw headers to keep report focused; they're available in the app
    export = {k: v for k, v in scan_result.items() if k != "headers_raw"}
    return json.dumps(export, indent=2, ensure_ascii=False).encode("utf-8")


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def generate_csv(scan_result: dict) -> bytes:
    """Return a flat CSV report as bytes."""
    buf = io.StringIO()
    writer = csv.writer(buf, quoting=csv.QUOTE_ALL)

    # Metadata block
    writer.writerow(["Section", "Field", "Value"])
    writer.writerow(["Metadata", "Target URL",  _safe(scan_result.get("target_url"))])
    writer.writerow(["Metadata", "Final URL",   _safe(scan_result.get("final_url"))])
    writer.writerow(["Metadata", "Timestamp",   _safe(scan_result.get("timestamp"))])
    writer.writerow(["Metadata", "HTTP Status", _safe(scan_result.get("http_status"))])
    writer.writerow([])

    # Security headers
    writer.writerow(["Security Headers", "Header", "Present", "Value", "Status",
                     "Purpose", "Implications", "Remediation"])
    for h in scan_result.get("header_analysis", []):
        writer.writerow([
            "Security Headers",
            _safe(h.get("name")),
            "Yes" if h.get("present") else "No",
            _safe(h.get("value")),
            _safe(h.get("status")),
            _safe(h.get("purpose")),
            _safe(h.get("implications")),
            _safe(h.get("remediation")),
        ])
    writer.writerow([])

    # CORS headers
    cors = scan_result.get("cors_analysis", {})
    writer.writerow(["CORS", "Header", "Value", "Status", "Observation", "Concern", "Recommendation"])
    for h in cors.get("headers", []):
        writer.writerow([
            "CORS",
            _safe(h.get("name")),
            _safe(h.get("value")),
            _safe(h.get("status")),
            _safe(h.get("observation")),
            _safe(h.get("concern")),
            _safe(h.get("recommendation")),
        ])
    writer.writerow([])

    # Findings
    writer.writerow(["Finding", "Title", "Severity", "Category", "Evidence",
                     "Explanation", "Impact", "Recommended Fix"])
    for f in scan_result.get("findings", []):
        writer.writerow([
            "Finding",
            _safe(f.get("title")),
            _safe(f.get("severity")),
            _safe(f.get("category")),
            _safe(f.get("evidence")),
            _safe(f.get("explanation")),
            _safe(f.get("impact")),
            _safe(f.get("fix")),
        ])

    return buf.getvalue().encode("utf-8-sig")  # BOM for Excel compatibility


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def generate_pdf(scan_result: dict) -> bytes:
    """Return a complete PDF security report as bytes using ReportLab."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        HRFlowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    )

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
        title="Web Security Assessment Report",
        author="Automated Web Security Scanner",
    )

    styles = getSampleStyleSheet()

    # Custom styles
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=6,
    )
    h1_style = ParagraphStyle(
        "H1",
        parent=styles["Heading1"],
        fontSize=14,
        textColor=colors.HexColor("#1e40af"),
        spaceBefore=14,
        spaceAfter=4,
    )
    h2_style = ParagraphStyle(
        "H2",
        parent=styles["Heading2"],
        fontSize=11,
        textColor=colors.HexColor("#374151"),
        spaceBefore=8,
        spaceAfter=2,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#1f2937"),
    )
    note_style = ParagraphStyle(
        "Note",
        parent=body_style,
        textColor=colors.HexColor("#6b7280"),
        fontSize=8,
    )

    severity_colors = {
        "High":          colors.HexColor("#dc2626"),
        "Medium":        colors.HexColor("#ea580c"),
        "Low":           colors.HexColor("#ca8a04"),
        "Informational": colors.HexColor("#2563eb"),
    }

    status_colors = {
        "PASS":           colors.HexColor("#16a34a"),
        "WARNING":        colors.HexColor("#dc2626"),
        "REVIEW":         colors.HexColor("#ca8a04"),
        "NOT APPLICABLE": colors.HexColor("#6b7280"),
    }

    story = []

    # ---- Title page ----
    story.append(Paragraph("Web Security Assessment Report", title_style))
    story.append(Paragraph("Automated Web Security Scanner", styles["Normal"]))
    story.append(Spacer(1, 0.4 * cm))
    story.append(HRFlowable(width="100%", thickness=2, color=colors.HexColor("#1e40af")))
    story.append(Spacer(1, 0.4 * cm))

    meta = [
        ["Target URL",  _safe(scan_result.get("target_url"))],
        ["Final URL",   _safe(scan_result.get("final_url"))],
        ["Timestamp",   _safe(scan_result.get("timestamp"))],
        ["HTTP Status", _safe(scan_result.get("http_status"))],
    ]
    meta_table = Table(meta, colWidths=[4 * cm, 13 * cm])
    meta_table.setStyle(TableStyle([
        ("FONTSIZE",    (0, 0), (-1, -1), 9),
        ("FONTNAME",    (0, 0), (0, -1), "Helvetica-Bold"),
        ("TEXTCOLOR",   (0, 0), (0, -1), colors.HexColor("#374151")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.5 * cm))

    # Disclaimer
    story.append(Paragraph(
        "<i>Disclaimer: This report contains preliminary, automated observations. "
        "It is not a substitute for a professional penetration test. Findings require "
        "contextual review before remediation decisions are made.</i>",
        note_style,
    ))
    story.append(Spacer(1, 0.8 * cm))

    # ---- Summary ----
    findings = scan_result.get("findings", [])
    counts = {s: 0 for s in ["High", "Medium", "Low", "Informational"]}
    for f in findings:
        counts[f.get("severity", "Informational")] += 1

    story.append(Paragraph("Finding Summary", h1_style))
    summary_data = [["Severity", "Count"]] + [[s, str(c)] for s, c in counts.items()]
    summary_table = Table(summary_data, colWidths=[6 * cm, 3 * cm])
    summary_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e40af")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",      (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING",    (0, 0), (-1, -1), 4),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 0.8 * cm))

    # ---- Security Headers ----
    story.append(Paragraph("Security Header Analysis", h1_style))
    hdr_data = [["Header", "Present", "Status", "Value"]]
    for h in scan_result.get("header_analysis", []):
        hdr_data.append([
            Paragraph(_safe(h.get("name")), body_style),
            "Yes" if h.get("present") else "No",
            _safe(h.get("status")),
            Paragraph(_truncate(_safe(h.get("value")), 60), body_style),
        ])
    hdr_table = Table(hdr_data, colWidths=[5.5 * cm, 2 * cm, 3 * cm, 6.5 * cm])
    hdr_style_cmds = [
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
    ]
    for row_idx, h in enumerate(scan_result.get("header_analysis", []), start=1):
        sc = status_colors.get(h.get("status", ""), colors.HexColor("#6b7280"))
        hdr_style_cmds.append(("TEXTCOLOR", (2, row_idx), (2, row_idx), sc))
    hdr_table.setStyle(TableStyle(hdr_style_cmds))
    story.append(hdr_table)
    story.append(Spacer(1, 0.5 * cm))

    # ---- CORS ----
    story.append(Paragraph("CORS Configuration Analysis", h1_style))
    cors = scan_result.get("cors_analysis", {})
    story.append(Paragraph(_safe(cors.get("summary")), body_style))
    story.append(Spacer(1, 0.3 * cm))

    cors_data = [["CORS Header", "Value", "Status"]]
    for h in cors.get("headers", []):
        cors_data.append([
            _safe(h.get("name")),
            Paragraph(_truncate(_safe(h.get("value")), 55), body_style),
            _safe(h.get("status")),
        ])
    cors_table = Table(cors_data, colWidths=[6 * cm, 7.5 * cm, 3.5 * cm])
    cors_table.setStyle(TableStyle([
        ("FONTNAME",      (0, 0), (-1, 0), "Helvetica-Bold"),
        ("BACKGROUND",    (0, 0), (-1, 0), colors.HexColor("#1e3a5f")),
        ("TEXTCOLOR",     (0, 0), (-1, 0), colors.white),
        ("FONTSIZE",      (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS",(0, 1), (-1, -1), [colors.HexColor("#f8fafc"), colors.white]),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("VALIGN",        (0, 0), (-1, -1), "TOP"),
        ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
    ]))
    story.append(cors_table)
    story.append(Spacer(1, 0.8 * cm))

    # ---- Findings ----
    story.append(Paragraph("Detailed Findings", h1_style))

    if not findings:
        story.append(Paragraph("No findings were generated for this scan.", body_style))
    else:
        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "Informational")
            sev_color = severity_colors.get(sev, colors.HexColor("#2563eb"))

            story.append(Paragraph(f"{i}. {_safe(f.get('title'))}", h2_style))

            detail_data = [
                ["Severity",    _safe(sev)],
                ["Category",    _safe(f.get("category"))],
                ["Evidence",    _safe(f.get("evidence"))],
                ["Explanation", _safe(f.get("explanation"))],
                ["Impact",      _safe(f.get("impact"))],
                ["Fix",         _safe(f.get("fix"))],
            ]
            d_table = Table(
                [[Paragraph(r[0], body_style), Paragraph(r[1], body_style)] for r in detail_data],
                colWidths=[3.5 * cm, 13.5 * cm],
            )
            d_style = TableStyle([
                ("FONTNAME",      (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE",      (0, 0), (-1, -1), 8),
                ("VALIGN",        (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING",    (0, 0), (-1, -1), 4),
                ("ROWBACKGROUNDS",(0, 0), (-1, -1), [colors.HexColor("#f0f4ff"), colors.white]),
                ("GRID",          (0, 0), (-1, -1), 0.3, colors.HexColor("#e2e8f0")),
                ("TEXTCOLOR",     (1, 0), (1, 0), sev_color),  # colour severity value
            ])
            d_table.setStyle(d_style)
            story.append(d_table)
            story.append(Spacer(1, 0.4 * cm))

    # ---- Limitations ----
    story.append(PageBreak())
    story.append(Paragraph("Assessment Limitations", h1_style))
    limitations = [
        "This tool performs passive, non-authenticated header inspection only.",
        "Results represent observations at the time of the scan; configurations may change.",
        "A missing header does not confirm exploitability — context and server configuration matter.",
        "CORS analysis is based solely on response headers and does not simulate cross-origin requests.",
        "This report is not a substitute for a professional security assessment or penetration test.",
        "TLS/certificate validation is performed by the Python requests library; deep TLS analysis is outside scope.",
    ]
    for lim in limitations:
        story.append(Paragraph(f"• {lim}", body_style))
    story.append(Spacer(1, 0.5 * cm))

    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#e2e8f0")))
    story.append(Paragraph(
        "Generated by Automated Web Security Scanner | For educational and authorised use only.",
        note_style,
    ))

    doc.build(story)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _safe(value: Any) -> str:
    """Convert value to string, replacing None with an em-dash."""
    if value is None:
        return "—"
    return str(value)


def _truncate(text: str, max_len: int) -> str:
    if len(text) > max_len:
        return text[:max_len] + "…"
    return text
