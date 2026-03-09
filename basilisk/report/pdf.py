"""
Basilisk PDF Report Generator.

Generates PDF reports from HTML content using weasyprint (if available)
or falls back to a basic text-based PDF using reportlab.

Dependencies (optional — PDF generation is a soft dependency):
  - weasyprint: pip install weasyprint   (recommended)
  - reportlab:  pip install reportlab    (fallback)
"""

from __future__ import annotations

import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from basilisk.core.session import ScanSession


def generate_pdf(session: ScanSession, path: Path) -> None:
    """Generate a PDF report. Tries weasyprint first, then reportlab."""
    # Try weasyprint (renders HTML → PDF with full CSS)
    try:
        from basilisk.report.html import generate_html
        html_path = path.with_suffix(".html")
        generate_html(session, html_path)

        import weasyprint
        weasyprint.HTML(filename=str(html_path)).write_pdf(str(path))
        html_path.unlink(missing_ok=True)
        return
    except ImportError:
        pass

    # Try reportlab fallback
    try:
        _generate_pdf_reportlab(session, path)
        return
    except ImportError:
        pass

    # Final fallback — write a formatted text file with .pdf extension
    _generate_pdf_text_fallback(session, path)


def _generate_pdf_reportlab(session: ScanSession, path: Path) -> None:
    """Generate PDF using reportlab."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.lib.colors import HexColor
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table as RLTable, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    doc = SimpleDocTemplate(str(path), pagesize=A4,
                            topMargin=2*cm, bottomMargin=2*cm,
                            leftMargin=2*cm, rightMargin=2*cm)

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('CustomTitle', parent=styles['Title'],
                                  fontSize=24, textColor=HexColor('#dc2626'))
    heading_style = ParagraphStyle('CustomHeading', parent=styles['Heading2'],
                                    fontSize=16, textColor=HexColor('#e5e5e5'))
    normal_style = ParagraphStyle('CustomNormal', parent=styles['Normal'],
                                   fontSize=10, textColor=HexColor('#a3a3a3'))
    finding_style = ParagraphStyle('FindingTitle', parent=styles['Heading3'],
                                    fontSize=12, textColor=HexColor('#e5e5e5'))

    elements = []

    # Title
    elements.append(Paragraph("🐍 Basilisk Scan Report", title_style))
    elements.append(Spacer(1, 0.5*cm))
    elements.append(Paragraph(
        f"Session: {session.id} | Target: {session.config.target.url} | "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        normal_style
    ))
    elements.append(Spacer(1, 1*cm))

    # Summary table
    summary = session.summary
    summary_data = [
        ["Severity", "Count"],
        ["CRITICAL", str(summary["severity_counts"].get("critical", 0))],
        ["HIGH", str(summary["severity_counts"].get("high", 0))],
        ["MEDIUM", str(summary["severity_counts"].get("medium", 0))],
        ["LOW", str(summary["severity_counts"].get("low", 0))],
        ["INFO", str(summary["severity_counts"].get("info", 0))],
        ["TOTAL", str(summary["total_findings"])],
    ]
    summary_table = RLTable(summary_data, colWidths=[4*cm, 3*cm])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#262626')),
        ('TEXTCOLOR', (0, 0), (-1, -1), HexColor('#e5e5e5')),
        ('GRID', (0, 0), (-1, -1), 0.5, HexColor('#404040')),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
    ]))
    elements.append(summary_table)
    elements.append(Spacer(1, 1*cm))

    # Findings
    elements.append(Paragraph("Findings", heading_style))
    elements.append(Spacer(1, 0.5*cm))

    for f in sorted(session.findings, key=lambda x: x.severity.numeric, reverse=True):
        elements.append(Paragraph(
            f"[{f.severity.value.upper()}] {f.title}",
            finding_style
        ))
        elements.append(Paragraph(
            f"ID: {f.id} | Module: {f.attack_module} | "
            f"OWASP: {f.category.owasp_id} | Confidence: {f.confidence:.0%}",
            normal_style
        ))
        if f.payload:
            elements.append(Spacer(1, 0.2*cm))
            payload_text = f.payload[:300].replace("&", "&amp;").replace("<", "&lt;")
            elements.append(Paragraph(f"<b>Payload:</b> <font face='Courier' size='8'>{payload_text}</font>", normal_style))
        if f.remediation:
            elements.append(Paragraph(f"<b>Remediation:</b> {f.remediation}", normal_style))
        elements.append(Spacer(1, 0.5*cm))

    # Footer
    elements.append(Spacer(1, 1*cm))
    elements.append(Paragraph(
        "Generated by Basilisk v1.0.7 — AI Red Teaming Framework | rothackers.com",
        normal_style
    ))

    doc.build(elements)


def _generate_pdf_text_fallback(session: ScanSession, path: Path) -> None:
    """Last resort — write a structured text file as .pdf (not a real PDF)."""
    lines = [
        "BASILISK SCAN REPORT",
        "=" * 60,
        f"Session: {session.id}",
        f"Target:  {session.config.target.url}",
        f"Date:    {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Model:   {session.profile.detected_model}",
        f"Mode:    {session.config.mode.value}",
        "",
        "SEVERITY SUMMARY",
        "-" * 40,
    ]

    summary = session.summary
    for sev in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"  {sev.upper()}: {summary['severity_counts'].get(sev, 0)}")
    lines.append(f"  TOTAL: {summary['total_findings']}")
    lines.extend(["", "FINDINGS", "-" * 40, ""])

    for f in sorted(session.findings, key=lambda x: x.severity.numeric, reverse=True):
        lines.extend([
            f"[{f.severity.value.upper()}] {f.title}",
            f"  ID:         {f.id}",
            f"  Module:     {f.attack_module}",
            f"  OWASP:      {f.category.owasp_id}",
            f"  Confidence: {f.confidence:.0%}",
            f"  Payload:    {f.payload[:200]}",
            f"  Remediation:{f.remediation}",
            "",
        ])

    lines.extend([
        "-" * 60,
        "Generated by Basilisk v1.0.7 | Rot Hackers | rothackers.com",
        "(Install weasyprint or reportlab for proper PDF output)",
    ])

    with open(path, "w") as fp:
        fp.write("\n".join(lines))
