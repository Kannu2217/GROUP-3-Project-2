"""
Incident report generator — after every autonomous remediation cycle,
AeroDrift writes a timestamped PDF documenting exactly what drifted,
how it was detected, the code that was synthesized to fix it, and
proof that the fix verified clean. This is the artifact a CloudOps
team would attach to a postmortem / change-management ticket.
"""

from __future__ import annotations

import datetime
import os
import textwrap

from reportlab.lib import colors
from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from aerodrift.codegen.ast_generator import GeneratedRemediation
from aerodrift.config import REPORTS_DIR
from aerodrift.graph.topology import DriftFinding
from aerodrift.remediation.executor import ExecutionResult


def generate_incident_report(
    finding: DriftFinding,
    generated: GeneratedRemediation,
    execution: ExecutionResult,
    healed: bool,
    output_dir: str = REPORTS_DIR,
) -> str:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"incident_{finding.security_group_id}_{timestamp}.pdf")

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("TitleStyle", parent=styles["Title"], textColor=colors.HexColor("#1E2761"))
    heading_style = ParagraphStyle("HeadingStyle", parent=styles["Heading2"], textColor=colors.HexColor("#1E2761"))
    body_style = styles["BodyText"]
    mono_style = ParagraphStyle("Mono", parent=styles["Code"], fontSize=8, leading=10)

    doc = SimpleDocTemplate(filename, pagesize=LETTER, topMargin=0.75 * inch, bottomMargin=0.75 * inch)
    story = []

    story.append(Paragraph("AeroDrift Autonomous Remediation — Incident Report", title_style))
    story.append(Spacer(1, 4))
    story.append(
        Paragraph(
            f"Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} · Severity: "
            f"<b>{finding.severity}</b> · Blast Score: <b>{finding.blast_score}/100</b>",
            body_style,
        )
    )
    story.append(Spacer(1, 16))

    story.append(Paragraph("1. Drift Detected", heading_style))
    detail_table_data = [
        ["Resource", finding.resource_name],
        ["Resource ID", finding.resource_id],
        ["Security Group", finding.security_group_id],
        ["Offending Rule", f"{finding.protocol}/{finding.from_port}-{finding.to_port} from {finding.cidr}"],
        ["Attack Path", finding.attack_path_str()],
    ]
    t = Table(detail_table_data, colWidths=[1.6 * inch, 4.9 * inch])
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#EEF1FB")),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    story.append(t)
    story.append(Spacer(1, 16))

    story.append(Paragraph("2. How It Was Found", heading_style))
    story.append(
        Paragraph(
            "The NetworkX Topology Engine re-evaluated Internet &rarr; database reachability after every "
            "asynchronous boto3 ingestion cycle. A directed edge chain from the <b>internet</b> node to a "
            "database-tagged instance node indicates a policy-bypassing network path.",
            body_style,
        )
    )
    story.append(Spacer(1, 16))

    story.append(Paragraph("3. AST-Synthesized Remediation", heading_style))
    story.append(
        Paragraph(
            f"Function <b>{generated.function_name}()</b> was synthesized in "
            f"{generated.synthesis_ms:.2f}ms ({generated.ast_node_count} AST nodes) via Python's "
            "<b>ast</b> module and executed in AeroDrift's restricted sandbox.",
            body_style,
        )
    )
    story.append(Spacer(1, 6))
    wrapped_lines = []
    for line in generated.source_code.splitlines():
        indent = len(line) - len(line.lstrip(" "))
        wrapped = textwrap.wrap(
            line, width=88, subsequent_indent=" " * (indent + 4), initial_indent="", break_long_words=False
        ) or [""]
        wrapped_lines.extend(wrapped)
    story.append(Preformatted("\n".join(wrapped_lines), mono_style))
    story.append(Spacer(1, 16))

    story.append(Paragraph("4. Execution Result", heading_style))
    result_line = "SUCCESS" if execution.success else "FAILED"
    story.append(
        Paragraph(
            f"Status: <b>{result_line}</b> · Duration: {execution.duration_ms:.2f}ms · "
            f"Dry run: {execution.dry_run}",
            body_style,
        )
    )
    if execution.error:
        story.append(Paragraph(f"Error: {execution.error}", body_style))
    story.append(Spacer(1, 16))

    story.append(Paragraph("5. Self-Heal Verification", heading_style))
    verify_text = (
        "The Topology Engine re-ingested live state and rebuilt the reachability graph. "
        f"The resource is <b>{'no longer' if healed else 'STILL'}</b> reachable from the Internet."
    )
    story.append(Paragraph(verify_text, body_style))

    doc.build(story)
    return filename
