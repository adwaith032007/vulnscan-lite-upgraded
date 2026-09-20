from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors

def build_pdf(scan):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    styles = getSampleStyleSheet()
    story = [
        Paragraph("VulnScan-Lite Security Assessment", styles["Title"]),
        Spacer(1, 12),
        Paragraph(f"<b>Target:</b> {scan.get('target','')}", styles["BodyText"]),
        Paragraph(f"<b>Final URL:</b> {scan.get('final_url','')}", styles["BodyText"]),
        Paragraph(f"<b>Risk:</b> {scan.get('risk_level','')} ({scan.get('risk_score',0)}/100)", styles["BodyText"]),
        Paragraph(f"<b>HTTP status:</b> {scan.get('status_code','')}", styles["BodyText"]),
        Spacer(1, 16),
    ]
    rows = [["Severity", "Finding", "Evidence"]]
    for f in scan.get("findings", []):
        rows.append([f["severity"], f["title"], f.get("evidence", "")[:100]])
    table = Table(rows, colWidths=[65, 250, 180], repeatRows=1)
    table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
        ("GRID", (0,0), (-1,-1), 0.4, colors.grey),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("FONTSIZE", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,0), 8),
    ]))
    story.append(table)
    story.append(Spacer(1, 14))
    story.append(Paragraph("This report contains passive observations only. Validate findings manually before taking remediation action.", styles["Italic"]))
    doc.build(story)
    buffer.seek(0)
    return buffer
