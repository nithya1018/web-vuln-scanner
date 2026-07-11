from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.enums import TA_LEFT, TA_CENTER
from datetime import datetime
import os

SEVERITY_COLORS = {
    'Critical': colors.HexColor('#ff2222'),
    'High':     colors.HexColor('#ff6600'),
    'Medium':   colors.HexColor('#ffcc00'),
    'Low':      colors.HexColor('#888888'),
}

TEXT_COLORS = {
    'Critical': colors.white,
    'High':     colors.white,
    'Medium':   colors.black,
    'Low':      colors.white,
}

def score_color(score):
    if score >= 85:
        return colors.HexColor('#00aa55')
    elif score >= 60:
        return colors.HexColor('#cc9900')
    else:
        return colors.HexColor('#cc2222')

def generate_pdf(simple_report, url, output_path="reports/report.pdf"):
    os.makedirs("reports", exist_ok=True)
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=20*mm,
        leftMargin=20*mm,
        topMargin=20*mm,
        bottomMargin=20*mm
    )

    title_style = ParagraphStyle(
        'Title', fontSize=22, textColor=colors.HexColor('#0a8a4f'),
        spaceAfter=6, fontName='Helvetica-Bold', alignment=TA_LEFT
    )
    subtitle_style = ParagraphStyle(
        'Subtitle', fontSize=10, textColor=colors.HexColor('#888888'),
        spaceAfter=4, fontName='Helvetica',
    )
    section_style = ParagraphStyle(
        'Section', fontSize=13, textColor=colors.HexColor('#0077b6'),
        spaceBefore=14, spaceAfter=8, fontName='Helvetica-Bold',
    )
    normal_style = ParagraphStyle(
        'Normal2', fontSize=10, textColor=colors.HexColor('#333333'),
        fontName='Helvetica', spaceAfter=4,
    )
    finding_title_style = ParagraphStyle(
        'FindingTitle', fontSize=12, textColor=colors.HexColor('#111111'),
        fontName='Helvetica-Bold', spaceAfter=4
    )
    explain_style = ParagraphStyle(
        'Explain', fontSize=10, textColor=colors.HexColor('#444444'),
        fontName='Helvetica', spaceAfter=6, leading=14
    )
    fix_style = ParagraphStyle(
        'Fix', fontSize=10, textColor=colors.HexColor('#0a8a4f'),
        fontName='Helvetica-Bold', leading=14
    )
    badge_style = ParagraphStyle(
        'Badge', fontSize=9, fontName='Helvetica-Bold', alignment=TA_CENTER
    )

    story = []

    story.append(Paragraph("Web Vulnerability Scanner Report", title_style))
    story.append(Paragraph(f"Target: {url}", subtitle_style))
    story.append(Paragraph(f"Scanned on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor('#dddddd')))
    story.append(Spacer(1, 14))

    # Score card
    score = simple_report['score']
    verdict = simple_report['verdict']
    sc = score_color(score)

    score_table = Table(
        [[Paragraph(f'<font size="26"><b>{score}</b></font>', ParagraphStyle('s', alignment=TA_CENTER, textColor=sc)),
          Paragraph(f'<font size="14"><b>{verdict}</b></font><br/><font size="9" color="#888888">Overall security score out of 100</font>',
                    ParagraphStyle('v', textColor=sc, leading=16))]],
        colWidths=[30*mm, 130*mm]
    )
    score_table.setStyle(TableStyle([
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (0,0), (0,0), 'CENTER'),
        ('BOX', (0,0), (-1,-1), 1, sc),
        ('TOPPADDING', (0,0), (-1,-1), 12),
        ('BOTTOMPADDING', (0,0), (-1,-1), 12),
        ('LEFTPADDING', (0,0), (-1,-1), 14),
    ]))
    story.append(score_table)
    story.append(Spacer(1, 18))

    # Findings
    story.append(Paragraph("Findings & Recommendations", section_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#dddddd')))
    story.append(Spacer(1, 8))

    findings = simple_report.get('findings', [])

    if not findings:
        story.append(Paragraph("No issues found. Your site looks good!", normal_style))
    else:
        for f in findings:
            risk = f.get('risk', 'Low')
            badge_color = SEVERITY_COLORS.get(risk, colors.gray)
            text_color = TEXT_COLORS.get(risk, colors.white)

            header_row = [[
                Paragraph(f'<font color="white">{risk}</font>' if risk in ('Critical','High')
                          else risk, badge_style),
                Paragraph(f.get('title', ''), finding_title_style)
            ]]
            header_table = Table(header_row, colWidths=[22*mm, 138*mm])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0,0), (0,0), badge_color),
                ('TEXTCOLOR', (0,0), (0,0), text_color),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('ALIGN', (0,0), (0,0), 'CENTER'),
                ('TOPPADDING', (0,0), (-1,-1), 6),
                ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ('LEFTPADDING', (1,0), (1,0), 10),
            ]))
            story.append(header_table)
            story.append(Spacer(1, 4))
            story.append(Paragraph(f.get('explain', ''), explain_style))
            story.append(Paragraph(f"What to do: {f.get('fix', '')}", fix_style))
            story.append(Spacer(1, 14))

    doc.build(story)
    return output_path