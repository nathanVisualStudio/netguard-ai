from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

LEVEL_COLORS = {
    "low": "#4f7a54",
    "medium": "#a9801f",
    "high": "#bd5d28",
    "critical": "#9f2a22",
    "info": "#47647f",
}
INK = colors.HexColor("#211f1b")
MUTED = colors.HexColor("#6b655a")
RULE = colors.HexColor("#cfc7b4")
WIDTH = 170 * mm

STYLES = {
    "title": ParagraphStyle("title", fontName="Times-Bold", fontSize=24, leading=28, textColor=INK, spaceAfter=4),
    "meta": ParagraphStyle("meta", fontName="Helvetica", fontSize=9, leading=12, textColor=MUTED, spaceAfter=10),
    "h2": ParagraphStyle("h2", fontName="Times-Bold", fontSize=14, leading=18, textColor=INK, spaceBefore=16, spaceAfter=6),
    "body": ParagraphStyle("body", fontName="Helvetica", fontSize=9.5, leading=13.5, textColor=INK),
    "small": ParagraphStyle("small", fontName="Helvetica", fontSize=8.5, leading=11.5, textColor=MUTED),
    "mono": ParagraphStyle("mono", fontName="Courier", fontSize=8, leading=10, textColor=INK),
    "score": ParagraphStyle("score", fontName="Times-Roman", fontSize=54, leading=58),
    "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=MUTED),
}


def _t(value, limit=None):
    text = str(value if value is not None else "")
    text = text.encode("latin-1", "replace").decode("latin-1")
    if limit:
        text = text[:limit]
    return escape(text)


def _color(level):
    return LEVEL_COLORS.get(level, "#211f1b")


def _tag(level):
    return Paragraph(f'<font color="{_color(level)}"><b>{_t(level).upper()}</b></font>', STYLES["label"])


def _grid(extra=()):
    return TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        *extra,
    ])


def _summary(report):
    risk = report["risk"]
    score = Paragraph(
        f'<font color="{_color(risk["level"])}">{risk["score"]}</font>'
        f'<font size="16" color="#6b655a"> / 100</font>',
        STYLES["score"],
    )
    right = [_tag(risk["level"]), Spacer(1, 4), Paragraph(_t(report["narrative"]), STYLES["body"])]
    table = Table([[score, right]], colWidths=[48 * mm, WIDTH - 48 * mm])
    table.setStyle(_grid([
        ("LINEABOVE", (0, 0), (-1, 0), 1, INK),
        ("LINEBELOW", (0, 0), (-1, 0), 0.5, RULE),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
    ]))
    return table


def _counts(report):
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        parts.append(f'<font color="{_color(sev)}"><b>{report["finding_counts"][sev]}</b> {sev}</font>')
    return Paragraph(" &nbsp;&middot;&nbsp; ".join(parts), STYLES["body"])


def _actions(report):
    rows = []
    for i, a in enumerate(report["top_actions"], 1):
        where = f'{_t(a["host"])}:{a["port"]}'
        rows.append([
            Paragraph(str(i), STYLES["small"]),
            _tag(a["severity"]),
            Paragraph(f'{_t(a["action"])} <font color="#6b655a">({where})</font>', STYLES["body"]),
        ])
    table = Table(rows, colWidths=[8 * mm, 22 * mm, WIDTH - 30 * mm])
    table.setStyle(_grid([("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE)]))
    return table


def _finding(f):
    title = f'<b>{_t(f["title"])}</b> <font color="#6b655a" size="8">port {f["port"]}</font>'
    if f.get("cve"):
        title += f' &nbsp;<font name="Courier" size="8" color="#6b655a">{_t(f["cve"])}</font>'
    steps = "<br/>".join(f"&bull; {_t(s)}" for s in f["remediation"])
    body = [
        Paragraph(title, STYLES["body"]),
        Paragraph(_t(f["description"]), STYLES["small"]),
        Spacer(1, 3),
        Paragraph(steps, STYLES["body"]),
    ]
    table = Table([[_tag(f["severity"]), body]], colWidths=[22 * mm, WIDTH - 22 * mm])
    table.setStyle(_grid([
        ("LINEBELOW", (0, 0), (-1, -1), 0.25, RULE),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
    ]))
    return KeepTogether([table])


def _host(h):
    risk = h["risk"]
    head = Paragraph(
        f'{_t(h["ip"])} <font size="10" color="{_color(risk["level"])}">&nbsp;{risk["level"].upper()}'
        f' &middot; {risk["score"]}/100</font>',
        STYLES["h2"],
    )
    rows = [[Paragraph(x, STYLES["label"]) for x in ("PORT", "SERVICE", "BANNER")]]
    for p in h["ports"]:
        lines = (p["banner"] or "").splitlines()
        rows.append([
            Paragraph(f'{p["port"]}/tcp', STYLES["mono"]),
            Paragraph(_t(p["service"]), STYLES["body"]),
            Paragraph(_t(lines[0] if lines else "", 110), STYLES["mono"]),
        ])
    ports = Table(rows, colWidths=[20 * mm, 35 * mm, WIDTH - 55 * mm], repeatRows=1)
    ports.setStyle(_grid([
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, INK),
        ("LINEBELOW", (0, 1), (-1, -1), 0.25, RULE),
    ]))
    factors = ", ".join(f'{_t(f["factor"])} (+{f["impact"]})' for f in risk["factors"])
    story = [head, ports, Spacer(1, 6)]
    if factors:
        story += [Paragraph(f"Key risk factors: {factors}", STYLES["small"]), Spacer(1, 6)]
    story += [_finding(f) for f in h["findings"]]
    return story


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(20 * mm, 11 * mm, "NetGuard AI - automated assessment, verify findings before acting")
    canvas.drawRightString(A4[0] - 20 * mm, 11 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(report):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title="NetGuard AI report",
        author="NetGuard AI",
    )
    meta = (
        f'Target {_t(report["target"])} &nbsp;|&nbsp; {_t(report["scanned_at"])} UTC &nbsp;|&nbsp; '
        f'{report["hosts_scanned"]} address(es) scanned, {report["hosts_with_open_ports"]} with open ports '
        f'&nbsp;|&nbsp; {report["duration_s"]}s'
    )
    story = [
        Paragraph("Network security report", STYLES["title"]),
        Paragraph(meta, STYLES["meta"]),
        _summary(report),
        Spacer(1, 8),
        _counts(report),
    ]
    if report["top_actions"]:
        story += [Paragraph("Priority actions", STYLES["h2"]), _actions(report)]
    if report["hosts"]:
        story.append(Paragraph("Hosts", STYLES["h2"]))
        for h in report["hosts"]:
            story += _host(h)
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buffer.getvalue()
