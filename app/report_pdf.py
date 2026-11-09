"""PDF report builder (reportlab)."""
import io
from datetime import datetime
from xml.sax.saxutils import escape

from reportlab.graphics.shapes import Drawing, Rect, String
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SEV = {"critical": "#b3261e", "high": "#c2570c", "medium": "#946200", "low": "#3d6b2f", "info": "#555555"}


def _t(x):  # standard PDF fonts are Latin-1 only
    return escape(str(x).encode("latin-1", "replace").decode("latin-1"))


def _score_col(s):
    return "#2fa866" if s >= 80 else "#d9a21b" if s >= 65 else "#e0782b" if s >= 50 else "#d9453b"


def _bars(items):
    row = 7 * mm
    h = row * len(items) + 2
    d = Drawing(170 * mm, h)
    for i, (label, frac, text, col) in enumerate(items):
        y = h - (i + 1) * row
        d.add(String(0, y + 1.5, _t(label).replace("&amp;", "&"), fontSize=8.5, fontName="Helvetica"))
        d.add(Rect(38 * mm, y, 100 * mm, 4 * mm, fillColor=colors.HexColor("#e6e6ea"), strokeColor=None))
        if frac:
            d.add(Rect(38 * mm, y, 100 * mm * frac, 4 * mm, fillColor=colors.HexColor(col), strokeColor=None))
        d.add(String(141 * mm, y + 1.5, text, fontSize=8.5, fontName="Helvetica"))
    return d


def _footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#777777"))
    canvas.drawString(18 * mm, 9 * mm, "SiteScan automated security report")
    canvas.drawRightString(A4[0] - 18 * mm, 9 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(rep, summ):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm,
                            title="Security report - " + str(rep.get("domain", "")))
    ss = getSampleStyleSheet()
    H1 = ParagraphStyle("H1", parent=ss["Title"], alignment=0, fontSize=22, spaceAfter=2)
    H2 = ParagraphStyle("H2", parent=ss["Heading2"], spaceBefore=14, spaceAfter=6)
    B = ParagraphStyle("B", parent=ss["BodyText"], fontSize=9.5, leading=13)
    S = ParagraphStyle("S", parent=B, fontSize=8.5, leading=11, textColor=colors.HexColor("#555555"))
    P = lambda t, st=B: Paragraph(t, st)

    score, grade = rep.get("score") or 0, rep.get("grade", "-")
    mode = "Deep scan (ports and exposed files included)" if rep.get("active_checks_run") else "Quick scan (passive checks only)"
    story = [P("Website Security Report", H1), P(f"<b>{_t(rep.get('domain', ''))}</b>", B),
             P(f"Scanned {_t(rep.get('scanned_at', '')[:16].replace('T', ' '))} UTC &nbsp;|&nbsp; {mode}", S), Spacer(1, 8)]

    counts = Table([[P(f'<font color="{SEV[k]}"><b>{k.title()}</b></font>'), str(summ["counts"][k])] for k in SEV],
                   colWidths=[30 * mm, 15 * mm])
    counts.setStyle(TableStyle([("FONTSIZE", (0, 0), (-1, -1), 9), ("BOTTOMPADDING", (0, 0), (-1, -1), 2), ("TOPPADDING", (0, 0), (-1, -1), 2)]))
    top = Table([[P(f'<font size="40" color="{_score_col(score)}"><b>{score}</b></font><br/><font size="11">/ 100 &nbsp; Grade {_t(grade)}</font>'), counts]],
                colWidths=[70 * mm, 100 * mm])
    top.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cccccc")), ("PADDING", (0, 0), (-1, -1), 10)]))
    story += [top, P("Category scores", H2)]
    items = []
    for c in summ["cats"]:
        if c["score"] is None:
            items.append((c["name"], 0, "not tested", "#999999"))
        else:
            items.append((c["name"], c["score"] / 100, f"{c['score']}  ({c['issues']} issues)", _score_col(c["score"])))
    story.append(_bars(items))

    fixes = [f for f in rep.get("findings", []) if f["id"] in rep.get("top_fixes", [])]
    if fixes:
        story.append(P("Fix these first", H2))
        for i, f in enumerate(fixes, 1):
            story.append(P(f"{i}. <b>{_t(f['title'])}</b>"))

    story.append(P("Findings", H2))
    if not rep.get("findings"):
        story.append(P("No issues found."))
    for f in rep.get("findings", []):
        col = SEV.get(f["severity"], "#555555")
        story.append(KeepTogether([
            P(f'<font color="{col}"><b>{f["severity"].upper()}</b></font> &nbsp; <b>{_t(f["title"])}</b>'),
            P(_t(f["plain"])), P("<b>How to fix:</b> " + _t(f["fix"]), S), Spacer(1, 7)]))

    i = rep.get("info", {})
    cert = i.get("cert", {})
    rows = [("IP addresses", ", ".join(i.get("ips", []))), ("Nameservers", ", ".join(i.get("ns", []))), ("Mail servers", ", ".join(i.get("mx", []))),
            ("Technology", ", ".join(i.get("tech", []))), ("Page title", i.get("title", "")),
            ("Response time", f"{i['response_ms']} ms" if i.get("response_ms") else ""), ("TLS version", i.get("tls_version", "")),
            ("Certificate issuer", cert.get("issuer", "")), ("Certificate expires", f"{cert.get('not_after', '')} ({cert.get('days_left', '')} days)" if cert else ""),
            ("Domain expires", i.get("domain_expiry", "")), ("Open risky ports", ", ".join(map(str, i.get("open_ports", []))) if "open_ports" in i else ""),
            ("SPF", " ".join(i.get("spf", []))[:200]), ("DMARC", " ".join(i.get("dmarc", []))[:200]),
            ("DKIM selectors found", ", ".join(i.get("dkim_selectors_found", [])))]
    rows = [(a, b) for a, b in rows if b]
    if rows:
        story.append(P("Technical details", H2))
        t = Table([[P(f"<b>{a}</b>", S), P(_t(b), S)] for a, b in rows], colWidths=[40 * mm, 130 * mm])
        t.setStyle(TableStyle([("LINEBELOW", (0, 0), (-1, -1), 0.25, colors.HexColor("#dddddd")), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(t)
    story += [Spacer(1, 14), P("Generated by automated checks. This report is a starting point and not a substitute for a full penetration test.", S)]
    doc.build(story, onFirstPage=_footer, onLaterPages=_footer)
    return buf.getvalue()
