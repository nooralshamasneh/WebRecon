"""PDF report generated in memory from a scan result (nothing is written to disk)."""
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, Preformatted, SimpleDocTemplate, Spacer, Table, TableStyle

SEV_COLORS = {"critical": "#b00020", "high": "#d84315", "medium": "#ef8f00", "low": "#2e7d32", "info": "#546e7a"}


def build_pdf(result):
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, title=f"WebRecon report - {result['target']}",
                            leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm)
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["Normal"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=8, leading=10, textColor=colors.HexColor("#444444"))
    mono = ParagraphStyle("mono", parent=ss["Code"], fontSize=7, leading=9)
    h1 = ParagraphStyle("h1", parent=ss["Heading1"], textColor=colors.HexColor("#c2185b"), fontSize=20)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#ad1457"), fontSize=13, spaceBefore=10)

    def p(text, style=body):
        return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)

    s, d = result["summary"], result["data"]
    story = [Paragraph("WebRecon Security Report", h1),
             p(f"Target: {result['target']} ({result['ip']})"), p(f"Scan finished: {result['finished_at']}")]
    if s["status"] == "assessed":
        story.append(p(f"Grade: {s['grade']} ({s['label']})   Score: {s['score']}/100   Coverage: {s['coverage']}%"))
    else:
        story.append(p("Grade: not assessed (the target did not respond)"))
    for cap in s["caps"]:
        story.append(p(f"Note: {cap}", small))
    story.append(p("Findings: " + ", ".join(f"{n} {k}" for k, n in s["counts"].items() if n) or "none"))

    story.append(Paragraph("Findings", h2))
    if not result["findings"]:
        story.append(p("No findings."))
    for f in result["findings"]:
        color = SEV_COLORS[f["severity"]]
        head = f"<font color='{color}'><b>[{f['severity'].upper()}]</b></font> <b>{escape(f['title'])}</b> ({f['id']})"
        story.append(Paragraph(head, body))
        meta = f"{f['owasp_name']}" + (f" | ASVS {', '.join(f['asvs'])}" if f["asvs"] else "")
        if f.get("confidence") == "tentative":
            meta += " | tentative (version-based)"
        story.append(p(meta, small))
        story.append(p(f["description"]))
        for ev in f["evidence"][:6]:
            story.append(p(f"  - {ev}", small))
        story.append(p(f"Fix: {f['remediation']}", small))
        story.append(Spacer(1, 5))

    ports = d.get("ports") or {}
    story.append(Paragraph("Open ports and services", h2))
    story.append(Preformatted(ports.get("text", "Not scanned"), mono))

    http = d.get("http")
    if http:
        story.append(Paragraph("HTTP security headers", h2))
        rows = [["Header", "Status", "Value"]] + [[r["name"], r["status"], (r["value"] or "-")[:70]] for r in http["headers"]]
        t = Table([[Paragraph(escape(c), small) for c in r] for r in rows], colWidths=[55 * mm, 20 * mm, 95 * mm])
        t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.25, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f3e5f5"))]))
        story.append(t)
        techs = ", ".join(f"{t['name']}{' ' + t['version'] if t['version'] else ''}" for t in http["technologies"])
        story.append(p(f"Technologies: {techs or 'none detected'}"))

    tls = d.get("tls")
    if tls and tls.get("reachable") and tls.get("certificate"):
        c = tls["certificate"]
        story.append(Paragraph("TLS", h2))
        story.append(p(f"Subject: {c['subject']}\nIssuer: {c['issuer']}\nValid until: {c['not_after']} ({c['days_remaining']} days)\n"
                       f"Key: {c['key_type']} {c['key_bits']}  Signature: {c['signature_hash']}\n"
                       f"Trusted: {tls['trusted']}  Hostname match: {tls['hostname_match']}\n"
                       f"Protocols: " + ", ".join(f"{k}={'yes' if v else 'no' if v is False else 'untested'}" for k, v in tls['protocols'].items())))

    ea = d.get("email_auth")
    if ea:
        story.append(Paragraph("E-mail authentication", h2))
        story.append(p(f"SPF: {(ea['spf'] or {}).get('record', 'none')}\nDMARC: {(ea['dmarc'] or {}).get('record', 'none')}\n"
                       f"DKIM selectors found: {', '.join(ea['dkim_selectors']) or 'none (of the common ones)'}"))

    subs = d.get("subdomains")
    if subs is not None:
        story.append(Paragraph(f"Subdomains ({len(subs)})", h2))
        story.append(p("\n".join(f"{x['name']}  [{', '.join(x['sources'])}]" for x in subs[:100]) or "None found"))
    if d.get("emails"):
        story.append(Paragraph("E-mail addresses", h2))
        story.append(p("\n".join(d["emails"])))
    if d.get("cve"):
        story.append(Paragraph("CVE correlation (NVD, version-based)", h2))
        for cpe, res in d["cve"].items():
            story.append(p(f"{cpe}: {res['total']} CVEs, max CVSS {res['max_cvss']}", small))

    story.append(Paragraph("Modules", h2))
    story.append(p("\n".join(f"{k}: {v['status']} ({v['seconds']}s){' - ' + v['error'] if v['error'] else ''}" for k, v in result["modules"].items())))
    for n in result["notes"]:
        story.append(p(f"Note: {n}", small))
    story.append(Spacer(1, 8))
    story.append(p("WebRecon results are automated indicators, not a penetration test. Verify findings before acting.", small))
    doc.build(story)
    return buf.getvalue()
