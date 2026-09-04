"""Checkpoint 7 - SAR report generation.

LLM-based summary of the complete investigation dossier (evidence, the three
Grok agent responses, regulatory findings, RAG references, auditor result,
next-best-action, audit trail) rendered into a password-protected PDF.
The finalized case moves from cases.csv into audit_ready_cases.csv.

PDF password = last four characters of the account holder's account id
(digit-based when the id contains at least four digits).
"""
from __future__ import annotations

import csv
import json
import os
import re
from datetime import datetime
from xml.sax.saxutils import escape

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas as pdfcanvas
from reportlab.platypus import (HRFlowable, PageBreak, Paragraph,
                                SimpleDocTemplate, Spacer, Table, TableStyle)

from agents.grok_client import GrokClient
from evidence.sanitizer import load_aliases

# alias tokens look like ACC-0001 / TXN-0012 (pure-digit bodies)
ALIAS_RE = re.compile(r"\b(?:ACC|CUS|TXN|DEV|GEO|BEN|EXT|ALR|GTA)-[0-9]{4}\b")

# the only SAR fields the backend is approved to restore
RESTORABLE_FIELDS = ("executive_summary", "suspicious_activity_narrative",
                     "subject_analysis", "assessment_conclusion")


def resolve_aliases(text: str, alias_map: dict[str, str]) -> str:
    """Controlled backend-side alias restoration: replace ONLY exact alias
    tokens that exist in the mapping; unknown aliases and all other text are
    preserved unchanged. The mapping never leaves the backend."""
    return ALIAS_RE.sub(lambda m: alias_map.get(m.group(0), m.group(0)), text)


def resolve_narrative(narrative: dict, alias_map: dict[str, str]) -> dict:
    """Resolve aliases in the approved narrative fields only."""
    return {k: (resolve_aliases(v, alias_map) if k in RESTORABLE_FIELDS
                and isinstance(v, str) else v)
            for k, v in narrative.items()}

AUDIT_READY_SCHEMA = [
    "case_id", "account_id", "created_at", "primary_trigger", "alert_ids",
    "evidence_signals", "typologies", "status", "bundle_reason",
    "completeness_score", "nba_action", "sar_generated_at", "report_path",
]

SYSTEM_PROMPT = (
    "You are a financial-crime reporting analyst for an Indian bank writing a "
    "Suspicious Activity Report (SAR) narrative. Use ONLY the facts in the "
    "provided dossier - never invent evidence, ids, amounts or dates. All "
    "identifiers in the dossier are masked aliases; keep them as-is. Return "
    "strict JSON with keys: executive_summary (3-5 sentences), "
    "suspicious_activity_narrative (detailed paragraphs covering fund flows, "
    "network and security findings), subject_analysis (behaviour of the case "
    "account), assessment_conclusion (which hypothesis is better supported and "
    "why, referencing the contradiction agent's verdict)."
)


def password_for(account_id: str) -> str:
    digits = [c for c in account_id if c.isdigit()]
    if len(digits) >= 4:
        return "".join(digits)[-4:]
    return account_id[-4:].upper()


def _compact_dossier(evidence: dict, analysis: dict, trail: list[dict]) -> dict:
    net = evidence.get("network", {})
    return {
        "case": evidence.get("case"),
        "account": evidence.get("account"),
        "alerts": evidence.get("alerts"),
        "transactions": (evidence.get("transactions") or [])[:12],
        "devices": evidence.get("devices"),
        "geo_events": (evidence.get("geo_events") or [])[:6],
        "beneficiaries": (evidence.get("beneficiaries") or [])[:8],
        "network": {"stats": net.get("stats"), "edges": (net.get("edges") or [])[:8]},
        "agents": analysis.get("agents"),
        "regulatory": analysis.get("regulatory"),
        "regulatory_rag": analysis.get("regulatory_rag"),
        "auditor": analysis.get("auditor"),
        "next_best_action": analysis.get("next_best_action"),
        "audit_trail": (trail or [])[-6:],
    }


def sar_summary(dossier: dict) -> dict:
    return GrokClient().complete(SYSTEM_PROMPT, json.dumps(dossier, default=str))


# ---------------- PDF presentation ----------------
# Reportlab's built-in fonts lack Unicode glyphs used by the LLM output
# (rupee sign, non-breaking hyphen, narrow spaces), which rendered as boxes.
# Everything is normalized to Latin-1-safe text and a TTF family is
# registered (when available) purely for a cleaner look.

_CHAR_MAP = {
    "\u2011": "-", "\u2013": "-", "\u2014": "-",
    "\u202f": " ", "\u00a0": " ",
    "\u2018": "'", "\u2019": "'",
    "\u201c": '"', "\u201d": '"',
    "\u2026": "...", "\u00d7": "x", "\u20b9": "Rs ",
}


def _clean(value) -> str:
    s = str(value)
    for src, dst in _CHAR_MAP.items():
        s = s.replace(src, dst)
    return s.encode("cp1252", "replace").decode("cp1252")


def _esc(value) -> str:
    return escape(_clean(value))


def _register_fonts() -> tuple[str, str, str]:
    import sys
    base = r"C:\Windows\Fonts"
    candidates = [
        (base + r"\arial.ttf", base + r"\arialbd.ttf", base + r"\ariali.ttf"),
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"),
    ] if sys.platform == "win32" else [
        ("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf",
         "/usr/share/fonts/truetype/dejavu/DejaVuSans-Oblique.ttf"),
    ]
    for reg, bold, ital in candidates:
        try:
            if all(os.path.exists(p) for p in (reg, bold, ital)):
                pdfmetrics.registerFont(TTFont("SarFont", reg))
                pdfmetrics.registerFont(TTFont("SarFont-Bold", bold))
                pdfmetrics.registerFont(TTFont("SarFont-Italic", ital))
                pdfmetrics.registerFontFamily(
                    "SarFont", normal="SarFont", bold="SarFont-Bold",
                    italic="SarFont-Italic", boldItalic="SarFont-Bold")
                return "SarFont", "SarFont-Bold", "SarFont-Italic"
        except Exception:
            continue
    return "Helvetica", "Helvetica-Bold", "Helvetica-Oblique"


_FONT_REG, _FONT_BOLD, _FONT_ITAL = _register_fonts()

BRAND = colors.HexColor("#0d3a4d")
ACCENT = colors.HexColor("#2f8ca3")
MUTED = colors.HexColor("#5b6f7b")
LIGHT = colors.HexColor("#edf3f6")
LINE = colors.HexColor("#c7d5dc")
INK = colors.HexColor("#1c2830")
PASS_C = "#1f7a44"
FAIL_C = "#a33b3b"


def _styles() -> dict:
    return {
        "title": ParagraphStyle("SarTitle", fontName=_FONT_BOLD, fontSize=20,
                                leading=24, textColor=BRAND),
        "subtitle": ParagraphStyle("SarSubtitle", fontName=_FONT_REG,
                                   fontSize=9, leading=12, textColor=MUTED,
                                   spaceBefore=4),
        "h1": ParagraphStyle("SarH1", fontName=_FONT_BOLD, fontSize=11.5,
                             leading=14, textColor=BRAND, spaceBefore=14,
                             spaceAfter=5),
        "h2": ParagraphStyle("SarH2", fontName=_FONT_BOLD, fontSize=9.5,
                             leading=12, textColor=ACCENT, spaceBefore=8,
                             spaceAfter=2),
        "body": ParagraphStyle("SarBody", fontName=_FONT_REG, fontSize=9.5,
                               leading=13.5, textColor=INK, spaceAfter=5),
        "bullet": ParagraphStyle("SarBullet", fontName=_FONT_REG, fontSize=9,
                                 leading=12.5, textColor=INK, leftIndent=12,
                                 bulletIndent=3, spaceAfter=2),
        "cell": ParagraphStyle("SarCell", fontName=_FONT_REG, fontSize=8.3,
                               leading=10.5, textColor=INK),
        "cellb": ParagraphStyle("SarCellB", fontName=_FONT_BOLD, fontSize=8.3,
                                leading=10.5, textColor=INK),
        "small": ParagraphStyle("SarSmall", fontName=_FONT_ITAL, fontSize=8.5,
                                leading=11.5, textColor=MUTED, spaceAfter=4),
    }


def Spacer4(styles):
    """Small vertical spacer between stacked flowables."""
    return Spacer(1, 4)


def _grid_style(header: bool) -> TableStyle:
    style = [
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]
    if header:
        style += [
            ("BACKGROUND", (0, 0), (-1, 0), BRAND),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ]
    return TableStyle(style)


def _kv_table(rows, styles):
    if not rows:
        return Paragraph("No records available.", styles["small"])
    data = [[Paragraph(f"<b>{_esc(k)}</b>", styles["cell"]),
             Paragraph(_esc(v), styles["cell"])] for k, v in rows]
    t = Table(data, colWidths=[125, 368], hAlign="LEFT")
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def _callout(text_html: str, styles) -> Table:
    t = Table([[Paragraph(text_html, styles["body"])]], colWidths=[493])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT),
        ("LINEBEFORE", (0, 0), (0, -1), 2.5, ACCENT),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
    ]))
    return t


def _bullets(items, styles, am) -> list:
    flow = []
    for item in items:
        if isinstance(item, (dict, list)):
            item = json.dumps(item, default=str)
        text = _clean(str(item)).strip()
        if text:
            flow.append(Paragraph(escape(resolve_aliases(text, am)),
                                  styles["bullet"], bulletText="\u2022"))
    return flow


def _agent_block(title: str, obj, styles, am) -> list:
    flow = [Paragraph(_esc(title), styles["h2"])]
    if not isinstance(obj, dict) or not obj:
        flow.append(Paragraph("No response stored for this agent.",
                              styles["small"]))
        return flow
    hyp = obj.get("hypothesis") or obj.get("summary")
    if hyp:
        flow.append(Paragraph(escape(resolve_aliases(_clean(str(hyp)), am)),
                              styles["body"]))
    meta = []
    if obj.get("verdict"):
        meta.append(f"verdict: {_esc(obj['verdict'])}")
    if obj.get("typology_assessment"):
        meta.append(f"typology: {_esc(obj['typology_assessment'])}")
    if obj.get("confidence") is not None:
        meta.append(f"confidence: {_esc(obj['confidence'])}")
    if meta:
        flow.append(Paragraph(" &nbsp;&middot;&nbsp; ".join(meta),
                              styles["small"]))
    for label, field in (
            ("Supporting points", "supporting_points"),
            ("Supporting evidence", "supporting_evidence"),
            ("Contradicting points", "contradicting_points"),
            ("Contradictions", "contradictions")):
        val = obj.get(field)
        if isinstance(val, list) and val:
            flow.append(Paragraph(f"<b>{_esc(label)}</b>", styles["h2"]))
            flow.extend(_bullets(val, styles, am))
    for field in ("missing_evidence", "remaining_uncertainty"):
        val = obj.get(field)
        if isinstance(val, list) and val:
            flow.append(Paragraph(f"<b>{pretty_field(field)}</b>", styles["h2"]))
            flow.extend(_bullets(val, styles, am))
        elif isinstance(val, str) and val.strip():
            flow.append(Paragraph(f"<b>{pretty_field(field)}</b>", styles["h2"]))
            flow.append(Paragraph(escape(resolve_aliases(_clean(val), am)),
                                  styles["body"]))
    return flow


def pretty_field(name: str) -> str:
    return name.replace("_", " ").capitalize()


def _rag_block(refs, styles, am) -> list:
    flow = []
    for ref in refs if isinstance(refs, list) else []:
        if not isinstance(ref, dict):
            continue
        head = f"<b>{_esc(ref.get('doc_id', ''))} - {_esc(ref.get('title', ''))}</b>"
        if ref.get("citation"):
            head += f" <i>({escape(resolve_aliases(_clean(ref['citation']), am))})</i>"
        flow.append(Paragraph(head, styles["body"]))
        text = _clean(str(ref.get("text", "")))
        if len(text) > 320:
            text = text[:320].rsplit(" ", 1)[0] + "..."
        if text:
            flow.append(Paragraph(escape(text), styles["small"]))
    return flow


def _checks_table(checks, styles) -> Table:
    rows = [[Paragraph("<b>Check</b>", styles["cellb"]),
             Paragraph("<b>Result</b>", styles["cellb"]),
             Paragraph("<b>Weight</b>", styles["cellb"]),
             Paragraph("<b>Note</b>", styles["cellb"])]]
    for c in checks if isinstance(checks, list) else []:
        passed = bool(c.get("passed"))
        result = (f'<font color="{PASS_C}"><b>PASS</b></font>' if passed
                  else f'<font color="{FAIL_C}"><b>FAIL</b></font>')
        rows.append([
            Paragraph(_esc(c.get("check", "")), styles["cell"]),
            Paragraph(result, styles["cell"]),
            Paragraph(_esc(c.get("weight", "")), styles["cell"]),
            Paragraph(_esc(c.get("note") or "-"), styles["cell"]),
        ])
    if len(rows) == 1:
        return Paragraph("No auditor checks recorded.", styles["small"])
    t = Table(rows, colWidths=[130, 55, 50, 258], repeatRows=1)
    t.setStyle(_grid_style(header=True))
    return t


def _findings_table(findings, styles) -> Table:
    rows = [[Paragraph("<b>Rule</b>", styles["cellb"]),
             Paragraph("<b>Title</b>", styles["cellb"]),
             Paragraph("<b>Severity</b>", styles["cellb"]),
             Paragraph("<b>Applies</b>", styles["cellb"]),
             Paragraph("<b>Detail</b>", styles["cellb"])]]
    for f in findings if isinstance(findings, list) else []:
        rows.append([
            Paragraph(f"<b>{_esc(f.get('rule_id', ''))}</b>", styles["cell"]),
            Paragraph(_esc(f.get("title", "")), styles["cell"]),
            Paragraph(_esc(f.get("severity", "")), styles["cell"]),
            Paragraph("YES" if f.get("applies") else "-", styles["cell"]),
            Paragraph(_esc(f.get("detail") or "-"), styles["cell"]),
        ])
    if len(rows) == 1:
        return Paragraph("No regulatory findings recorded.", styles["small"])
    t = Table(rows, colWidths=[75, 105, 52, 42, 219], repeatRows=1)
    t.setStyle(_grid_style(header=True))
    return t


def _trail_table(events, styles) -> Table:
    rows = [[Paragraph("<b>Timestamp</b>", styles["cellb"]),
             Paragraph("<b>Actor</b>", styles["cellb"]),
             Paragraph("<b>Event</b>", styles["cellb"]),
             Paragraph("<b>Details</b>", styles["cellb"])]]
    for e in events if isinstance(events, list) else []:
        rows.append([
            Paragraph(_esc(e.get("timestamp", "")), styles["cell"]),
            Paragraph(_esc(e.get("actor", "")), styles["cell"]),
            Paragraph(_esc(e.get("event_type", "")), styles["cell"]),
            Paragraph(_esc(e.get("details") or "-"), styles["cell"]),
        ])
    if len(rows) == 1:
        return Paragraph("No audit events recorded.", styles["small"])
    t = Table(rows, colWidths=[85, 42, 132, 234], repeatRows=1)
    t.setStyle(_grid_style(header=True))
    return t


def _numbered_canvas_factory(case_id: str):
    """Two-pass canvas so the footer can print 'Page X of Y'."""

    class NumberedCanvas(pdfcanvas.Canvas):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self._saved_page_states = []
            self._sar_case_id = case_id

        def showPage(self):
            self._saved_page_states.append(dict(self.__dict__))
            self._startPage()

        def save(self):
            total = len(self._saved_page_states)
            for state in self._saved_page_states:
                self.__dict__.update(state)
                self._draw_footer(total)
                pdfcanvas.Canvas.showPage(self)
            pdfcanvas.Canvas.save(self)

        def _draw_footer(self, total):
            self.saveState()
            self.setStrokeColor(LINE)
            self.setLineWidth(0.5)
            self.line(15 * mm, 13 * mm, A4[0] - 15 * mm, 13 * mm)
            self.setFont(_FONT_REG, 7.5)
            self.setFillColor(MUTED)
            self.drawString(15 * mm, 9 * mm,
                            f"CONFIDENTIAL - SAR {self._sar_case_id}")
            self.drawRightString(A4[0] - 15 * mm, 9 * mm,
                                 f"Page {self._pageNumber} of {total}")
            self.restoreState()

    return NumberedCanvas


def _build_pdf(path: str, case: dict, account_id: str, narrative: dict,
               dossier: dict, alias_map: dict | None = None):
    am = alias_map or {}
    st = _styles()
    agents = dossier.get("agents") or {}
    regulatory = dossier.get("regulatory") or {}
    rules = regulatory.get("rules_engine") or regulatory
    auditor = dossier.get("auditor") or {}
    nba = dossier.get("next_best_action") or {}

    story = [
        Paragraph("Suspicious Activity Report (SAR)", st["title"]),
        Paragraph(f"Case {_esc(case['case_id'])} &nbsp;&middot;&nbsp; "
                  f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} "
                  f"&nbsp;&middot;&nbsp; Status SAR_READY", st["subtitle"]),
        HRFlowable(width="100%", thickness=1.2, color=ACCENT,
                   spaceBefore=8, spaceAfter=4),
        Paragraph("1. Case identification", st["h1"]),
        _kv_table([
            ("Case ID", case["case_id"]),
            ("Account ID", account_id),
            ("Primary trigger", case["primary_trigger"]),
            ("Typologies", case["typologies"]),
            ("Status", "SAR_READY"),
            ("Created at", case["created_at"]),
            ("Completeness score", auditor.get("score", "-")),
            ("Next-best action", nba.get("action", "-")),
        ], st),
        Paragraph("2. Executive summary (LLM)", st["h1"]),
        Paragraph(_esc(narrative.get("executive_summary", "")), st["body"]),
        Paragraph("3. Suspicious activity narrative (LLM)", st["h1"]),
        Paragraph(_esc(narrative.get("suspicious_activity_narrative", "")),
                  st["body"]),
        Paragraph("4. Subject analysis (LLM)", st["h1"]),
        Paragraph(_esc(narrative.get("subject_analysis", "")), st["body"]),
        Paragraph("5. Assessment &amp; conclusion (LLM)", st["h1"]),
        Paragraph(_esc(narrative.get("assessment_conclusion", "")), st["body"]),

        PageBreak(),
        Paragraph("6. Hypothesis agents (LLM responses)", st["h1"]),
        Paragraph("Structured view of the three stored agent responses; "
                  "identifiers remain masked aliases outside the approved "
                  "narrative fields.", st["small"]),
    ]
    for key, label in (("scammer_hypothesis", "Fraud / scam hypothesis"),
                       ("legitimate_hypothesis", "Legitimate hypothesis"),
                       ("contradiction", "Contradiction")):
        story.extend(_agent_block(label, agents.get(key), st, am))

    story += [
        Paragraph("7. Regulatory findings &amp; RAG references", st["h1"]),
        _findings_table(rules.get("findings"), st),
        Paragraph(
            f"Applied rules: {_esc(', '.join(rules.get('applied') or []) or '-')}"
            f" &nbsp;&middot;&nbsp; Max severity: <b>{_esc(rules.get('max_severity', '-'))}</b>"
            f" &nbsp;&middot;&nbsp; STR required: "
            f"<b>{'YES' if rules.get('str_required') else 'NO'}</b>",
            st["small"]),
        Paragraph("Regulatory RAG references", st["h2"]),
    ]
    story.extend(_rag_block(dossier.get("regulatory_rag"), st, am))

    story += [
        Paragraph("8. Investigation auditor", st["h1"]),
        _callout(
            f"Completeness score <b>{_esc(auditor.get('score', '-'))}</b> "
            f"(threshold {_esc(auditor.get('threshold', '-'))}) "
            f"&nbsp;&middot;&nbsp; Routing "
            f"<b>{_esc(auditor.get('routing', '-'))}</b>", st),
        Spacer4(st),
        _checks_table(auditor.get("checks"), st),
    ]
    missing = auditor.get("missing")
    if isinstance(missing, list) and missing:
        story.append(Paragraph("<b>Evidence gaps</b>", st["h2"]))
        story.extend(_bullets(missing, st, am))
    story += [
        Paragraph("9. Next-best-action", st["h1"]),
        _callout(f"<b>{_esc(nba.get('action', '-'))}</b>"
                 + (f" - {_esc(nba.get('reason', ''))}"
                    if nba.get("reason") else ""), st),
        Spacer4(st),
        _kv_table(list((nba.get("inputs") or {}).items()), st),
        Paragraph("10. Audit trail", st["h1"]),
        _trail_table(dossier.get("audit_trail"), st),
        Paragraph("11. Final disposition", st["h1"]),
        _callout(
            f"Investigation completed. Case status: <b>SAR_READY</b>. "
            f"Recommended action: <b>{_esc(nba.get('action', '-'))}</b>. "
            f"Routing: <b>{_esc(auditor.get('routing', '-'))}</b>.", st),
    ]

    tmp = path + ".tmp"          # demasked intermediate - encrypted then removed
    doc = SimpleDocTemplate(tmp, pagesize=A4, leftMargin=18 * mm,
                            rightMargin=18 * mm, topMargin=16 * mm,
                            bottomMargin=18 * mm,
                            title=f"SAR {case['case_id']}",
                            author="Tekmerion Intelligence")
    doc.build(story, canvasmaker=_numbered_canvas_factory(case["case_id"]))
    # password-protect
    writer = PdfWriter()
    writer.append(PdfReader(tmp))
    writer.encrypt(password_for(account_id))
    with open(path, "wb") as f:
        writer.write(f)
    os.remove(tmp)


def _mark_audit_ready(mockdata_dir: str, case: dict, dossier: dict,
                      report_path: str):
    # append to audit_ready_cases.csv (lifecycle move, not a new detection)
    ready_path = os.path.join(mockdata_dir, "audit_ready_cases.csv")
    new = not os.path.exists(ready_path)
    with open(ready_path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=AUDIT_READY_SCHEMA)
        if new:
            w.writeheader()
        w.writerow({
            **{k: case[k] for k in AUDIT_READY_SCHEMA[:8]},
            "completeness_score": dossier["auditor"]["score"],
            "nba_action": dossier["next_best_action"]["action"],
            "sar_generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "report_path": report_path,
        })
    # update cases.csv status -> SAR_READY
    cases_path = os.path.join(mockdata_dir, "cases.csv")
    with open(cases_path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
        fields = csv.DictReader(open(cases_path, encoding="utf-8")).fieldnames
    for r in rows:
        if r["case_id"] == case["case_id"]:
            r["status"] = "SAR_READY"
    with open(cases_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)


def generate(case: dict, evidence: dict, analysis: dict, trail: list[dict],
             mockdata_dir: str, alias_map: dict[str, str] | None = None) -> dict:
    alias_map = alias_map or {}
    account_id = case["account_id"]
    reports_dir = os.path.join(mockdata_dir, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    pdf_path = os.path.join(reports_dir, f"SAR_{case['case_id']}.pdf")

    dossier = _compact_dossier(evidence, analysis, trail)
    narrative = sar_summary(dossier)          # LLM sees aliases ONLY
    # trusted backend restores aliases for the approved narrative fields;
    # the demasked text exists only inside the PDF, never in an API response
    resolved = resolve_narrative(narrative, alias_map)
    _build_pdf(pdf_path, case, account_id, resolved, dossier, alias_map)
    _mark_audit_ready(mockdata_dir, case, dossier, pdf_path)

    pwd = password_for(account_id)
    return {"report_path": pdf_path, "password": pwd}
