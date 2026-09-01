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
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import Preformatted, SimpleDocTemplate, Spacer, Table, Paragraph

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


def _section(styles, title):
    return Paragraph(title, styles["Heading2"])


def _kv_table(rows):
    return Table([[escape(str(k)), escape(str(v))] for k, v in rows], colWidths=[170, 320])


def _build_pdf(path: str, case: dict, account_id: str, narrative: dict,
               dossier: dict, alias_map: dict | None = None):
    am = alias_map or {}

    def _dump(obj, cap):
        return resolve_aliases(json.dumps(obj, indent=1, default=str)[:cap], am)

    styles = getSampleStyleSheet()
    story = [
        Paragraph("Suspicious Activity Report (SAR)", styles["Title"]),
        Paragraph(f"Case {escape(case['case_id'])} - generated "
                  f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles["Normal"]),
        Spacer(1, 10),
        _section(styles, "1. Case identification"),
        _kv_table([
            ("case_id", case["case_id"]), ("account_id", account_id),
            ("primary_trigger", case["primary_trigger"]),
            ("typologies", case["typologies"]), ("status", "SAR_READY"),
            ("created_at", case["created_at"]),
            ("completeness_score", dossier["auditor"]["score"]),
            ("next_best_action", dossier["next_best_action"]["action"]),
        ]),
        Spacer(1, 10),
        _section(styles, "2. Executive summary (LLM)"),
        Paragraph(escape(narrative.get("executive_summary", "")), styles["Normal"]),
        Spacer(1, 8),
        _section(styles, "3. Suspicious activity narrative (LLM)"),
        Paragraph(escape(narrative.get("suspicious_activity_narrative", "")), styles["Normal"]),
        Spacer(1, 8),
        _section(styles, "4. Subject analysis (LLM)"),
        Paragraph(escape(narrative.get("subject_analysis", "")), styles["Normal"]),
        Spacer(1, 8),
        _section(styles, "5. Assessment & conclusion (LLM)"),
        Paragraph(escape(narrative.get("assessment_conclusion", "")), styles["Normal"]),
        Spacer(1, 10),
        _section(styles, "6. Hypothesis agents (LLM responses)"),
        Preformatted(_dump(dossier["agents"], 3500),
                     ParagraphStyle("mono", fontName="Courier", fontSize=6.5, leading=8)),
        Spacer(1, 8),
        _section(styles, "7. Regulatory findings & RAG references"),
        Preformatted(_dump({"rules_engine": dossier["regulatory"],
                           "rag": dossier["regulatory_rag"]}, 2500),
                     ParagraphStyle("mono2", fontName="Courier", fontSize=6.5, leading=8)),
        Spacer(1, 8),
        _section(styles, "8. Investigation auditor"),
        Preformatted(_dump(dossier["auditor"], 1800),
                     ParagraphStyle("mono3", fontName="Courier", fontSize=6.5, leading=8)),
        Spacer(1, 8),
        _section(styles, "9. Next-best-action"),
        Preformatted(_dump(dossier["next_best_action"], 2000),
                     ParagraphStyle("mono4", fontName="Courier", fontSize=6.5, leading=8)),
        Spacer(1, 8),
        _section(styles, "10. Audit trail"),
        Preformatted(_dump(dossier["audit_trail"], 2200),
                     ParagraphStyle("mono5", fontName="Courier", fontSize=6.5, leading=8)),
        Spacer(1, 8),
        _section(styles, "11. Final disposition"),
        Paragraph(escape(f"Investigation completed. Case status: SAR_READY. "
                         f"Recommended action: {dossier['next_best_action']['action']}. "
                         f"Routing: {dossier['auditor']['routing']}."), styles["Normal"]),
    ]
    tmp = path + ".tmp"          # demasked intermediate - encrypted then removed
    SimpleDocTemplate(tmp, pagesize=A4).build(story)
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
