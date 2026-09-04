"""SAR report generation.

Checkpoint 7 / Backend Finalization

Responsibilities:
- Generate the LLM-written SAR narrative using Gemini Flash 3.6.
- Keep the LLM boundary sanitized: only aliases/masked evidence are sent.
- Build a decorative, audit-ready PDF.
- Encrypt the resulting PDF with a case-specific password.
- Preserve the existing SAR JSON contract and backend API integration.

Important:
    This module does NOT demask PII for the LLM.
    Alias restoration, when authorized, remains a backend concern.
"""

from __future__ import annotations

import io
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from agents.gemini_client import GeminiClient

from pypdf import PdfReader, PdfWriter

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SAR_JSON_KEYS = (
    "executive_summary",
    "suspicious_activity_narrative",
    "subject_analysis",
    "assessment_conclusion",
)

SYSTEM_PROMPT = """
You are the SAR Narrative Agent in an Indian banking financial-crime
investigation system.

Generate a concise, factual, audit-ready Suspicious Activity Report narrative
from ONLY the supplied investigation dossier.

STRICT RULES:

1. Use only facts present in the supplied dossier.
2. Never invent transactions, dates, amounts, locations, devices, accounts,
   beneficiaries, regulatory findings, or investigative conclusions.
3. Do not infer a person's real identity.
4. The evidence package may contain aliases or masked identifiers such as
   ACCOUNT_001, CUSTOMER_001, DEVICE_004, BENEFICIARY_002.
   Preserve those aliases exactly.
5. Never attempt to reconstruct, guess, or reveal masked PII.
6. Distinguish:
   - smurfing
   - reverse smurfing
   - money mule activity
   - account swap / account compromise
7. An account compromise does not automatically mean that the account is a
   money mule.
8. Clearly distinguish observed facts from analytical conclusions.
9. Mention uncertainty where evidence is incomplete or contradictory.
10. Do not fabricate regulatory citations.
11. Do not fabricate an investigation outcome.
12. Do not include markdown.
13. Return ONLY valid JSON.
14. Use exactly these keys:

{
  "executive_summary": "string",
  "suspicious_activity_narrative": "string",
  "subject_analysis": "string",
  "assessment_conclusion": "string"
}

The report should read like a professional banking financial-crime
investigation document suitable for compliance review and audit.
""".strip()


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def _safe_text(value: Any, default: str = "Not available") -> str:
    """Convert a value into safe printable report text."""

    if value is None:
        return default

    if isinstance(value, str):
        text = value.strip()
        return text if text else default

    if isinstance(value, (dict, list, tuple)):
        try:
            return json.dumps(value, indent=2, default=str)
        except Exception:
            return str(value)

    return str(value)


def _safe_list(value: Any) -> list[Any]:
    """Return a list regardless of the input shape."""

    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def _first_present(data: dict[str, Any], *keys: str, default: Any = None) -> Any:
    """Return the first non-empty value for the supplied keys."""

    for key in keys:
        if key in data and data[key] not in (None, "", [], {}):
            return data[key]

    return default


def _flatten_for_prompt(value: Any) -> Any:
    """Convert nested objects into JSON-safe values."""

    if isinstance(value, dict):
        return {
            str(k): _flatten_for_prompt(v)
            for k, v in value.items()
        }

    if isinstance(value, (list, tuple)):
        return [_flatten_for_prompt(v) for v in value]

    if isinstance(value, (datetime,)):
        return value.isoformat()

    return value


def _json_for_prompt(value: Any, max_chars: int = 12000) -> str:
    """Serialize evidence for the Gemini prompt with a hard size boundary."""

    try:
        text = json.dumps(
            _flatten_for_prompt(value),
            indent=2,
            default=str,
            ensure_ascii=False,
        )
    except Exception:
        text = str(value)

    if len(text) <= max_chars:
        return text

    return text[:max_chars] + "\n...[evidence truncated]"


def _extract_case_id(dossier: dict[str, Any]) -> str:
    return str(
        _first_present(
            dossier,
            "case_id",
            "caseId",
            "id",
            default="UNKNOWN-CASE",
        )
    )


def _extract_account_id(dossier: dict[str, Any]) -> str:
    """Extract the subject/account identifier used for password derivation."""

    account_id = _first_present(
        dossier,
        "account_id",
        "accountId",
        "subject_account_id",
        "subjectAccountId",
        default=None,
    )

    if account_id:
        return str(account_id)

    subject = dossier.get("subject")

    if isinstance(subject, dict):
        account_id = _first_present(
            subject,
            "account_id",
            "accountId",
            "id",
            default=None,
        )

        if account_id:
            return str(account_id)

    # Search one level down in common structures.
    for key in ("case", "case_data", "caseData", "metadata"):
        value = dossier.get(key)

        if isinstance(value, dict):
            account_id = _first_present(
                value,
                "account_id",
                "accountId",
                "subject_account_id",
                "subjectAccountId",
                default=None,
            )

            if account_id:
                return str(account_id)

    return "UNKNOWN"


def _password_from_account_id(account_id: str) -> str:
    """Create the case PDF password.

    Existing contract:
    - If account ID contains at least four characters, use the last four.
    - Otherwise use the last four available characters.
    - Uppercase the password.

    Example:
        ACC-123456 -> 3456
    """

    normalized = str(account_id).strip()

    if not normalized:
        return "CASE"

    if len(normalized) >= 4:
        return normalized[-4:].upper()

    return normalized.upper()


def _normalise_sar_json(result: Any) -> dict[str, str]:
    """Guarantee the existing SAR JSON contract."""

    if isinstance(result, str):
        text = result.strip()

        # Gemini occasionally returns fenced JSON despite the MIME request.
        if text.startswith("```"):
            lines = text.splitlines()

            if lines and lines[0].strip().startswith("```"):
                lines = lines[1:]

            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]

            text = "\n".join(lines).strip()

        try:
            result = json.loads(text)
        except json.JSONDecodeError:
            logger.warning(
                "Gemini returned non-JSON SAR content; using fallback."
            )
            result = {}

    if not isinstance(result, dict):
        result = {}

    return {
        key: _safe_text(
            result.get(key),
            default="Not available from the investigation evidence.",
        )
        for key in SAR_JSON_KEYS
    }


# ---------------------------------------------------------------------------
# Gemini SAR narrative
# ---------------------------------------------------------------------------

def sar_summary(
    dossier: dict[str, Any],
    client: GeminiClient | None = None,
) -> dict[str, str]:
    """Generate the SAR narrative using Gemini Flash 3.6.

    The dossier should already contain sanitized / aliased investigation data.

    The function intentionally does not:
    - demask PII
    - reveal alias mappings
    - query the original customer/account database
    - modify the dossier
    """

    if not isinstance(dossier, dict):
        raise TypeError("SAR dossier must be a dictionary.")

    gemini = client or GeminiClient()

    prompt = (
        "INVESTIGATION DOSSIER\n"
        "=====================\n"
        f"{_json_for_prompt(dossier)}\n\n"
        "Generate the SAR narrative according to the system instructions."
    )

    try:
        result = gemini.complete(
            SYSTEM_PROMPT,
            prompt,
        )

        return _normalise_sar_json(result)

    except Exception as exc:
        logger.exception("Gemini SAR generation failed: %s", exc)

        # Keep the API usable even when the external LLM is unavailable.
        # This fallback contains no invented investigation facts.
        return {
            "executive_summary": (
                "SAR narrative generation was unavailable. "
                "The underlying investigation evidence remains available "
                "for authorized compliance review."
            ),
            "suspicious_activity_narrative": (
                "Automated narrative generation could not be completed. "
                "Refer to the investigation evidence, transaction analysis, "
                "network evidence, and audit trail contained in this report."
            ),
            "subject_analysis": (
                "Automated subject analysis was unavailable. "
                "No additional subject-level conclusion has been generated."
            ),
            "assessment_conclusion": (
                "No automated SAR conclusion was generated because the "
                "narrative model was unavailable."
            ),
        }


# ---------------------------------------------------------------------------
# ReportLab styles
# ---------------------------------------------------------------------------

def _build_styles() -> dict[str, ParagraphStyle]:
    """Create the decorative SAR report style system."""

    base = getSampleStyleSheet()

    return {
        "title": ParagraphStyle(
            "SARTitle",
            parent=base["Title"],
            fontName="Helvetica-Bold",
            fontSize=23,
            leading=27,
            alignment=TA_CENTER,
            spaceAfter=5 * mm,
            textColor=colors.HexColor("#172033"),
        ),
        "subtitle": ParagraphStyle(
            "SARSubtitle",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#566176"),
            spaceAfter=8 * mm,
        ),
        "section": ParagraphStyle(
            "SARSection",
            parent=base["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=colors.HexColor("#172033"),
            spaceBefore=4 * mm,
            spaceAfter=3 * mm,
        ),
        "subsection": ParagraphStyle(
            "SARSubsection",
            parent=base["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=9.5,
            leading=12,
            textColor=colors.HexColor("#33415c"),
            spaceBefore=3 * mm,
            spaceAfter=2 * mm,
        ),
        "body": ParagraphStyle(
            "SARBody",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.8,
            leading=13,
            alignment=TA_LEFT,
            textColor=colors.HexColor("#202735"),
            spaceAfter=3 * mm,
        ),
        "small": ParagraphStyle(
            "SARSmall",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#596579"),
        ),
        "label": ParagraphStyle(
            "SARLabel",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#596579"),
        ),
        "value": ParagraphStyle(
            "SARValue",
            parent=base["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=colors.HexColor("#172033"),
        ),
        "callout": ParagraphStyle(
            "SARCallout",
            parent=base["BodyText"],
            fontName="Helvetica",
            fontSize=8.7,
            leading=13,
            textColor=colors.HexColor("#263247"),
        ),
        "footer": ParagraphStyle(
            "SARFooter",
            parent=base["Normal"],
            fontName="Helvetica",
            fontSize=6.5,
            leading=8,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#687386"),
        ),
    }


# ---------------------------------------------------------------------------
# PDF page decoration
# ---------------------------------------------------------------------------

def _draw_page(canvas, doc) -> None:
    """Draw header/footer decoration on every PDF page."""

    canvas.saveState()

    width, height = A4

    # Header line.
    canvas.setStrokeColor(colors.HexColor("#CBD3DF"))
    canvas.setLineWidth(0.6)
    canvas.line(
        16 * mm,
        height - 14 * mm,
        width - 16 * mm,
        height - 14 * mm,
    )

    canvas.setFont("Helvetica-Bold", 7)
    canvas.setFillColor(colors.HexColor("#35415A"))
    canvas.drawString(
        16 * mm,
        height - 11 * mm,
        "TEKMERION INTELLIGENCE",
    )

    canvas.setFont("Helvetica", 6.5)
    canvas.setFillColor(colors.HexColor("#687386"))
    canvas.drawRightString(
        width - 16 * mm,
        height - 11 * mm,
        "CONFIDENTIAL • FINANCIAL CRIME INVESTIGATION",
    )

    # Footer line.
    canvas.setStrokeColor(colors.HexColor("#CBD3DF"))
    canvas.line(
        16 * mm,
        13 * mm,
        width - 16 * mm,
        13 * mm,
    )

    canvas.setFont("Helvetica", 6.5)
    canvas.setFillColor(colors.HexColor("#687386"))

    canvas.drawString(
        16 * mm,
        9 * mm,
        "CONFIDENTIAL — AUTHORIZED INVESTIGATOR ACCESS ONLY",
    )

    canvas.drawCentredString(
        width / 2,
        9 * mm,
        "SAR / INVESTIGATION REPORT",
    )

    canvas.drawRightString(
        width - 16 * mm,
        9 * mm,
        f"PAGE {doc.page}",
    )

    canvas.restoreState()


# ---------------------------------------------------------------------------
# Generic decorative components
# ---------------------------------------------------------------------------

def _section_heading(title: str, styles: dict[str, ParagraphStyle]):
    return [
        Paragraph(title, styles["section"]),
        HRFlowable(
            width="100%",
            thickness=0.7,
            color=colors.HexColor("#CBD3DF"),
            spaceBefore=0,
            spaceAfter=3 * mm,
        ),
    ]


def _info_table(
    rows: list[tuple[str, str]],
    styles: dict[str, ParagraphStyle],
) -> Table:
    data = []

    for label, value in rows:
        data.append(
            [
                Paragraph(_safe_text(label), styles["label"]),
                Paragraph(_safe_text(value), styles["value"]),
            ]
        )

    table = Table(
        data,
        colWidths=[42 * mm, 130 * mm],
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#F1F4F8"),
                ),
                (
                    "BACKGROUND",
                    (1, 0),
                    (1, -1),
                    colors.white,
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.6,
                    colors.HexColor("#CBD3DF"),
                ),
                (
                    "INNERGRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor("#DCE2EA"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    3 * mm,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    3 * mm,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    2.5 * mm,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    2.5 * mm,
                ),
            ]
        )
    )

    return table


def _callout(
    title: str,
    body: str,
    styles: dict[str, ParagraphStyle],
) -> Table:
    content = [
        Paragraph(
            f"<b>{_safe_text(title)}</b>",
            styles["subsection"],
        ),
        Paragraph(
            _safe_text(body).replace("\n", "<br/>"),
            styles["callout"],
        ),
    ]

    table = Table(
        [[content]],
        colWidths=[172 * mm],
        hAlign="LEFT",
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, -1),
                    colors.HexColor("#F7F9FC"),
                ),
                (
                    "BOX",
                    (0, 0),
                    (-1, -1),
                    0.7,
                    colors.HexColor("#C9D2DF"),
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    4 * mm,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    4 * mm,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    3 * mm,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    3 * mm,
                ),
            ]
        )
    )

    return table


def _bullet_section(
    title: str,
    values: Any,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    items = _safe_list(values)

    if not items:
        return []

    story = [
        Paragraph(title, styles["subsection"]),
    ]

    for item in items:
        text = _safe_text(item).replace("\n", "<br/>")

        story.append(
            Paragraph(
                f"• {text}",
                styles["body"],
            )
        )

    return story


# ---------------------------------------------------------------------------
# Report content extraction
# ---------------------------------------------------------------------------

def _extract_metadata(dossier: dict[str, Any]) -> dict[str, Any]:
    case_id = _extract_case_id(dossier)
    account_id = _extract_account_id(dossier)

    typology = _first_present(
        dossier,
        "typology",
        "primary_trigger",
        "primary_typology",
        default="Not classified",
    )

    status = _first_present(
        dossier,
        "status",
        "case_status",
        default="Investigation report",
    )

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    return {
        "case_id": case_id,
        "account_id": account_id,
        "typology": typology,
        "status": status,
        "generated_at": generated_at,
    }


def _extract_analysis_sections(
    dossier: dict[str, Any],
) -> dict[str, Any]:
    """Locate optional pipeline sections without imposing a new schema."""

    return {
        "hypotheses": _first_present(
            dossier,
            "hypotheses",
            "hypothesis_agents",
            "agent_analysis",
            default={},
        ),
        "regulatory": _first_present(
            dossier,
            "regulatory_findings",
            "regulatory",
            "regulatory_evaluation",
            default={},
        ),
        "rag": _first_present(
            dossier,
            "rag",
            "regulatory_rag",
            "references",
            default={},
        ),
        "auditor": _first_present(
            dossier,
            "auditor",
            "investigation_auditor",
            "audit_review",
            default={},
        ),
        "next_best_action": _first_present(
            dossier,
            "next_best_action",
            "nba",
            "recommended_action",
            default={},
        ),
        "audit_trail": _first_present(
            dossier,
            "audit_trail",
            "audit_events",
            default=[],
        ),
        "network": _first_present(
            dossier,
            "network",
            "network_evidence",
            default={},
        ),
        "evidence": _first_present(
            dossier,
            "evidence",
            "evidence_package",
            default={},
        ),
        "disposition": _first_present(
            dossier,
            "final_disposition",
            "disposition",
            "action",
            default="Not available",
        ),
    }


def _render_hypotheses(
    hypotheses: Any,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    story: list[Any] = []

    if not hypotheses:
        return story

    story.extend(_section_heading("Hypothesis Agent Analysis", styles))

    if isinstance(hypotheses, dict):
        scammer = hypotheses.get("scammer")
        legitimate = hypotheses.get("legitimate")
        contradiction = hypotheses.get("contradiction")

        for title, value in (
            ("Scammer Hypothesis", scammer),
            ("Legitimate Hypothesis", legitimate),
            ("Contradiction Analysis", contradiction),
        ):
            if value:
                if isinstance(value, dict):
                    text = _safe_text(
                        value.get("hypothesis")
                        or value.get("verdict")
                        or value
                    )

                    confidence = value.get("confidence")

                    if confidence is not None:
                        text += (
                            f"<br/><b>Confidence:</b> "
                            f"{_safe_text(confidence)}"
                        )

                    supporting = value.get("supporting_points")
                    contradicting = value.get("contradicting_points")

                    if supporting:
                        text += (
                            "<br/><b>Supporting points:</b><br/>"
                            + "<br/>".join(
                                f"• {_safe_text(x)}"
                                for x in _safe_list(supporting)
                            )
                        )

                    if contradicting:
                        text += (
                            "<br/><b>Contradicting points:</b><br/>"
                            + "<br/>".join(
                                f"• {_safe_text(x)}"
                                for x in _safe_list(contradicting)
                            )
                        )

                else:
                    text = _safe_text(value)

                story.append(
                    _callout(
                        title,
                        text,
                        styles,
                    )
                )
                story.append(Spacer(1, 2 * mm))

    else:
        story.append(
            Paragraph(
                _safe_text(hypotheses),
                styles["body"],
            )
        )

    return story


def _render_regulatory(
    regulatory: Any,
    rag: Any,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    story: list[Any] = []

    if not regulatory and not rag:
        return story

    story.extend(_section_heading("Regulatory Assessment & References", styles))

    if regulatory:
        if isinstance(regulatory, dict):
            findings = regulatory.get(
                "findings",
                regulatory.get("breaches", regulatory),
            )

            if isinstance(findings, list):
                story.extend(
                    _bullet_section(
                        "Regulatory Findings",
                        findings,
                        styles,
                    )
                )
            else:
                story.append(
                    Paragraph(
                        _safe_text(findings),
                        styles["body"],
                    )
                )
        else:
            story.append(
                Paragraph(
                    _safe_text(regulatory),
                    styles["body"],
                )
            )

    if rag:
        if isinstance(rag, dict):
            references = _first_present(
                rag,
                "references",
                "sources",
                "documents",
                "citations",
                default=rag,
            )

            if isinstance(references, list):
                story.extend(
                    _bullet_section(
                        "Reference Material",
                        references,
                        styles,
                    )
                )
            else:
                story.append(
                    Paragraph(
                        "<b>Reference Material</b>",
                        styles["subsection"],
                    )
                )
                story.append(
                    Paragraph(
                        _safe_text(references),
                        styles["body"],
                    )
                )
        else:
            story.append(
                Paragraph(
                    "<b>Reference Material</b>",
                    styles["subsection"],
                )
            )
            story.append(
                Paragraph(
                    _safe_text(rag),
                    styles["body"],
                )
            )

    return story


def _render_auditor(
    auditor: Any,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    if not auditor:
        return []

    story = _section_heading(
        "Investigation Auditor Review",
        styles,
    )

    if isinstance(auditor, dict):
        completeness = _first_present(
            auditor,
            "completeness_score",
            "completeness",
            default=None,
        )

        checks = _first_present(
            auditor,
            "checks",
            "audit_checks",
            "findings",
            default=None,
        )

        conclusion = _first_present(
            auditor,
            "conclusion",
            "assessment",
            "summary",
            default=None,
        )

        if completeness is not None:
            story.append(
                _callout(
                    "Evidence Completeness",
                    str(completeness),
                    styles,
                )
            )
            story.append(Spacer(1, 2 * mm))

        if checks:
            if isinstance(checks, list):
                story.extend(
                    _bullet_section(
                        "Auditor Checks",
                        checks,
                        styles,
                    )
                )
            else:
                story.append(
                    Paragraph(
                        _safe_text(checks),
                        styles["body"],
                    )
                )

        if conclusion:
            story.append(
                _callout(
                    "Auditor Conclusion",
                    _safe_text(conclusion),
                    styles,
                )
            )

    else:
        story.append(
            Paragraph(
                _safe_text(auditor),
                styles["body"],
            )
        )

    return story


def _render_nba(
    nba: Any,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    if not nba:
        return []

    story = _section_heading(
        "Next-Best-Action / Recommended Disposition",
        styles,
    )

    if isinstance(nba, dict):
        action = _first_present(
            nba,
            "action",
            "recommended_action",
            "recommendation",
            default="Not available",
        )

        rationale = _first_present(
            nba,
            "rationale",
            "reason",
            "explanation",
            default=None,
        )

        priority = _first_present(
            nba,
            "priority",
            "risk_level",
            default=None,
        )

        body = f"<b>Recommended action:</b> {_safe_text(action)}"

        if priority is not None:
            body += f"<br/><b>Priority / risk:</b> {_safe_text(priority)}"

        if rationale is not None:
            body += f"<br/><br/><b>Rationale:</b> {_safe_text(rationale)}"

        story.append(
            _callout(
                "Recommended Action",
                body,
                styles,
            )
        )

    else:
        story.append(
            _callout(
                "Recommended Action",
                _safe_text(nba),
                styles,
            )
        )

    return story


def _render_audit_trail(
    audit_trail: Any,
    styles: dict[str, ParagraphStyle],
) -> list[Any]:
    events = _safe_list(audit_trail)

    if not events:
        return []

    story = _section_heading(
        "Audit Trail",
        styles,
    )

    rows = [
        [
            Paragraph("Event", styles["label"]),
            Paragraph("Actor", styles["label"]),
            Paragraph("Type", styles["label"]),
            Paragraph("Details", styles["label"]),
        ]
    ]

    for event in events:
        if not isinstance(event, dict):
            rows.append(
                [
                    Paragraph("-", styles["small"]),
                    Paragraph("-", styles["small"]),
                    Paragraph("-", styles["small"]),
                    Paragraph(
                        _safe_text(event),
                        styles["small"],
                    ),
                ]
            )
            continue

        rows.append(
            [
                Paragraph(
                    _safe_text(
                        event.get("event_id")
                        or event.get("id")
                        or "-"
                    ),
                    styles["small"],
                ),
                Paragraph(
                    _safe_text(event.get("actor", "-")),
                    styles["small"],
                ),
                Paragraph(
                    _safe_text(event.get("event_type", "-")),
                    styles["small"],
                ),
                Paragraph(
                    _safe_text(event.get("details", "-")),
                    styles["small"],
                ),
            ]
        )

    table = Table(
        rows,
        colWidths=[
            29 * mm,
            28 * mm,
            34 * mm,
            81 * mm,
        ],
        repeatRows=1,
    )

    table.setStyle(
        TableStyle(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#E9EEF5"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#33415C"),
                ),
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor("#D2D9E3"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    2 * mm,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    2 * mm,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    1.8 * mm,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    1.8 * mm,
                ),
            ]
        )
    )

    story.append(table)

    return story


# ---------------------------------------------------------------------------
# PDF generation
# ---------------------------------------------------------------------------

def _build_pdf(
    dossier: dict[str, Any],
    sar: dict[str, str],
) -> bytes:
    """Build the decorative SAR PDF in memory."""

    metadata = _extract_metadata(dossier)
    sections = _extract_analysis_sections(dossier)
    styles = _build_styles()

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=19 * mm,
        leftMargin=19 * mm,
        topMargin=21 * mm,
        bottomMargin=19 * mm,
        title=f"SAR Report - {metadata['case_id']}",
        author="Tekmerion Intelligence",
        subject="Financial Crime Suspicious Activity Report",
    )

    story: list[Any] = []

    # -----------------------------------------------------------------------
    # Cover / identification
    # -----------------------------------------------------------------------

    story.append(Spacer(1, 5 * mm))

    story.append(
        Paragraph(
            "SUSPICIOUS ACTIVITY REPORT",
            styles["title"],
        )
    )

    story.append(
        Paragraph(
            "TEKMERION INTELLIGENCE • FINANCIAL CRIME INVESTIGATION",
            styles["subtitle"],
        )
    )

    identification_rows = [
        ("Case ID", metadata["case_id"]),
        ("Subject Account", metadata["account_id"]),
        ("Primary Typology", metadata["typology"]),
        ("Report Status", metadata["status"]),
        ("Generated", metadata["generated_at"]),
        ("Confidentiality", "CONFIDENTIAL"),
    ]

    story.append(
        _info_table(
            identification_rows,
            styles,
        )
    )

    story.append(Spacer(1, 7 * mm))

    story.append(
        _callout(
            "Document Security",
            (
                "This report contains investigation information and is "
                "password protected. Access is restricted to authorized "
                "investigators and compliance personnel."
            ),
            styles,
        )
    )

    # -----------------------------------------------------------------------
    # Executive summary
    # -----------------------------------------------------------------------

    story.extend(
        _section_heading(
            "1. Executive Summary",
            styles,
        )
    )

    story.append(
        Paragraph(
            sar["executive_summary"].replace("\n", "<br/>"),
            styles["body"],
        )
    )

    # -----------------------------------------------------------------------
    # Suspicious activity narrative
    # -----------------------------------------------------------------------

    story.extend(
        _section_heading(
            "2. Suspicious Activity Narrative",
            styles,
        )
    )

    story.append(
        Paragraph(
            sar["suspicious_activity_narrative"].replace(
                "\n",
                "<br/>",
            ),
            styles["body"],
        )
    )

    # -----------------------------------------------------------------------
    # Subject analysis
    # -----------------------------------------------------------------------

    story.extend(
        _section_heading(
            "3. Subject Analysis",
            styles,
        )
    )

    story.append(
        Paragraph(
            sar["subject_analysis"].replace("\n", "<br/>"),
            styles["body"],
        )
    )

    # -----------------------------------------------------------------------
    # Evidence overview
    # -----------------------------------------------------------------------

    evidence = sections["evidence"]

    if evidence:
        story.extend(
            _section_heading(
                "4. Investigation Evidence",
                styles,
            )
        )

        if isinstance(evidence, dict):
            for key, value in evidence.items():
                if value in (None, "", [], {}):
                    continue

                if isinstance(value, list):
                    story.extend(
                        _bullet_section(
                            str(key).replace("_", " ").title(),
                            value,
                            styles,
                        )
                    )
                elif isinstance(value, dict):
                    story.append(
                        Paragraph(
                            str(key).replace("_", " ").title(),
                            styles["subsection"],
                        )
                    )

                    story.append(
                        Paragraph(
                            _safe_text(value).replace(
                                "\n",
                                "<br/>",
                            ),
                            styles["body"],
                        )
                    )
                else:
                    story.append(
                        Paragraph(
                            f"<b>{str(key).replace('_', ' ').title()}</b>: "
                            f"{_safe_text(value)}",
                            styles["body"],
                        )
                    )
        else:
            story.append(
                Paragraph(
                    _safe_text(evidence),
                    styles["body"],
                )
            )

    # -----------------------------------------------------------------------
    # Network evidence
    # -----------------------------------------------------------------------

    network = sections["network"]

    if network:
        story.extend(
            _section_heading(
                "5. Network / Transaction Analysis",
                styles,
            )
        )

        if isinstance(network, dict):
            for key, value in network.items():
                if value in (None, "", [], {}):
                    continue

                title = str(key).replace("_", " ").title()

                if isinstance(value, list):
                    story.extend(
                        _bullet_section(
                            title,
                            value,
                            styles,
                        )
                    )
                else:
                    story.append(
                        Paragraph(
                            f"<b>{title}</b>",
                            styles["subsection"],
                        )
                    )
                    story.append(
                        Paragraph(
                            _safe_text(value).replace(
                                "\n",
                                "<br/>",
                            ),
                            styles["body"],
                        )
                    )
        else:
            story.append(
                Paragraph(
                    _safe_text(network),
                    styles["body"],
                )
            )

    # -----------------------------------------------------------------------
    # Hypothesis analysis
    # -----------------------------------------------------------------------

    story.extend(
        _render_hypotheses(
            sections["hypotheses"],
            styles,
        )
    )

    # -----------------------------------------------------------------------
    # Regulatory assessment
    # -----------------------------------------------------------------------

    story.extend(
        _render_regulatory(
            sections["regulatory"],
            sections["rag"],
            styles,
        )
    )

    # -----------------------------------------------------------------------
    # Auditor
    # -----------------------------------------------------------------------

    story.extend(
        _render_auditor(
            sections["auditor"],
            styles,
        )
    )

    # -----------------------------------------------------------------------
    # Next-best-action
    # -----------------------------------------------------------------------

    story.extend(
        _render_nba(
            sections["next_best_action"],
            styles,
        )
    )

    # -----------------------------------------------------------------------
    # Assessment / conclusion
    # -----------------------------------------------------------------------

    story.extend(
        _section_heading(
            "Assessment & Conclusion",
            styles,
        )
    )

    story.append(
        Paragraph(
            sar["assessment_conclusion"].replace(
                "\n",
                "<br/>",
            ),
            styles["body"],
        )
    )

    # -----------------------------------------------------------------------
    # Final disposition
    # -----------------------------------------------------------------------

    disposition = sections["disposition"]

    story.extend(
        _section_heading(
            "Final Disposition",
            styles,
        )
    )

    story.append(
        _callout(
            "Investigation Disposition",
            _safe_text(disposition),
            styles,
        )
    )

    # -----------------------------------------------------------------------
    # Audit trail
    # -----------------------------------------------------------------------

    story.extend(
        _render_audit_trail(
            sections["audit_trail"],
            styles,
        )
    )

    # -----------------------------------------------------------------------
    # Closing notice
    # -----------------------------------------------------------------------

    story.append(Spacer(1, 7 * mm))

    story.append(
        _callout(
            "Confidentiality Notice",
            (
                "This document is intended solely for authorized financial "
                "crime investigation, compliance, legal, audit, or regulatory "
                "review. Unauthorized disclosure, modification, or "
                "distribution is prohibited."
            ),
            styles,
        )
    )

    doc.build(
        story,
        onFirstPage=_draw_page,
        onLaterPages=_draw_page,
    )

    return buffer.getvalue()


# ---------------------------------------------------------------------------
# PDF encryption
# ---------------------------------------------------------------------------

def _encrypt_pdf(
    pdf_bytes: bytes,
    password: str,
) -> bytes:
    """Encrypt a PDF using pypdf."""

    reader = PdfReader(io.BytesIO(pdf_bytes))

    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    # Preserve document metadata where possible.
    try:
        if reader.metadata:
            writer.add_metadata(
                {
                    str(key): str(value)
                    for key, value in reader.metadata.items()
                    if value is not None
                }
            )
    except Exception:
        logger.debug(
            "Could not preserve original PDF metadata.",
            exc_info=True,
        )

    writer.encrypt(
        user_password=password,
        owner_password=password,
        use_128bit=True,
    )

    encrypted = io.BytesIO()
    writer.write(encrypted)

    return encrypted.getvalue()


# ---------------------------------------------------------------------------
# Audit-ready marker
# ---------------------------------------------------------------------------

def _mark_audit_ready(
    dossier: dict[str, Any],
    pdf_path: str | os.PathLike[str],
) -> None:
    """Mark the generated SAR as audit-ready in the supplied dossier.

    This is deliberately best-effort. The report itself is still generated
    even if the caller's dossier object is immutable or differently shaped.
    """

    try:
        dossier["sar_report"] = {
            "status": "audit_ready",
            "pdf_path": str(pdf_path),
            "generated_at": datetime.now().isoformat(),
        }
    except Exception:
        logger.debug(
            "Unable to attach SAR audit-ready metadata to dossier.",
            exc_info=True,
        )


# ---------------------------------------------------------------------------
# Public generation API
# ---------------------------------------------------------------------------

def generate(
    dossier: dict[str, Any],
    output_dir: str | os.PathLike[str] | None = None,
    client: GeminiClient | None = None,
) -> dict[str, Any]:
    """Generate a password-protected SAR PDF.

    Parameters
    ----------
    dossier:
        Sanitized investigation dossier. It may contain evidence, network
        analysis, hypothesis results, regulatory findings, auditor results,
        NBA, audit trail, and disposition.

    output_dir:
        Destination directory. Defaults to ``reports/generated``.

    client:
        Optional GeminiClient instance, primarily useful for testing.

    Returns
    -------
    dict
        Existing-style report result containing:
        - case_id
        - account_id
        - pdf_path
        - password
        - sar
        - status
    """

    if not isinstance(dossier, dict):
        raise TypeError("dossier must be a dictionary.")

    metadata = _extract_metadata(dossier)

    case_id = metadata["case_id"]
    account_id = metadata["account_id"]

    # -----------------------------------------------------------------------
    # 1. Generate SAR narrative through Gemini.
    # -----------------------------------------------------------------------

    sar = sar_summary(
        dossier,
        client=client,
    )

    # -----------------------------------------------------------------------
    # 2. Build decorative PDF.
    # -----------------------------------------------------------------------

    pdf_bytes = _build_pdf(
        dossier,
        sar,
    )

    # -----------------------------------------------------------------------
    # 3. Password protection.
    # -----------------------------------------------------------------------

    password = _password_from_account_id(
        account_id,
    )

    encrypted_pdf = _encrypt_pdf(
        pdf_bytes,
        password,
    )

    # -----------------------------------------------------------------------
    # 4. Persist PDF.
    # -----------------------------------------------------------------------

    if output_dir is None:
        output_dir = Path(__file__).resolve().parent / "generated"

    output_path = Path(output_dir)
    output_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    safe_case_id = "".join(
        character
        if character.isalnum() or character in ("-", "_")
        else "_"
        for character in str(case_id)
    )

    pdf_path = output_path / f"SAR_{safe_case_id}.pdf"

    pdf_path.write_bytes(
        encrypted_pdf,
    )

    # -----------------------------------------------------------------------
    # 5. Mark report as audit-ready.
    # -----------------------------------------------------------------------

    _mark_audit_ready(
        dossier,
        pdf_path,
    )

    logger.info(
        "SAR report generated successfully: case=%s path=%s",
        case_id,
        pdf_path,
    )

    return {
        "case_id": case_id,
        "account_id": account_id,
        "pdf_path": str(pdf_path),
        "password": password,
        "sar": sar,
        "status": "audit_ready",
    }


__all__ = [
    "sar_summary",
    "generate",
]