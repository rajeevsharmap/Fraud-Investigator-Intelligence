"""FastAPI service boundary for the Detection Layer (Checkpoint 2 MVP).

Flow (per the MVP execution requirement):
  - The Detection pipeline runs at application startup (and on explicit
    POST /detection/run). It writes cases.csv / suspected_alerts.csv.
  - GET /cases reads the already-generated cases and returns only those
    authorized for the authenticated investigator's role.
  - GET /cases/{case_id}/network builds the fund-flow graph ON DEMAND for
    the selected case (NetworkX, <= 3 hops) and returns Cytoscape.js JSON.

Role auth is a lightweight MVP header scheme; Checkpoint 3+ replaces it
with real authentication/authorization without changing this boundary.

LLM provider:
  - Google Gemini
  - GeminiClient from agents.gemini_client
  - Intended model: gemini-3.6-flash

PII boundary:
  - Evidence sent to the LLM is sanitized/masked.
  - Alias mappings remain backend-only.
  - /agents/reveal performs deterministic backend-side alias resolution.
  - No LLM rerun is performed during PII reveal.
"""

from __future__ import annotations

import csv
import json
import os
import random
import string
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse

from agents.gemini_client import GeminiClient
from agents.hypothesis_agents import run_all as run_agents

from audit.auditor import audit as run_auditor
from audit.next_best_action import next_best_action
from audit.trail import read as read_trail, record as record_event

from detection.loader import BankData
from detection.network_layer import build_case_network
from detection.pipeline import run_pipeline

from evidence.builder import EvidenceBuilder
from evidence.sanitizer import PIISanitizer, load_aliases

from regulatory.rag import retrieve as rag_retrieve
from regulatory.rules_engine import evaluate as regulatory_evaluate

from reports.sar import generate as generate_sar
from reports.case_memory import (
    save as save_reference,
    read_all as read_references,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

MOCKDATA_DIR = os.environ.get("MOCKDATA_DIR", "./mockdata")

VALID_ROLES = ("JUNIOR", "SENIOR")

# Gemini model configuration is handled by GeminiClient itself.
# The expected environment configuration is:
#
# GEMINI_API_KEY=your_gemini_api_key
# GEMINI_MODEL=gemini-3.6-flash


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def _read_csv(name: str) -> list[dict]:
    """Read a CSV file from MOCKDATA_DIR.

    Returns an empty list when the requested file does not exist.
    """
    path = os.path.join(MOCKDATA_DIR, name)

    if not os.path.exists(path):
        return []

    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _require_role(role: str | None) -> str:
    """Validate the investigator role header."""
    r = (role or "").strip().upper()

    if r not in VALID_ROLES:
        raise HTTPException(
            status_code=401,
            detail=(
                "missing/invalid X-Investigator-Role header "
                "(JUNIOR or SENIOR)"
            ),
        )

    return r


def _evidence_path(case_id: str, suffix: str) -> str:
    """Return the path for a case-specific evidence artifact."""
    return os.path.join(
        MOCKDATA_DIR,
        "evidence",
        f"{case_id}{suffix}.json",
    )


def _save_json(obj: dict, path: str):
    """Persist a JSON object."""
    directory = os.path.dirname(path)

    if directory:
        os.makedirs(directory, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        json.dump(
            obj,
            f,
            indent=1,
            default=str,
        )


def _load_json(path: str) -> dict:
    """Load a JSON object from disk."""
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# FastAPI application lifecycle
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the detection data-processing cycle."""
    run_pipeline(MOCKDATA_DIR)

    app.state.data = BankData(MOCKDATA_DIR)

    yield


app = FastAPI(
    title="Tekmerion Intelligence - Detection API",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {
        "status": "ok",
        "mockdata": os.path.abspath(MOCKDATA_DIR),
    }


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

@app.post("/detection/run")
def detection_run():
    """Explicit backend trigger for the detection pipeline."""
    alerts, cases = run_pipeline(MOCKDATA_DIR)

    # Refresh BankData after detection has regenerated/updated the data.
    app.state.data = BankData(MOCKDATA_DIR)

    return {
        "alerts": len(alerts),
        "cases": len(cases),
    }


# ---------------------------------------------------------------------------
# Case listing
# ---------------------------------------------------------------------------

@app.get("/cases")
def list_cases(
    x_investigator_role: str | None = Header(default=None),
):
    role = _require_role(x_investigator_role)

    cases = _read_csv("cases.csv")

    if role == "JUNIOR":
        # Every new case lands in the Junior queue.
        cases = [
            c for c in cases
            if c["status"] == "JUNIOR"
        ]

    return {
        "role": role,
        "count": len(cases),
        "cases": cases,
    }


def _get_case(case_id: str, role: str) -> dict:
    """Retrieve a case after applying role-based visibility."""
    for c in _read_csv("cases.csv"):
        if c["case_id"] == case_id:

            # Junior keeps queue visibility, but may still view cases
            # they worked that have been finalized.
            if (
                role == "JUNIOR"
                and c["status"] not in ("JUNIOR", "SAR_READY")
            ):
                raise HTTPException(
                    status_code=403,
                    detail="case not authorized for JUNIOR role",
                )

            return c

    raise HTTPException(
        status_code=404,
        detail=f"case {case_id} not found",
    )


# ---------------------------------------------------------------------------
# Case detail
# ---------------------------------------------------------------------------

@app.get("/cases/{case_id}")
def case_detail(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    role = _require_role(x_investigator_role)

    case = _get_case(case_id, role)

    alert_ids = (
        set(case["alert_ids"].split(","))
        if case["alert_ids"]
        else set()
    )

    alerts = [
        a
        for a in _read_csv("suspected_alerts.csv")
        if a["alert_id"] in alert_ids
    ]

    return {
        "case": case,
        "alerts": alerts,
    }


# ---------------------------------------------------------------------------
# Case network
# ---------------------------------------------------------------------------

@app.get("/cases/{case_id}/network")
def case_network(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """On-demand network for the selected case.

    Returns Cytoscape.js elements generated by the NetworkX network layer.
    """
    role = _require_role(x_investigator_role)

    case = _get_case(case_id, role)

    return build_case_network(
        app.state.data,
        case["account_id"],
    )


# ---------------------------------------------------------------------------
# Checkpoint 3 / 4
# Evidence builder + PII sanitizer + Gemini hypothesis agents
# ---------------------------------------------------------------------------

def _case_with_alerts(case_id: str, role: str):
    """Return the authorized case and its associated suspected alerts."""
    case = _get_case(case_id, role)

    alert_ids = (
        set(case["alert_ids"].split(","))
        if case["alert_ids"]
        else set()
    )

    alerts = [
        a
        for a in _read_csv("suspected_alerts.csv")
        if a["alert_id"] in alert_ids
    ]

    return case, alerts


@app.post("/cases/{case_id}/investigate")
def start_investigation(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Start Investigation (Checkpoints 3+4).

    Flow:
      1. Load the authorized case.
      2. Build evidence.
      3. Mask PII.
      4. Persist the sanitized evidence.
      5. Send only the sanitized package to the Gemini hypothesis agents.
      6. Persist the masked agent responses.
      7. Record the investigation event.

    The Gemini model never receives the backend alias map.
    """
    role = _require_role(x_investigator_role)

    case, alerts = _case_with_alerts(
        case_id,
        role,
    )

    builder = EvidenceBuilder(
        app.state.data,
        os.path.join(MOCKDATA_DIR, "evidence"),
    )

    raw = builder.build(
        case,
        alerts,
    )

    sanitizer = PIISanitizer()

    safe = sanitizer.mask_package(
        raw,
        role,
    )

    builder.save(safe)

    # Gemini replacement for the previous Grok client.
    #
    # GeminiClient internally uses the configured Gemini model,
    # expected to be gemini-3.6-flash.
    agents_out = run_agents(
        safe,
        GeminiClient(),
    )

    _save_json(
        agents_out,
        _evidence_path(case_id, "_agents"),
    )

    record_event(
        MOCKDATA_DIR,
        case_id,
        role,
        "HYPOTHESIS_AGENTS_RUN",
        f"verdict={agents_out['contradiction'].get('verdict')}",
    )

    return {
        "llm_safe_evidence": safe,
        "agents": agents_out,
    }


# ---------------------------------------------------------------------------
# Stored evidence
# ---------------------------------------------------------------------------

@app.get("/cases/{case_id}/evidence")
def get_evidence(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Fetch the stored, already-sanitized evidence package."""
    role = _require_role(x_investigator_role)

    # Authorization check.
    _get_case(case_id, role)

    path = os.path.join(
        MOCKDATA_DIR,
        "evidence",
        f"{case_id}.json",
    )

    if not os.path.exists(path):
        raise HTTPException(
            status_code=404,
            detail=(
                "no evidence package yet - "
                "POST /cases/{case_id}/investigate first"
            ),
        )

    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Checkpoints 5 + 6
# Regulatory + RAG + Auditor + Next-Best-Action
# ---------------------------------------------------------------------------

def _full_analysis(
    case: dict,
    evidence: dict,
    agents_out: dict,
    role: str,
) -> dict:
    """Run the full Checkpoint 5+6 analysis chain.

    Chain:
        Regulatory Engine
            -> Regulatory RAG
            -> Investigation Auditor
            -> Next-Best-Action
    """

    regulatory = regulatory_evaluate(
        evidence,
        agents_out,
    )

    rag_context = (
        f"{case['primary_trigger']} "
        f"{case['typologies']} "
        f"{regulatory['max_severity']} "
        + " ".join(
            finding["detail"]
            for finding in regulatory["findings"]
            if finding["applies"]
        )
        + " "
        + str(
            agents_out
            .get("contradiction", {})
            .get("verdict")
        )
    )

    analysis = {
        "case_id": case["case_id"],
        "role": role,
        "agents": agents_out,
        "regulatory": regulatory,
        "regulatory_rag": rag_retrieve(
            rag_context,
        ),
        "auditor": run_auditor(
            case,
            evidence,
            agents_out,
            regulatory,
        ),
    }

    analysis["next_best_action"] = next_best_action(
        agents_out,
        regulatory,
        analysis["auditor"],
    )

    return analysis


@app.post("/cases/{case_id}/analysis")
def run_analysis(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Full Checkpoint 5+6 chain for the dashboard.

    Runs:
      - Gemini hypothesis agents when required
      - deterministic regulatory engine
      - India regulatory RAG
      - investigation auditor
      - completeness scoring
      - routing
      - next-best-action

    Writes the resulting analysis to the evidence directory and records
    the operation in the audit trail.
    """
    role = _require_role(x_investigator_role)

    case, _ = _case_with_alerts(
        case_id,
        role,
    )

    ev_path = os.path.join(
        MOCKDATA_DIR,
        "evidence",
        f"{case_id}.json",
    )

    if not os.path.exists(ev_path):
        raise HTTPException(
            status_code=404,
            detail=(
                "no evidence package yet - "
                "POST /cases/{case_id}/investigate first"
            ),
        )

    evidence = _load_json(ev_path)

    agents_path = _evidence_path(
        case_id,
        "_agents",
    )

    agents_out = (
        _load_json(agents_path)
        if os.path.exists(agents_path)
        else None
    )

    if agents_out is None:
        # Gemini replacement for the previous Grok client.
        agents_out = run_agents(
            evidence,
            GeminiClient(),
        )

        _save_json(
            agents_out,
            agents_path,
        )

    analysis = _full_analysis(
        case,
        evidence,
        agents_out,
        role,
    )

    _save_json(
        analysis,
        _evidence_path(case_id, "_analysis"),
    )

    record_event(
        MOCKDATA_DIR,
        case_id,
        role,
        "ANALYSIS_RUN",
        (
            f"routing={analysis['auditor']['routing']} "
            f"score={analysis['auditor']['score']} "
            f"nba={analysis['next_best_action']['action']}"
        ),
    )

    return analysis


# ---------------------------------------------------------------------------
# Stored analysis
# ---------------------------------------------------------------------------

@app.get("/cases/{case_id}/analysis")
def get_analysis(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Return the stored dashboard analysis payload."""
    role = _require_role(x_investigator_role)

    _get_case(
        case_id,
        role,
    )

    path = _evidence_path(
        case_id,
        "_analysis",
    )

    if not os.path.exists(path):
        raise HTTPException(
            status_code=404,
            detail=(
                "no analysis yet - "
                "POST /cases/{case_id}/analysis first"
            ),
        )

    return _load_json(path)


# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

@app.get("/cases/{case_id}/audit-trail")
def audit_trail(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    role = _require_role(x_investigator_role)

    _get_case(
        case_id,
        role,
    )

    return {
        "case_id": case_id,
        "events": read_trail(
            MOCKDATA_DIR,
            case_id,
        ),
    }


# ---------------------------------------------------------------------------
# Escalation
# ---------------------------------------------------------------------------

ESCALATION_SCHEMA = [
    "escalation_id",
    "case_id",
    "escalation_reason",
    "completeness_score_at_escalation",
    "primary_trigger",
    "evidence_signals",
    "escalated_at",
    "escalated_by",
    "status",
]


@app.post("/cases/{case_id}/escalate")
def escalate_case(
    case_id: str,
    body: dict,
    x_investigator_role: str | None = Header(default=None),
):
    """Human-review action.

    Junior investigators can escalate a case to the Senior queue.
    """

    role = _require_role(x_investigator_role)

    if role != "JUNIOR":
        raise HTTPException(
            status_code=403,
            detail="only JUNIOR escalates",
        )

    case = _get_case(
        case_id,
        role,
    )

    reason = (
        body.get("reason")
        or "escalated by investigator"
    )

    path = os.path.join(
        MOCKDATA_DIR,
        "case_escalation.csv",
    )

    if not os.path.exists(path):
        with open(
            path,
            "w",
            newline="",
            encoding="utf-8",
        ) as f:
            csv.DictWriter(
                f,
                fieldnames=ESCALATION_SCHEMA,
            ).writeheader()

    analysis_path = _evidence_path(
        case_id,
        "_analysis",
    )

    score = (
        _load_json(analysis_path)["auditor"]["score"]
        if os.path.exists(analysis_path)
        else ""
    )

    eid = (
        "ESC-"
        + "".join(
            random.Random().choice(
                string.ascii_uppercase + string.digits
            )
            for _ in range(7)
        )
    )

    with open(
        path,
        "a",
        newline="",
        encoding="utf-8",
    ) as f:
        csv.DictWriter(
            f,
            fieldnames=ESCALATION_SCHEMA,
        ).writerow(
            {
                "escalation_id": eid,
                "case_id": case_id,
                "escalation_reason": reason,
                "completeness_score_at_escalation": score,
                "primary_trigger": case["primary_trigger"],
                "evidence_signals": case["evidence_signals"],
                "escalated_at": (
                    datetime.now()
                    .replace(microsecond=0)
                    .strftime("%Y-%m-%d %H:%M:%S")
                ),
                "escalated_by": "JUNIOR",
                "status": "OPEN",
            }
        )

    _update_case_status(
        case_id,
        "SENIOR",
    )

    record_event(
        MOCKDATA_DIR,
        case_id,
        "JUNIOR",
        "ESCALATED_TO_SENIOR",
        reason,
    )

    return {
        "escalation_id": eid,
        "case_id": case_id,
        "status": "SENIOR",
    }


def _update_case_status(
    case_id: str,
    new_status: str,
):
    """Update the status of a case in cases.csv."""
    path = os.path.join(
        MOCKDATA_DIR,
        "cases.csv",
    )

    rows = _read_csv("cases.csv")

    for r in rows:
        if r["case_id"] == case_id:
            r["status"] = new_status

    if not rows:
        return

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(rows[0].keys()),
        )

        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# Checkpoint 7
# SAR report + audit-ready case
# ---------------------------------------------------------------------------

def _build_sar_dossier(
    case: dict,
    evidence: dict,
    analysis: dict,
    trail: list,
) -> dict:
    """Build the backend dossier consumed by reports.sar.generate().

    This keeps the SAR report boundary independent from the FastAPI route
    while preserving the existing case/evidence/analysis/audit information.
    """

    return {
        "case_id": case.get(
            "case_id",
            "",
        ),
        "account_id": case.get(
            "account_id",
            "UNKNOWN",
        ),
        "typology": case.get(
            "primary_trigger",
            case.get(
                "typologies",
                "Not classified",
            ),
        ),
        "primary_trigger": case.get(
            "primary_trigger",
            "",
        ),
        "typologies": case.get(
            "typologies",
            "",
        ),
        "status": case.get(
            "status",
            "",
        ),
        "case": case,
        "evidence": evidence,
        "network": evidence.get(
            "network",
            {},
        ),
        "hypotheses": analysis.get(
            "agents",
            {},
        ),
        "regulatory": analysis.get(
            "regulatory",
            {},
        ),
        "regulatory_rag": analysis.get(
            "regulatory_rag",
            {},
        ),
        "auditor": analysis.get(
            "auditor",
            {},
        ),
        "next_best_action": analysis.get(
            "next_best_action",
            {},
        ),
        "audit_trail": trail,
        "disposition": analysis.get(
            "next_best_action",
            {},
        ).get(
            "action",
            "Not available",
        ),
    }


@app.post("/cases/{case_id}/sar-report")
def sar_report(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Generate the audit-ready SAR report.

    Flow:
      masked dossier
          -> Gemini SAR generation
          -> backend-side alias restoration where supported
          -> decorative PDF
          -> password protection

    The API returns only the protected PDF.
    It does not return:
      - the alias mapping
      - an unprotected demasked narrative
      - the backend PII map

    Both JUNIOR and SENIOR can generate the SAR report for a finalized
    SAR_READY case.
    """

    role = _require_role(
        x_investigator_role,
    )

    case = next(
        (
            c
            for c in _read_csv("cases.csv")
            if c["case_id"] == case_id
        ),
        None,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail=f"case {case_id} not found",
        )

    # Both JUNIOR and SENIOR can generate the SAR report for a finalized
    # case. Active cases retain normal queue visibility rules.
    if case["status"] != "SAR_READY":
        _get_case(
            case_id,
            role,
        )

    ev_path = _evidence_path(
        case_id,
        "",
    )

    an_path = _evidence_path(
        case_id,
        "_analysis",
    )

    if (
        not os.path.exists(ev_path)
        or not os.path.exists(an_path)
    ):
        raise HTTPException(
            status_code=404,
            detail=(
                "no analysis yet - run "
                "POST /cases/{case_id}/investigate then "
                "POST /cases/{case_id}/analysis first"
            ),
        )

    evidence = _load_json(
        ev_path,
    )

    analysis = _load_json(
        an_path,
    )

    # Backend-only alias map.
    #
    # This map is never passed to Gemini and is never returned by this API.
    al_path = os.path.join(
        MOCKDATA_DIR,
        "evidence",
        f"{case_id}_aliases.json",
    )

    alias_map = load_aliases(
        al_path,
    )

    if not alias_map:
        alerts = [
            a
            for a in _read_csv("suspected_alerts.csv")
            if a["alert_id"]
            in (
                set(case["alert_ids"].split(","))
                if case["alert_ids"]
                else set()
            )
        ]

        sanitizer = PIISanitizer()

        sanitizer.mask_package(
            EvidenceBuilder(
                app.state.data,
                os.path.join(
                    MOCKDATA_DIR,
                    "evidence",
                ),
            ).build(
                case,
                alerts,
            ),
            role,
        )

        alias_map = sanitizer.alias_map()

        sanitizer.save_aliases(
            al_path,
        )

    trail = read_trail(
        MOCKDATA_DIR,
        case_id,
    )

    dossier = _build_sar_dossier(
        case,
        evidence,
        analysis,
        trail,
    )

    # Gemini-powered SAR generation.
    #
    # The SAR module receives the dossier and GeminiClient. The alias map
    # remains backend-only and is not supplied to the LLM.
    result = generate_sar(
        dossier,
        output_dir=os.path.join(
            MOCKDATA_DIR,
            "reports",
        ),
        client=GeminiClient(),
    )

    # Support the current SAR generator's returned PDF path.
    report_path = result.get(
        "pdf_path",
        result.get(
            "report_path",
        ),
    )

    if not report_path:
        raise HTTPException(
            status_code=500,
            detail="SAR generator did not return a PDF path",
        )

    if not os.path.exists(report_path):
        raise HTTPException(
            status_code=500,
            detail="SAR PDF was not created",
        )

    record_event(
        MOCKDATA_DIR,
        case_id,
        role,
        "SAR_GENERATED",
        os.path.basename(report_path),
    )

    return FileResponse(
        report_path,
        media_type="application/pdf",
        filename=f"SAR_{case_id}.pdf",
        headers={
            "X-SAR-Password-Hint": (
                "account holder's account id - last four "
                "characters"
            )
        },
    )


# ---------------------------------------------------------------------------
# Checkpoint 7
# Case memory / reference cases
# ---------------------------------------------------------------------------

@app.post("/cases/{case_id}/reference")
def add_reference(
    case_id: str,
    body: dict | None = None,
    x_investigator_role: str | None = Header(default=None),
):
    """Investigator explicitly retains a case as reference/case memory.

    This operation is never automatic.
    """

    role = _require_role(
        x_investigator_role,
    )

    case = next(
        (
            c
            for c in _read_csv("cases.csv")
            if c["case_id"] == case_id
        ),
        None,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail=f"case {case_id} not found",
        )

    # Finalized SAR_READY cases may be retained as reference by any
    # authenticated investigator. Active cases keep queue visibility rules.
    if case["status"] != "SAR_READY":
        _get_case(
            case_id,
            role,
        )

    an_path = _evidence_path(
        case_id,
        "_analysis",
    )

    analysis = (
        _load_json(an_path)
        if os.path.exists(an_path)
        else None
    )

    if analysis:
        evidence_path = _evidence_path(
            case_id,
            "",
        )

        if os.path.exists(evidence_path):
            analysis["evidence_network"] = _load_json(
                evidence_path,
            ).get(
                "network",
                {},
            ).get(
                "stats",
            )

    result = save_reference(
        MOCKDATA_DIR,
        case,
        analysis,
        (body or {}).get(
            "notes",
            "",
        ),
        role,
    )

    if result.get("stored"):
        record_event(
            MOCKDATA_DIR,
            case_id,
            role,
            "REFERENCE_SAVED",
            result["reference_id"],
        )

    return {
        "case_id": case_id,
        **result,
    }


@app.get("/reference-cases")
def list_reference_cases(
    x_investigator_role: str | None = Header(default=None),
):
    role = _require_role(
        x_investigator_role,
    )

    refs = read_references(
        MOCKDATA_DIR,
    )

    return {
        "role": role,
        "count": len(refs),
        "reference_cases": refs,
    }


# ---------------------------------------------------------------------------
# Authorized PII reveal for the three agent responses
# ---------------------------------------------------------------------------

def _resolve_text(
    text: str,
    alias_map: dict,
) -> str:
    """Resolve backend aliases inside text.

    Only aliases present in the backend alias map are replaced.
    Unknown text is preserved exactly.

    This is deterministic and does not call Gemini.
    """

    if not isinstance(text, str):
        return text

    # Replace longer aliases first so that a shorter alias cannot interfere
    # with a longer/more-specific alias.
    for alias, real_value in sorted(
        alias_map.items(),
        key=lambda item: len(str(item[0])),
        reverse=True,
    ):
        text = text.replace(
            str(alias),
            str(real_value),
        )

    return text


def _resolve_presentation(
    obj,
    alias_map: dict,
):
    """Recursively restore authorized PII for presentation.

    This operates entirely on the stored LLM response structure.

    The original masked response remains stored unchanged.
    """

    if isinstance(obj, dict):
        return {
            key: _resolve_presentation(
                value,
                alias_map,
            )
            for key, value in obj.items()
        }

    if isinstance(obj, list):
        return [
            _resolve_presentation(
                value,
                alias_map,
            )
            for value in obj
        ]

    if isinstance(obj, str):
        return _resolve_text(
            obj,
            alias_map,
        )

    return obj


@app.post("/cases/{case_id}/agents/reveal")
def reveal_agent_pii(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Authorized PII view of the three stored agent responses.

    Security properties:
      - No LLM rerun.
      - Original masked LLM output is preserved unchanged.
      - Alias resolution happens only in the backend.
      - Alias mapping itself is never returned.
      - Every reveal is recorded in the audit trail.
    """

    role = _require_role(
        x_investigator_role,
    )

    _get_case(
        case_id,
        role,
    )

    agents_path = _evidence_path(
        case_id,
        "_agents",
    )

    if not os.path.exists(agents_path):
        raise HTTPException(
            status_code=404,
            detail=(
                "no agent responses yet - "
                "POST /cases/{case_id}/investigate first"
            ),
        )

    # Original masked LLM output.
    masked = _load_json(
        agents_path,
    )

    al_path = os.path.join(
        MOCKDATA_DIR,
        "evidence",
        f"{case_id}_aliases.json",
    )

    alias_map = load_aliases(
        al_path,
    )

    if not alias_map:
        # Deterministic backend-only fallback rebuild.
        case2, alerts = _case_with_alerts(
            case_id,
            role,
        )

        sanitizer = PIISanitizer()

        sanitizer.mask_package(
            EvidenceBuilder(
                app.state.data,
                os.path.join(
                    MOCKDATA_DIR,
                    "evidence",
                ),
            ).build(
                case2,
                alerts,
            ),
            role,
        )

        alias_map = sanitizer.alias_map()

        sanitizer.save_aliases(
            al_path,
        )

    record_event(
        MOCKDATA_DIR,
        case_id,
        role,
        "PII_REVEAL",
        (
            "authorized reveal of three agent responses "
            "(aliases resolved backend-side; no LLM call)"
        ),
    )

    return {
        "case_id": case_id,
        "view": "authorized_pii",
        "agents": _resolve_presentation(
            masked,
            alias_map,
        ),
        "masked_view_available": True,
    }