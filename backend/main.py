"""FastAPI service boundary for Tekmerion Intelligence.

Backend flow:

    Bank Data
        |
        v
    Detection Pipeline
        |
        v
    Cases / Alerts
        |
        v
    Evidence Builder
        |
        v
    PII Sanitizer
        |
        v
    Gemini Flash 3.6 Hypothesis Agents
        |
        v
    Regulatory Rules + RAG
        |
        v
    Investigation Auditor
        |
        v
    Next-Best-Action
        |
        v
    SAR / Case Memory / Audit Trail

Checkpoint 7 responsibilities preserved:
- Role-based access boundary
- Case queue visibility
- On-demand NetworkX/Cytoscape network
- Evidence generation
- LLM-safe PII masking
- Gemini hypothesis analysis
- Regulatory evaluation
- Regulatory RAG
- Investigation auditor
- Next-best-action
- Audit trail
- Junior -> Senior escalation
- SAR generation
- Password-protected SAR PDF
- Reference/case memory
- Authorized PII reveal
- No alias map returned to clients
- No LLM rerun during PII reveal

The frontend API contract is intentionally unchanged.
"""

from __future__ import annotations

import asyncio
import csv
import json
import os
import random
import string
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import FileResponse

from agents.gemini_client import GeminiClient
from agents.hypothesis_agents import HypothesisAgents

from audit.auditor import audit as run_auditor
from audit.next_best_action import next_best_action
from audit.trail import read as read_trail
from audit.trail import record as record_event

from detection.loader import BankData
from detection.network_layer import build_case_network
from detection.pipeline import run_pipeline

from evidence.builder import EvidenceBuilder
from evidence.sanitizer import PIISanitizer, load_aliases

from regulatory.rag import retrieve as rag_retrieve
from regulatory.rules_engine import evaluate as regulatory_evaluate

from reports.case_memory import (
    read_all as read_references,
    save as save_reference,
)
from reports.sar import generate as generate_sar


# ============================================================================
# Configuration
# ============================================================================

MOCKDATA_DIR = os.environ.get(
    "MOCKDATA_DIR",
    "./mockdata",
)

VALID_ROLES = (
    "JUNIOR",
    "SENIOR",
)


# ============================================================================
# Gemini client
# ============================================================================

def _gemini_client() -> GeminiClient:
    """Return the shared Gemini Flash 3.6 client.

    The actual model selection is controlled by GeminiClient / GEMINI_MODEL.
    Expected configuration:

        GEMINI_API_KEY=...
        GEMINI_MODEL=gemini-3.6-flash
    """

    return GeminiClient()


# ============================================================================
# CSV helpers
# ============================================================================

def _read_csv(name: str) -> list[dict[str, str]]:
    """Read a CSV from MOCKDATA_DIR.

    Missing files return an empty list rather than crashing the API.
    """

    path = os.path.join(
        MOCKDATA_DIR,
        name,
    )

    if not os.path.exists(path):
        return []

    with open(
        path,
        encoding="utf-8",
        newline="",
    ) as f:
        return list(csv.DictReader(f))


def _write_csv(
    name: str,
    rows: list[dict[str, Any]],
) -> None:
    """Write CSV rows while preserving their existing columns."""

    path = os.path.join(
        MOCKDATA_DIR,
        name,
    )

    if not rows:
        return

    os.makedirs(
        os.path.dirname(path) or ".",
        exist_ok=True,
    )

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


# ============================================================================
# Authorization
# ============================================================================

def _require_role(
    role: str | None,
) -> str:
    """Validate the lightweight MVP investigator role header."""

    normalized = (
        role or ""
    ).strip().upper()

    if normalized not in VALID_ROLES:
        raise HTTPException(
            status_code=401,
            detail=(
                "missing/invalid X-Investigator-Role header "
                "(JUNIOR or SENIOR)"
            ),
        )

    return normalized


# ============================================================================
# Application lifecycle
# ============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize the detection data layer when the API starts."""

    run_pipeline(MOCKDATA_DIR)

    app.state.data = BankData(
        MOCKDATA_DIR,
    )

    yield


app = FastAPI(
    title="Tekmerion Intelligence - Detection API",
    lifespan=lifespan,
)


# ============================================================================
# Health
# ============================================================================

@app.get("/health")
def health():
    return {
        "status": "ok",
        "mockdata": os.path.abspath(MOCKDATA_DIR),
    }


# ============================================================================
# Detection
# ============================================================================

@app.post("/detection/run")
def detection_run():
    """Explicit backend trigger for the detection pipeline."""

    alerts, cases = run_pipeline(
        MOCKDATA_DIR,
    )

    app.state.data = BankData(
        MOCKDATA_DIR,
    )

    return {
        "alerts": len(alerts),
        "cases": len(cases),
    }


# ============================================================================
# Case access
# ============================================================================

@app.get("/cases")
def list_cases(
    x_investigator_role: str | None = Header(default=None),
):
    role = _require_role(
        x_investigator_role,
    )

    cases = _read_csv(
        "cases.csv",
    )

    if role == "JUNIOR":
        # New cases enter the Junior queue.
        cases = [
            case
            for case in cases
            if case.get("status") == "JUNIOR"
        ]

    return {
        "role": role,
        "count": len(cases),
        "cases": cases,
    }


def _get_case(
    case_id: str,
    role: str,
) -> dict[str, str]:
    """Get a case after applying role-based queue visibility."""

    for case in _read_csv("cases.csv"):
        if case.get("case_id") != case_id:
            continue

        status = case.get(
            "status",
            "",
        )

        # Junior investigators can view:
        # - their active Junior queue
        # - finalized SAR_READY cases they worked
        if role == "JUNIOR":
            if status not in (
                "JUNIOR",
                "SAR_READY",
            ):
                raise HTTPException(
                    status_code=403,
                    detail="case not authorized for JUNIOR role",
                )

        return case

    raise HTTPException(
        status_code=404,
        detail=f"case {case_id} not found",
    )


def _case_with_alerts(
    case_id: str,
    role: str,
):
    """Return a case and all alerts bundled into it."""

    case = _get_case(
        case_id,
        role,
    )

    alert_ids = (
        set(
            case.get(
                "alert_ids",
                "",
            ).split(",")
        )
        if case.get("alert_ids")
        else set()
    )

    alerts = [
        alert
        for alert in _read_csv("suspected_alerts.csv")
        if alert.get("alert_id") in alert_ids
    ]

    return case, alerts


@app.get("/cases/{case_id}")
def case_detail(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    role = _require_role(
        x_investigator_role,
    )

    case, alerts = _case_with_alerts(
        case_id,
        role,
    )

    return {
        "case": case,
        "alerts": alerts,
    }


# ============================================================================
# Network
# ============================================================================

@app.get("/cases/{case_id}/network")
def case_network(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Build the selected case's network on demand.

    Returns the existing Cytoscape.js-compatible network structure.
    """

    role = _require_role(
        x_investigator_role,
    )

    case = _get_case(
        case_id,
        role,
    )

    return build_case_network(
        app.state.data,
        case["account_id"],
    )


# ============================================================================
# Evidence helpers
# ============================================================================

def _evidence_path(
    case_id: str,
    suffix: str,
) -> str:
    return os.path.join(
        MOCKDATA_DIR,
        "evidence",
        f"{case_id}{suffix}.json",
    )


def _save_json(
    obj: Any,
    path: str,
) -> None:
    os.makedirs(
        os.path.dirname(path),
        exist_ok=True,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            obj,
            f,
            indent=1,
            default=str,
        )


def _load_json(
    path: str,
) -> dict:
    with open(
        path,
        encoding="utf-8",
    ) as f:
        return json.load(f)


# ============================================================================
# Checkpoints 3 + 4
# Evidence builder + PII sanitizer + Gemini hypothesis agents
# ============================================================================

@app.post("/cases/{case_id}/investigate")
async def start_investigation(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Build sanitized evidence and run the two initial hypotheses in parallel.

    Workflow boundary:
        EvidenceBuilder -> PII Sanitizer -> {Scammer, Legitimate} (parallel)

    The contradiction agent is deliberately NOT executed here. It is gated
    behind ``POST /cases/{case_id}/resolve-contradiction`` so the investigator
    can review both independent hypotheses before resolving the contradiction.

    The JSON returned by each hypothesis agent is preserved exactly; this
    endpoint only wraps those two unchanged agent objects under ``agents``.
    """
    role = _require_role(x_investigator_role)

    case, alerts = _case_with_alerts(case_id, role)

    evidence_dir = os.path.join(MOCKDATA_DIR, "evidence")
    builder = EvidenceBuilder(app.state.data, evidence_dir)

    raw = builder.build(case, alerts)

    sanitizer = PIISanitizer()
    safe = sanitizer.mask_package(raw, role)

    builder.save(safe)

    alias_path = os.path.join(
        evidence_dir,
        f"{case_id}_aliases.json",
    )
    sanitizer.save_aliases(alias_path)

    # Run the independent hypothesis agents concurrently.  Separate client
    # instances keep the provider boundary isolated per worker while the
    # evidence package remains identical for both agents.
    async def _run_scammer():
        return await asyncio.to_thread(
            HypothesisAgents(client=GeminiClient()).scammer,
            safe,
        )

    async def _run_legitimate():
        return await asyncio.to_thread(
            HypothesisAgents(client=GeminiClient()).legitimate,
            safe,
        )

    scammer_result, legitimate_result = await asyncio.gather(
        _run_scammer(),
        _run_legitimate(),
    )

    agents_out = {
        "scammer": scammer_result,
        "legitimate": legitimate_result,
    }

    _save_json(
        agents_out,
        _evidence_path(case_id, "_agents"),
    )

    record_event(
        MOCKDATA_DIR,
        case_id,
        role,
        "HYPOTHESIS_AGENTS_RUN",
        "scammer and legitimate hypotheses completed in parallel",
    )

    return {
        "llm_safe_evidence": safe,
        "agents": agents_out,
    }


@app.post("/cases/{case_id}/resolve-contradiction")
async def resolve_contradiction(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Run the contradiction agent after both independent hypotheses exist.

    The contradiction agent receives:
      - the unchanged scammer hypothesis JSON,
      - the unchanged legitimate hypothesis JSON,
      - the sanitized evidence-builder package.

    Its existing JSON contract is returned unchanged under ``agents``.
    """
    role = _require_role(x_investigator_role)
    case, _ = _case_with_alerts(case_id, role)

    evidence_path = _evidence_path(case_id, "")
    agents_path = _evidence_path(case_id, "_agents")

    if not os.path.exists(evidence_path):
        raise HTTPException(
            status_code=404,
            detail=(
                "no evidence package yet - "
                "POST /cases/{case_id}/investigate first"
            ),
        )

    if not os.path.exists(agents_path):
        raise HTTPException(
            status_code=404,
            detail=(
                "hypothesis results not found - "
                "POST /cases/{case_id}/investigate first"
            ),
        )

    evidence = _load_json(evidence_path)
    initial_agents = _load_json(agents_path)

    scammer_result = initial_agents.get("scammer")
    legitimate_result = initial_agents.get("legitimate")

    # Read legacy key names only for compatibility with older persisted
    # analysis files; the response contract of the agents themselves is never
    # renamed or rewritten.
    if scammer_result is None:
        scammer_result = initial_agents.get("scammer_hypothesis")
    if legitimate_result is None:
        legitimate_result = initial_agents.get("legitimate_hypothesis")

    if not isinstance(scammer_result, dict) or not isinstance(
        legitimate_result, dict
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "both scammer and legitimate hypotheses are required "
                "before contradiction resolution"
            ),
        )

    contradiction = await asyncio.to_thread(
        HypothesisAgents(client=GeminiClient()).contradiction,
        scammer_result,
        legitimate_result,
        evidence,
    )

    agents_out = {
        "scammer": scammer_result,
        "legitimate": legitimate_result,
        "contradiction": contradiction,
    }

    _save_json(
        agents_out,
        agents_path,
    )

    record_event(
        MOCKDATA_DIR,
        case_id,
        role,
        "CONTRADICTION_AGENT_RUN",
        f"verdict={contradiction.get('verdict')}",
    )

    return {
        "case_id": case["case_id"],
        "agents": agents_out,
    }


@app.get("/cases/{case_id}/evidence")
def get_evidence(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Return the stored sanitized evidence package."""

    role = _require_role(
        x_investigator_role,
    )

    _get_case(
        case_id,
        role,
    )

    path = _evidence_path(
        case_id,
        "",
    )

    if not os.path.exists(path):
        raise HTTPException(
            status_code=404,
            detail=(
                "no evidence package yet - "
                "POST /cases/{case_id}/investigate first"
            ),
        )

    return _load_json(
        path,
    )


# ============================================================================
# Checkpoints 5 + 6
# Regulatory + RAG + Auditor + NBA
# ============================================================================

def _full_analysis(
    case: dict[str, str],
    evidence: dict,
    agents_out: dict,
    role: str,
) -> dict:
    """Run the deterministic analysis chain."""

    # ------------------------------------------------------------------------
    # 1. Regulatory rules engine
    # ------------------------------------------------------------------------

    regulatory = regulatory_evaluate(
        evidence,
        agents_out,
    )

    # ------------------------------------------------------------------------
    # 2. Regulatory RAG query
    # ------------------------------------------------------------------------

    finding_details = " ".join(
        str(finding.get("detail", ""))
        for finding in regulatory.get(
            "findings",
            [],
        )
        if finding.get("applies")
    )

    rag_context = (
        f"{case.get('primary_trigger', '')} "
        f"{case.get('typologies', '')} "
        f"{regulatory.get('max_severity', '')} "
        f"{finding_details} "
        f"{agents_out.get('contradiction', {}).get('verdict', '')}"
    )

    rag_result = rag_retrieve(
        rag_context,
    )

    # ------------------------------------------------------------------------
    # 3. Investigation Auditor
    # ------------------------------------------------------------------------

    auditor = run_auditor(
        case,
        evidence,
        agents_out,
        regulatory,
    )

    analysis = {
        "case_id": case["case_id"],
        "role": role,
        "agents": agents_out,
        "regulatory": regulatory,
        "regulatory_rag": rag_result,
        "auditor": auditor,
    }

    # Compact regulatory projection for the frontend.  The authoritative
    # regulatory engine response remains unchanged; this convenience field
    # exposes only rules that actually applied.
    analysis["broken_rules"] = [
        {
            "rule_id": finding.get("rule_id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "detail": finding.get("detail"),
            "citation": finding.get("citation"),
        }
        for finding in regulatory.get("findings", [])
        if finding.get("applies")
    ]

    # ------------------------------------------------------------------------
    # 4. Next Best Action
    # ------------------------------------------------------------------------

    analysis["next_best_action"] = next_best_action(
        agents_out,
        regulatory,
        auditor,
    )

    return analysis


@app.post("/cases/{case_id}/analysis")
def run_analysis(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Run the full Checkpoint 5 + 6 analysis chain."""

    role = _require_role(
        x_investigator_role,
    )

    case, _ = _case_with_alerts(
        case_id,
        role,
    )

    evidence_path = _evidence_path(
        case_id,
        "",
    )

    if not os.path.exists(evidence_path):
        raise HTTPException(
            status_code=404,
            detail=(
                "no evidence package yet - "
                "POST /cases/{case_id}/investigate first"
            ),
        )

    evidence = _load_json(
        evidence_path,
    )

    agents_path = _evidence_path(
        case_id,
        "_agents",
    )

    if not os.path.exists(agents_path):
        raise HTTPException(
            status_code=404,
            detail=(
                "hypothesis results not found - run "
                "POST /cases/{case_id}/investigate first"
            ),
        )

    agents_out = _load_json(agents_path)

    if not isinstance(agents_out.get("contradiction"), dict):
        raise HTTPException(
            status_code=409,
            detail=(
                "contradiction resolution is required before analysis - "
                "POST /cases/{case_id}/resolve-contradiction first"
            ),
        )

    analysis = _full_analysis(
        case,
        evidence,
        agents_out,
        role,
    )

    analysis_path = _evidence_path(
        case_id,
        "_analysis",
    )

    _save_json(
        analysis,
        analysis_path,
    )

    record_event(
        MOCKDATA_DIR,
        case_id,
        role,
        "ANALYSIS_RUN",
        (
            f"routing={analysis['auditor'].get('routing')} "
            f"score={analysis['auditor'].get('score')} "
            f"nba={analysis['next_best_action'].get('action')}"
        ),
    )

    return analysis


@app.get("/cases/{case_id}/analysis")
def get_analysis(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Return the stored dashboard analysis payload."""

    role = _require_role(
        x_investigator_role,
    )

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

    return _load_json(
        path,
    )


# ============================================================================
# Audit trail
# ============================================================================

@app.get("/cases/{case_id}/audit-trail")
def audit_trail(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    role = _require_role(
        x_investigator_role,
    )

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


# ============================================================================
# Escalation
# ============================================================================

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
    """Junior investigator escalates a case to Senior review."""

    role = _require_role(
        x_investigator_role,
    )

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

    escalation_path = os.path.join(
        MOCKDATA_DIR,
        "case_escalation.csv",
    )

    if not os.path.exists(escalation_path):
        with open(
            escalation_path,
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

    score = ""

    if os.path.exists(analysis_path):
        analysis = _load_json(
            analysis_path,
        )

        score = analysis.get(
            "auditor",
            {},
        ).get(
            "score",
            "",
        )

    # Use SystemRandom rather than constructing Random repeatedly.
    eid = (
        "ESC-"
        + "".join(
            random.SystemRandom().choice(
                string.ascii_uppercase + string.digits,
            )
            for _ in range(7)
        )
    )

    with open(
        escalation_path,
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
                "primary_trigger": case.get(
                    "primary_trigger",
                    "",
                ),
                "evidence_signals": case.get(
                    "evidence_signals",
                    "",
                ),
                "escalated_at": (
                    datetime.now()
                    .replace(microsecond=0)
                    .strftime("%Y-%m-%d %H:%M:%S")
                ),
                "escalated_by": role,
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
        role,
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
) -> None:
    """Update a case's queue status in cases.csv."""

    path = os.path.join(
        MOCKDATA_DIR,
        "cases.csv",
    )

    rows = _read_csv(
        "cases.csv",
    )

    if not rows:
        raise HTTPException(
            status_code=404,
            detail="cases.csv is empty or missing",
        )

    found = False

    for row in rows:
        if row.get("case_id") == case_id:
            row["status"] = new_status
            found = True

    if not found:
        raise HTTPException(
            status_code=404,
            detail=f"case {case_id} not found",
        )

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


# ============================================================================
# Checkpoint 7
# SAR REPORT
# ============================================================================


def _build_sar_dossier(
    case: dict,
    evidence: dict,
    analysis: dict,
    trail: list,
) -> dict:
    """Build a compact investigation summary for the SAR narrative agent.

    Raw transactions, network edges, security rows, and the full audit trail
    remain in their persisted backend records.  The SAR LLM receives only
    aggregate investigation facts plus the already-produced agent/regulatory
    conclusions, so the PDF summarizes the investigation instead of printing
    the evidence package verbatim.
    """
    transactions = evidence.get("transactions") or []
    network = evidence.get("network") or {}
    stats = network.get("stats") if isinstance(network, dict) else {}
    stats = stats if isinstance(stats, dict) else {}

    inbound = sum(
        float(t.get("amount") or 0)
        for t in transactions
        if t.get("direction") == "IN"
    )
    outbound = sum(
        float(t.get("amount") or 0)
        for t in transactions
        if t.get("direction") == "OUT"
    )

    alerts = evidence.get("alerts") or []
    alert_summary = {
        "count": len(alerts),
        "total_score": round(
            sum(float(a.get("score") or 0) for a in alerts), 2
        ),
        "typologies": sorted({
            str(a.get("typology"))
            for a in alerts
            if a.get("typology")
        }),
        "detection_rules": sorted({
            str(a.get("rule_id"))
            for a in alerts
            if a.get("rule_id")
        }),
    }

    account = evidence.get("account") or {}
    agents = analysis.get("agents") or {}
    regulatory = analysis.get("regulatory") or {}
    auditor = analysis.get("auditor") or {}
    nba = analysis.get("next_best_action") or {}

    applied_rules = [
        {
            "rule_id": finding.get("rule_id"),
            "title": finding.get("title"),
            "severity": finding.get("severity"),
            "detail": finding.get("detail"),
            "citation": finding.get("citation"),
        }
        for finding in regulatory.get("findings", [])
        if finding.get("applies")
    ]

    return {
        "case": {
            "case_id": case.get("case_id", ""),
            "primary_trigger": case.get("primary_trigger", ""),
            "typologies": case.get("typologies", ""),
            "status": case.get("status", ""),
            "created_at": case.get("created_at", ""),
        },
        "account": {
            "account_id": account.get(
                "account_id",
                case.get("account_id", "UNKNOWN"),
            ),
            "account_type": account.get("account_type"),
            "account_status": account.get("account_status"),
            "kyc_status": account.get("kyc_status"),
            "risk_rating": account.get("risk_rating"),
            "registered_country": account.get("registered_country"),
            "customer_segment": account.get("customer_segment"),
        },
        "alert_summary": alert_summary,
        "activity_summary": {
            "transaction_count": len(transactions),
            "inbound_total": round(inbound, 2),
            "outbound_total": round(outbound, 2),
            "net_flow": round(inbound - outbound, 2),
            "network_nodes": stats.get("nodes", 0),
            "network_edges": stats.get("edges", 0),
            "max_reached_depth": stats.get("max_reached_depth", 0),
            "device_count": len(evidence.get("devices") or []),
            "geo_event_count": len(evidence.get("geo_events") or []),
            "beneficiary_count": len(evidence.get("beneficiaries") or []),
        },
        # Preserve the actual hypothesis-agent JSON objects.  This is a
        # summary boundary for SAR only; the API response remains unchanged.
        "hypotheses": {
            "scammer": agents.get("scammer")
                or agents.get("scammer_hypothesis")
                or {},
            "legitimate": agents.get("legitimate")
                or agents.get("legitimate_hypothesis")
                or {},
            "contradiction": agents.get("contradiction") or {},
        },
        "regulatory": {
            "str_required": regulatory.get("str_required", False),
            "max_severity": regulatory.get("max_severity", "INFO"),
            "broken_rules": applied_rules,
        },
        "auditor": {
            "score": auditor.get("score"),
            "threshold": auditor.get("threshold"),
            "routing": auditor.get("routing"),
            "missing": auditor.get("missing", []),
            "escalation_to_senior": auditor.get(
                "escalation_to_senior",
                False,
            ),
        },
        "next_best_action": {
            "action": nba.get("action"),
            "reason": nba.get("reason"),
        },
        "audit_summary": {
            "event_count": len(trail or []),
            "event_types": sorted({
                str(event.get("event_type"))
                for event in (trail or [])
                if isinstance(event, dict) and event.get("event_type")
            }),
        },
    }


@app.post("/cases/{case_id}/sar-report")
def sar_report(
    case_id: str,
    x_investigator_role: str | None = Header(default=None),
):
    """Generate a password-protected SAR report.

    Flow:

        Stored sanitized evidence
                  +
        Stored analysis
                  +
        Audit trail
                  |
                  v
             SAR dossier
                  |
                  v
          Gemini Flash 3.6
                  |
                  v
          Decorative PDF
                  |
                  v
             PDF encryption
                  |
                  v
          Protected PDF response

    No alias map is returned to the API client.
    """

    role = _require_role(
        x_investigator_role,
    )

    case = next(
        (
            c
            for c in _read_csv("cases.csv")
            if c.get("case_id") == case_id
        ),
        None,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail=f"case {case_id} not found",
        )

    # Finalized SAR_READY cases can be accessed by either role.
    # Active cases retain normal queue visibility.
    if case.get("status") != "SAR_READY":
        _get_case(
            case_id,
            role,
        )

    evidence_path = _evidence_path(
        case_id,
        "",
    )

    analysis_path = _evidence_path(
        case_id,
        "_analysis",
    )

    if (
        not os.path.exists(evidence_path)
        or not os.path.exists(analysis_path)
    ):
        raise HTTPException(
            status_code=404,
            detail=(
                "no analysis yet - run POST "
                "/cases/{case_id}/investigate then POST "
                "/cases/{case_id}/analysis first"
            ),
        )

    # ------------------------------------------------------------------------
    # Backend-only alias map.
    #
    # IMPORTANT:
    # The alias map is deliberately NOT included in the Gemini dossier.
    # ------------------------------------------------------------------------

    alias_path = os.path.join(
        MOCKDATA_DIR,
        "evidence",
        f"{case_id}_aliases.json",
    )

    alias_map = load_aliases(
        alias_path,
    )

    # Rebuild the map only if the persisted map is unavailable.
    if not alias_map:
        alerts = [
            alert
            for alert in _read_csv("suspected_alerts.csv")
            if alert.get("alert_id")
            in (
                set(
                    case.get(
                        "alert_ids",
                        "",
                    ).split(",")
                )
                if case.get("alert_ids")
                else set()
            )
        ]

        sanitizer = PIISanitizer()

        raw = EvidenceBuilder(
            app.state.data,
            os.path.join(
                MOCKDATA_DIR,
                "evidence",
            ),
        ).build(
            case,
            alerts,
        )

        sanitizer.mask_package(
            raw,
            role,
        )

        alias_map = sanitizer.alias_map()

        sanitizer.save_aliases(
            alias_path,
        )

    # ------------------------------------------------------------------------
    # Construct the SAR dossier.
    #
    # The dossier contains:
    # - case metadata
    # - already sanitized evidence
    # - analysis
    # - audit trail
    #
    # It deliberately DOES NOT contain alias_map.
    # ------------------------------------------------------------------------

    evidence = _load_json(
        evidence_path,
    )

    analysis = _load_json(
        analysis_path,
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

    # ------------------------------------------------------------------------
    # Generate SAR through the new Gemini-compatible reports.sar API.
    # ------------------------------------------------------------------------

    result = generate_sar(
        dossier,
        output_dir=os.path.join(
            MOCKDATA_DIR,
            "reports",
        ),
        client=_gemini_client(),
    )

    # ------------------------------------------------------------------------
    # Persist audit event.
    #
    # Only the filename is written to the event; no PII or alias map.
    # ------------------------------------------------------------------------

    pdf_path = result.get(
        "pdf_path",
    )

    if not pdf_path:
        raise HTTPException(
            status_code=500,
            detail="SAR generation completed without a PDF path",
        )

    record_event(
        MOCKDATA_DIR,
        case_id,
        role,
        "SAR_GENERATED",
        os.path.basename(
            pdf_path,
        ),
    )

    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"SAR_{case_id}.pdf",
        headers={
            "X-SAR-Password-Hint": "Use the configured SAR password.",
        },
    )


# ============================================================================
# Checkpoint 7
# CASE MEMORY / REFERENCE CASES
# ============================================================================

@app.post("/cases/{case_id}/reference")
def add_reference(
    case_id: str,
    body: dict | None = None,
    x_investigator_role: str | None = Header(default=None),
):
    """Explicitly save a case as reference/case memory.

    This remains investigator-triggered and is never automatic.
    """

    role = _require_role(
        x_investigator_role,
    )

    case = next(
        (
            c
            for c in _read_csv("cases.csv")
            if c.get("case_id") == case_id
        ),
        None,
    )

    if case is None:
        raise HTTPException(
            status_code=404,
            detail=f"case {case_id} not found",
        )

    # Finalized cases can be retained by either authenticated role.
    if case.get("status") != "SAR_READY":
        _get_case(
            case_id,
            role,
        )

    analysis_path = _evidence_path(
        case_id,
        "_analysis",
    )

    analysis = (
        _load_json(analysis_path)
        if os.path.exists(analysis_path)
        else None
    )

    if analysis:
        evidence = _load_json(
            _evidence_path(
                case_id,
                "",
            )
        )

        analysis["evidence_network"] = (
            evidence
            .get("network", {})
            .get("stats")
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
            result.get(
                "reference_id",
                "",
            ),
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

    references = read_references(
        MOCKDATA_DIR,
    )

    return {
        "role": role,
        "count": len(references),
        "reference_cases": references,
    }


# ============================================================================
# Authorized PII reveal
# ============================================================================

def _resolve_text(
    text: str,
    alias_map: dict[str, str],
) -> str:
    """Resolve known aliases deterministically.

    This function performs no LLM call and does not expose the alias map.
    """

    if not isinstance(text, str):
        return text

    if not alias_map:
        return text

    resolved = text

    # Longest aliases first prevents partial alias collisions.
    for alias, real_value in sorted(
        alias_map.items(),
        key=lambda item: len(str(item[0])),
        reverse=True,
    ):
        if not alias:
            continue

        resolved = resolved.replace(
            str(alias),
            str(real_value),
        )

    return resolved


def _resolve_presentation(
    obj: Any,
    alias_map: dict[str, str],
):
    """Recursively restore aliases for an authorized presentation view."""

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
    """Authorized presentation-layer PII reveal.

    Critical properties:

    - Original Gemini response remains stored in masked form.
    - No Gemini request is made here.
    - Alias mapping remains backend-only.
    - Alias mapping itself is never returned.
    - Every reveal is written to the audit trail.
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

    # This is the original masked Gemini output.
    masked = _load_json(
        agents_path,
    )

    alias_path = os.path.join(
        MOCKDATA_DIR,
        "evidence",
        f"{case_id}_aliases.json",
    )

    alias_map = load_aliases(
        alias_path,
    )

    # Deterministic rebuild fallback.
    if not alias_map:
        case, alerts = _case_with_alerts(
            case_id,
            role,
        )

        sanitizer = PIISanitizer()

        raw = EvidenceBuilder(
            app.state.data,
            os.path.join(
                MOCKDATA_DIR,
                "evidence",
            ),
        ).build(
            case,
            alerts,
        )

        sanitizer.mask_package(
            raw,
            role,
        )

        alias_map = sanitizer.alias_map()

        sanitizer.save_aliases(
            alias_path,
        )

    # Audit before returning the authorized presentation.
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


# ============================================================================
# Public module exports
# ============================================================================

__all__ = [
    "app",
]