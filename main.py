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
"""
from __future__ import annotations

import csv
import json
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException

from agents.grok_client import GrokClient
from agents.hypothesis_agents import run_all as run_agents
from audit.auditor import audit as run_auditor
from audit.next_best_action import next_best_action
from audit.trail import read as read_trail, record as record_event
from detection.loader import BankData
from detection.network_layer import build_case_network
from detection.pipeline import run_pipeline
from evidence.builder import EvidenceBuilder
from evidence.sanitizer import PIISanitizer
from regulatory.rag import retrieve as rag_retrieve
from regulatory.rules_engine import evaluate as regulatory_evaluate

MOCKDATA_DIR = os.environ.get("MOCKDATA_DIR", "./mockdata")
VALID_ROLES = ("JUNIOR", "SENIOR")


def _read_csv(name: str) -> list[dict]:
    path = os.path.join(MOCKDATA_DIR, name)
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _require_role(role: str | None) -> str:
    r = (role or "").strip().upper()
    if r not in VALID_ROLES:
        raise HTTPException(status_code=401,
                            detail="missing/invalid X-Investigator-Role header (JUNIOR or SENIOR)")
    return r


@asynccontextmanager
async def lifespan(app: FastAPI):
    # data-processing cycle start: run detection, then load data for on-demand networks
    run_pipeline(MOCKDATA_DIR)
    app.state.data = BankData(MOCKDATA_DIR)
    yield


app = FastAPI(title="Tekmerion Intelligence - Detection API", lifespan=lifespan)


@app.get("/health")
def health():
    return {"status": "ok", "mockdata": os.path.abspath(MOCKDATA_DIR)}


@app.post("/detection/run")
def detection_run():
    """Explicit backend trigger for the detection pipeline."""
    alerts, cases = run_pipeline(MOCKDATA_DIR)
    app.state.data = BankData(MOCKDATA_DIR)
    return {"alerts": len(alerts), "cases": len(cases)}


@app.get("/cases")
def list_cases(x_investigator_role: str | None = Header(default=None)):
    role = _require_role(x_investigator_role)
    cases = _read_csv("cases.csv")
    if role == "JUNIOR":
        # every new case lands in the Junior queue (Architecture.md s20)
        cases = [c for c in cases if c["status"] == "JUNIOR"]
    return {"role": role, "count": len(cases), "cases": cases}


def _get_case(case_id: str, role: str) -> dict:
    for c in _read_csv("cases.csv"):
        if c["case_id"] == case_id:
            if role == "JUNIOR" and c["status"] != "JUNIOR":
                raise HTTPException(status_code=403,
                                    detail="case not authorized for JUNIOR role")
            return c
    raise HTTPException(status_code=404, detail=f"case {case_id} not found")


@app.get("/cases/{case_id}")
def case_detail(case_id: str, x_investigator_role: str | None = Header(default=None)):
    role = _require_role(x_investigator_role)
    case = _get_case(case_id, role)
    alert_ids = set(case["alert_ids"].split(",")) if case["alert_ids"] else set()
    alerts = [a for a in _read_csv("suspected_alerts.csv") if a["alert_id"] in alert_ids]
    return {"case": case, "alerts": alerts}


@app.get("/cases/{case_id}/network")
def case_network(case_id: str, x_investigator_role: str | None = Header(default=None)):
    """On-demand network for the selected case (Cytoscape.js elements)."""
    role = _require_role(x_investigator_role)
    case = _get_case(case_id, role)
    return build_case_network(app.state.data, case["account_id"])


# ---------------- Checkpoint 3: evidence builder + PII sanitizer ----------------

def _case_with_alerts(case_id: str, role: str):
    case = _get_case(case_id, role)
    alert_ids = set(case["alert_ids"].split(",")) if case["alert_ids"] else set()
    alerts = [a for a in _read_csv("suspected_alerts.csv") if a["alert_id"] in alert_ids]
    return case, alerts


def _evidence_path(case_id: str, suffix: str) -> str:
    return os.path.join(MOCKDATA_DIR, "evidence", f"{case_id}{suffix}.json")


def _save_json(obj: dict, path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=1, default=str)


def _load_json(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@app.post("/cases/{case_id}/investigate")
def start_investigation(case_id: str, x_investigator_role: str | None = Header(default=None)):
    """Start Investigation (Checkpoints 3+4): bundle case evidence, mask PII,
    then run the three hypothesis agents on the LLM-safe package."""
    role = _require_role(x_investigator_role)
    case, alerts = _case_with_alerts(case_id, role)
    builder = EvidenceBuilder(app.state.data,
                              os.path.join(MOCKDATA_DIR, "evidence"))
    raw = builder.build(case, alerts)
    safe = PIISanitizer().mask_package(raw, role)
    builder.save(safe)
    agents_out = run_agents(safe, GrokClient())
    _save_json(agents_out, _evidence_path(case_id, "_agents"))
    record_event(MOCKDATA_DIR, case_id, role,
                 "HYPOTHESIS_AGENTS_RUN",
                 f"verdict={agents_out['contradiction'].get('verdict')}")
    return {"llm_safe_evidence": safe, "agents": agents_out}


@app.get("/cases/{case_id}/evidence")
def get_evidence(case_id: str, x_investigator_role: str | None = Header(default=None)):
    """Fetch the stored (already sanitized) evidence package for a case."""
    role = _require_role(x_investigator_role)
    _get_case(case_id, role)     # authorization check
    path = os.path.join(MOCKDATA_DIR, "evidence", f"{case_id}.json")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="no evidence package yet - "
                            "POST /cases/{case_id}/investigate first")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# ------------- Checkpoints 5+6: regulatory, auditor, NBA, audit trail -------------

def _full_analysis(case: dict, evidence: dict, agents_out: dict, role: str) -> dict:
    """Regulatory engine -> RAG -> Investigation Auditor -> Next-Best-Action."""
    regulatory = regulatory_evaluate(evidence, agents_out)
    rag_context = (f"{case['primary_trigger']} {case['typologies']} "
                   f"{regulatory['max_severity']} "
                   + " ".join(f['detail'] for f in regulatory['findings']
                              if f['applies'])
                   + " " + str(agents_out.get('contradiction', {}).get('verdict')))
    analysis = {
        "case_id": case["case_id"],
        "role": role,
        "agents": agents_out,
        "regulatory": regulatory,
        "regulatory_rag": rag_retrieve(rag_context),
        "auditor": run_auditor(case, evidence, agents_out, regulatory),
    }
    analysis["next_best_action"] = next_best_action(
        agents_out, regulatory, analysis["auditor"])
    return analysis


@app.post("/cases/{case_id}/analysis")
def run_analysis(case_id: str, x_investigator_role: str | None = Header(default=None)):
    """Full Checkpoint 5+6 chain for the dashboard. Runs the three agents on
    sanitized evidence, then the deterministic regulatory engine, India RAG,
    investigation auditor, completeness score, routing and next-best-action.
    Writes mockdata/audit_trail.csv events."""
    role = _require_role(x_investigator_role)
    case, _ = _case_with_alerts(case_id, role)
    ev_path = os.path.join(MOCKDATA_DIR, "evidence", f"{case_id}.json")
    if not os.path.exists(ev_path):
        raise HTTPException(status_code=404, detail="no evidence package yet - "
                            "POST /cases/{case_id}/investigate first")
    evidence = _load_json(ev_path)
    agents_out = _load_json(_evidence_path(case_id, "_agents")) \
        if os.path.exists(_evidence_path(case_id, "_agents")) else None
    if agents_out is None:
        agents_out = run_agents(evidence, GrokClient())
        _save_json(agents_out, _evidence_path(case_id, "_agents"))

    analysis = _full_analysis(case, evidence, agents_out, role)
    _save_json(analysis, _evidence_path(case_id, "_analysis"))
    record_event(MOCKDATA_DIR, case_id, role, "ANALYSIS_RUN",
                 f"routing={analysis['auditor']['routing']} "
                 f"score={analysis['auditor']['score']} "
                 f"nba={analysis['next_best_action']['action']}")
    return analysis


@app.get("/cases/{case_id}/analysis")
def get_analysis(case_id: str, x_investigator_role: str | None = Header(default=None)):
    """Stored dashboard payload for a case."""
    role = _require_role(x_investigator_role)
    _get_case(case_id, role)
    path = _evidence_path(case_id, "_analysis")
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="no analysis yet - "
                            "POST /cases/{case_id}/analysis first")
    return _load_json(path)


@app.get("/cases/{case_id}/audit-trail")
def audit_trail(case_id: str, x_investigator_role: str | None = Header(default=None)):
    role = _require_role(x_investigator_role)
    _get_case(case_id, role)
    return {"case_id": case_id, "events": read_trail(MOCKDATA_DIR, case_id)}


ESCALATION_SCHEMA = ["escalation_id", "case_id", "escalation_reason",
                     "completeness_score_at_escalation", "primary_trigger",
                     "evidence_signals", "escalated_at", "escalated_by",
                     "status"]


@app.post("/cases/{case_id}/escalate")
def escalate_case(case_id: str, body: dict,
                  x_investigator_role: str | None = Header(default=None)):
    """Human-review action (Checkpoints 6+30): Junior escalates to Senior.
    Appends a row to case_escalation.csv (starts empty, populated only on a
    real escalation event) and moves the case into the Senior queue."""
    role = _require_role(x_investigator_role)
    if role != "JUNIOR":
        raise HTTPException(status_code=403, detail="only JUNIOR escalates")
    case = _get_case(case_id, role)
    reason = body.get("reason") or "escalated by investigator"
    path = os.path.join(MOCKDATA_DIR, "case_escalation.csv")
    if not os.path.exists(path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=ESCALATION_SCHEMA).writeheader()
    analysis_path = _evidence_path(case_id, "_analysis")
    score = _load_json(analysis_path)["auditor"]["score"] \
        if os.path.exists(analysis_path) else ""
    import random, string
    eid = "ESC-" + "".join(random.Random().choice(string.ascii_uppercase + string.digits)
                           for _ in range(7))
    from datetime import datetime
    with open(path, "a", newline="", encoding="utf-8") as f:
        csv.DictWriter(f, fieldnames=ESCALATION_SCHEMA).writerow({
            "escalation_id": eid, "case_id": case_id,
            "escalation_reason": reason,
            "completeness_score_at_escalation": score,
            "primary_trigger": case["primary_trigger"],
            "evidence_signals": case["evidence_signals"],
            "escalated_at": datetime.now().replace(microsecond=0)
            .strftime("%Y-%m-%d %H:%M:%S"),
            "escalated_by": "JUNIOR", "status": "OPEN"})
    _update_case_status(case_id, "SENIOR")
    record_event(MOCKDATA_DIR, case_id, "JUNIOR", "ESCALATED_TO_SENIOR", reason)
    return {"escalation_id": eid, "case_id": case_id, "status": "SENIOR"}


def _update_case_status(case_id: str, new_status: str):
    path = os.path.join(MOCKDATA_DIR, "cases.csv")
    rows = _read_csv("cases.csv")
    for r in rows:
        if r["case_id"] == case_id:
            r["status"] = new_status
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)


# ---------------- Checkpoint 7: SAR report + audit-ready case ----------------

from reports.sar import generate as generate_sar   # noqa: E402


@app.post("/cases/{case_id}/sar-report")
def sar_report(case_id: str, x_investigator_role: str | None = Header(default=None)):
    """SAR Report button (JUNIOR or SENIOR). Summarizes the full investigation
    dossier - evidence, the three Grok agent responses, regulatory findings,
    RAG references, auditor result, next-best-action and audit trail - into a
    password-protected PDF, then moves the case to audit_ready_cases.csv."""
    role = _require_role(x_investigator_role)
    case = _get_case(case_id, role)

    ev_path = _evidence_path(case_id, "")
    an_path = _evidence_path(case_id, "_analysis")
    if not os.path.exists(ev_path) or not os.path.exists(an_path):
        raise HTTPException(status_code=404, detail="no analysis yet - run POST "
                            "/cases/{case_id}/investigate then POST "
                            "/cases/{case_id}/analysis first")
    trail = read_trail(MOCKDATA_DIR, case_id)
    result = generate_sar(case, _load_json(ev_path), _load_json(an_path), trail,
                          MOCKDATA_DIR)
    record_event(MOCKDATA_DIR, case_id, role, "SAR_GENERATED", result["report_path"])
    return {"case_id": case_id, "status": "SAR_READY", "generated_by": role,
            "report_path": result["report_path"], "password": result["password"],
            "alert": result["alert"], "narrative": result["narrative"]}


# ---------------- Checkpoint 7 (cont.): case memory / reference cases ----------------

from reports.case_memory import save as save_reference, read_all as read_references   # noqa: E402


@app.post("/cases/{case_id}/reference")
def add_reference(case_id: str, body: dict | None = None,
                  x_investigator_role: str | None = Header(default=None)):
    """Investigator explicitly retains a case as reference/case memory.
    Never automatic (Architecture.md s36)."""
    role = _require_role(x_investigator_role)
    case = next((c for c in _read_csv("cases.csv") if c["case_id"] == case_id), None)
    if case is None:
        raise HTTPException(status_code=404, detail=f"case {case_id} not found")
    # finalized (SAR_READY) cases may be retained as reference by any
    # authenticated investigator; active cases keep queue visibility rules
    if case["status"] != "SAR_READY":
        _get_case(case_id, role)
    an_path = _evidence_path(case_id, "_analysis")
    analysis = _load_json(an_path) if os.path.exists(an_path) else None
    if analysis:
        analysis["evidence_network"] = _load_json(
            _evidence_path(case_id, "")).get("network", {}).get("stats")
    result = save_reference(MOCKDATA_DIR, case, analysis,
                            (body or {}).get("notes", ""), role)
    if result.get("stored"):
        record_event(MOCKDATA_DIR, case_id, role, "REFERENCE_SAVED",
                     result["reference_id"])
    return {"case_id": case_id, **result}


@app.get("/reference-cases")
def list_reference_cases(x_investigator_role: str | None = Header(default=None)):
    role = _require_role(x_investigator_role)
    refs = read_references(MOCKDATA_DIR)
    return {"role": role, "count": len(refs), "reference_cases": refs}
