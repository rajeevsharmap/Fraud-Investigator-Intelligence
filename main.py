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
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Header, HTTPException

from detection.loader import BankData
from detection.network_layer import build_case_network
from detection.pipeline import run_pipeline

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
