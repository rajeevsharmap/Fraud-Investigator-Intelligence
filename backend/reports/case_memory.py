"""Case memory (Architecture.md sections 36-37, Checkpoint 7).

reference_cases.csv stores cases the investigator EXPLICITLY chooses to
retain for future reference. It is never auto-populated and is a reference
artifact only - never silently a detection rule.
"""
from __future__ import annotations

import csv
import json
import os
from datetime import datetime

SCHEMA = ["reference_id", "case_id", "account_id", "primary_trigger",
          "typologies", "evidence_summary", "network_summary",
          "investigation_reasoning", "final_action", "outcome",
          "reference_notes", "stored_at", "stored_by"]


def _next_id(rows) -> str:
    return f"REF-{len(rows) + 1:04d}"


def save(mockdata_dir: str, case: dict, analysis: dict | None,
         notes: str, stored_by: str) -> dict:
    path = os.path.join(mockdata_dir, "reference_cases.csv")
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8", newline="") as f:
            rows = list(csv.DictReader(f))
    if any(r["case_id"] == case["case_id"] for r in rows):
        return {"stored": False, "reason": "case already in reference memory"}

    ev_summary = net_summary = reasoning = final_action = outcome = ""
    if analysis:
        aud, nba = analysis.get("auditor", {}), analysis.get("next_best_action", {})
        contra = analysis.get("agents", {}).get("contradiction", {})
        ev_summary = (f"completeness={aud.get('score')}, "
                      f"signals={case.get('evidence_signals', '')}")
        net_summary = json.dumps(analysis.get("evidence_network") or "", default=str)[:300]
        reasoning = (f"verdict={contra.get('verdict')}, "
                     f"confidence={contra.get('confidence')}")
        final_action = nba.get("action", "")
        outcome = nba.get("reason", "")[:200]

    row = {
        "reference_id": _next_id(rows), "case_id": case["case_id"],
        "account_id": case["account_id"],
        "primary_trigger": case["primary_trigger"],
        "typologies": case["typologies"], "evidence_summary": ev_summary,
        "network_summary": net_summary, "investigation_reasoning": reasoning,
        "final_action": final_action, "outcome": outcome,
        "reference_notes": notes[:300],
        "stored_at": datetime.now().replace(microsecond=0)
        .strftime("%Y-%m-%d %H:%M:%S"), "stored_by": stored_by,
    }
    new = not os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SCHEMA)
        if new:
            w.writeheader()
        w.writerow(row)
    return {"stored": True, "reference_id": row["reference_id"]}


def read_all(mockdata_dir: str) -> list[dict]:
    path = os.path.join(mockdata_dir, "reference_cases.csv")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))
