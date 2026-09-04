"""Audit trail (Checkpoint 6): append-only CSV of investigation events."""
from __future__ import annotations

import csv
import os
import random
import string
from datetime import datetime

SCHEMA = ["event_id", "case_id", "timestamp", "actor", "event_type", "details"]


def record(mockdata_dir: str, case_id: str, actor: str, event_type: str,
           details: str, run_at: datetime | None = None) -> str:
    rng = random.Random()
    body = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(7))
    row = {"event_id": f"EVT-{body}", "case_id": case_id,
           "timestamp": (run_at or datetime.now()).replace(microsecond=0)
           .strftime("%Y-%m-%d %H:%M:%S"),
           "actor": actor, "event_type": event_type, "details": details}
    path = os.path.join(mockdata_dir, "audit_trail.csv")
    exists = os.path.exists(path)
    with open(path, "a", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=SCHEMA, extrasaction="ignore")
        if not exists:
            w.writeheader()
        w.writerow(row)
    return row["event_id"]


def read(mockdata_dir: str, case_id: str) -> list[dict]:
    path = os.path.join(mockdata_dir, "audit_trail.csv")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8", newline="") as f:
        return [r for r in csv.DictReader(f) if r["case_id"] == case_id]
