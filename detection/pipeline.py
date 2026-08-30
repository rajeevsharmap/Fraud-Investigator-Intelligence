"""Detection pipeline entry point (Checkpoint 2).

Runs the rule-based Detection Agent over the mock banking data, bundles
alerts into cases and writes:

    mockdata/cases.csv                operational case queue (Detection output)
    mockdata/suspected_alerts.csv     alert detail (analysis support)

It never reads ground truth. Run standalone:

    python -m detection.pipeline [--mockdata ./mockdata]
"""
from __future__ import annotations

import argparse
import csv
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.loader import BankData
from detection.detector import DetectionAgent
from detection.case_intake import CaseIntake, CASE_SCHEMA, ALERT_SCHEMA


def run_pipeline(mockdata_dir: str = "./mockdata", run_at: datetime | None = None):
    run_at = run_at or datetime.now().replace(microsecond=0)
    data = BankData(mockdata_dir)
    agent = DetectionAgent(data, run_at)
    alerts = agent.run()
    cases = CaseIntake(run_at).bundle(alerts)

    def write(path, schema, rows):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=schema, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)

    write(os.path.join(mockdata_dir, "suspected_alerts.csv"), ALERT_SCHEMA, alerts)
    write(os.path.join(mockdata_dir, "cases.csv"), CASE_SCHEMA, cases)
    return alerts, cases


def main():
    ap = argparse.ArgumentParser(description="Run the detection pipeline")
    ap.add_argument("--mockdata", default="./mockdata")
    args = ap.parse_args()
    alerts, cases = run_pipeline(args.mockdata)
    print(f"alerts: {len(alerts)}  ->  cases: {len(cases)}")
    for c in cases:
        print(f"  {c['case_id']}  {c['account_id']}  trigger={c['primary_trigger']}  "
              f"signals={c['evidence_signals']}")
    print(f"written to {os.path.abspath(args.mockdata)}/cases.csv, suspected_alerts.csv")


if __name__ == "__main__":
    main()
