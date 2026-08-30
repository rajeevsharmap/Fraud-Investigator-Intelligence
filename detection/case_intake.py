"""Case Intake (Architecture.md sections 19-20).

Bundles suspected alerts belonging to the same account into a single case.
Every new case is assigned to the JUNIOR investigator queue.
"""
from __future__ import annotations

import random
import string
from collections import defaultdict
from datetime import datetime

CASE_SCHEMA = ["case_id", "account_id", "created_at", "primary_trigger",
               "alert_ids", "evidence_signals", "typologies", "status",
               "bundle_reason"]
ALERT_SCHEMA = ["alert_id", "account_id", "rule_id", "rule_name", "typology",
                "score", "detected_at", "window_start", "window_end", "evidence"]


def _case_id(rng):
    body = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(7))
    return f"CASE-{body}"


class CaseIntake:
    def __init__(self, run_at: datetime | None = None):
        self.run_at = run_at or datetime.now().replace(microsecond=0)
        self.rng = random.Random(31415926)

    def bundle(self, alerts):
        by_account = defaultdict(list)
        for a in alerts:
            by_account[a["account_id"]].append(a)

        cases = []
        for acc, acc_alerts in sorted(by_account.items()):
            typologies = sorted({a["typology"] for a in acc_alerts})
            total_score = sum(a["score"] for a in acc_alerts)
            scores = {t: sum(a["score"] for a in acc_alerts if a["typology"] == t)
                      for t in typologies}
            if len(typologies) > 1:
                trigger = max(scores, key=scores.get)
                reason = (f"bundled {len(acc_alerts)} alerts "
                          f"({', '.join(f'{t}:{scores[t]}' for t in typologies)}); "
                          f"primary by score")
            else:
                trigger = typologies[0]
                reason = f"bundled {len(acc_alerts)} {trigger} alerts on one account"
            cases.append({
                "case_id": _case_id(self.rng),
                "account_id": acc,
                "created_at": self.run_at.strftime("%Y-%m-%d %H:%M:%S"),
                "primary_trigger": trigger,
                "alert_ids": ",".join(a["alert_id"] for a in acc_alerts),
                "evidence_signals": ",".join(f"{a['rule_id']}" for a in acc_alerts),
                "typologies": ",".join(typologies),
                "status": "JUNIOR",            # initial ownership (section 20)
                "bundle_reason": f"{reason}; total_score={total_score}",
            })
        return cases
