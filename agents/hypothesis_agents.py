"""Three hypothesis agents (Architecture.md section 23, MVP).

Scammer / Legitimate / Contradiction agents receive ONLY the PII-sanitized
evidence package (hard sanitizer boundary, Checkpoint 3) and return
structured JSON from the live LLM (Grok). There is no offline fallback: a
missing key or API failure raises and surfaces to the caller.
"""
from __future__ import annotations

import json

from agents.grok_client import GrokClient

SYSTEM_COMMON = (
    "You are an analyst on an Indian banking fraud investigation system. "
    "Use only facts contained in the evidence package. Never invent evidence. "
    "Distinguish fund-flow typologies (smurfing, reverse_smurfing) from "
    "account compromise (account_swap); a compromised account is not "
    "automatically a money mule."
)

TWO_HYP_SYSTEM = SYSTEM_COMMON + (
    " Output JSON: {\"hypothesis\": str, \"typology_assessment\": str, "
    "\"supporting_points\": [str], \"contradicting_points\": [str], "
    "\"confidence\": float}."
)

CONTRA_SYSTEM = SYSTEM_COMMON + (
    " Compare the scammer hypothesis with the legitimate hypothesis and "
    "decide which the evidence better supports. Output JSON: "
    "{\"verdict\": \"scammer|legitimate|insufficient_evidence\", "
    "\"confidence\": float, \"supporting_evidence\": [str], "
    "\"contradictions\": [str], \"missing_evidence\": [str], "
    "\"remaining_uncertainty\": str}."
)




def _evidence_digest(ev: dict) -> str:
    """Compact the sanitized evidence package for the LLM prompt."""
    slim = {
        "case": ev.get("case"),
        "account": ev.get("account"),
        "alerts": [{k: a.get(k) for k in ("rule_id", "rule_name", "typology",
                                          "score", "evidence")}
                   for a in ev.get("alerts", [])],
        "transactions": ev.get("transactions", [])[:20],
        "devices": ev.get("devices", []),
        "geo_events": ev.get("geo_events", [])[:10],
        "beneficiaries": ev.get("beneficiaries", [])[:10],
        "network": {"stats": ev.get("network", {}).get("stats"),
                    "edges": ev.get("network", {}).get("edges", [])[:10]},
        "security_timeline": ev.get("security_timeline", [])[:10],
    }
    return json.dumps(slim, default=str)[:6000]


class HypothesisAgents:
    def __init__(self, client: GrokClient | None = None):
        self.client = client or GrokClient()

    # ---------------- scammer ----------------
    def scammer(self, ev: dict) -> dict:
        return self.client.complete(TWO_HYP_SYSTEM,
            "Argue the strongest SUSPICIOUS/criminal interpretation. "
            "Evidence:\n" + _evidence_digest(ev))

    # ---------------- legitimate ----------------
    def legitimate(self, ev: dict) -> dict:
        return self.client.complete(TWO_HYP_SYSTEM,
            "Argue the strongest LEGITIMATE interpretation without "
            "inventing facts. Evidence:\n" + _evidence_digest(ev))

    # ---------------- contradiction ----------------
    def contradiction(self, ev: dict, scam: dict, leg: dict) -> dict:
        return self.client.complete(CONTRA_SYSTEM,
            "Evidence:\n" + _evidence_digest(ev) +
            "\nScammer hypothesis:\n" + str(scam) +
            "\nLegitimate hypothesis:\n" + str(leg))


def run_all(ev: dict, client: GrokClient | None = None) -> dict:
    ag = HypothesisAgents(client)
    scam = ag.scammer(ev)
    leg = ag.legitimate(ev)
    contra = ag.contradiction(ev, scam, leg)
    return {"scammer_hypothesis": scam, "legitimate_hypothesis": leg,
            "contradiction": contra}
