"""Rule-based Investigation Auditor + Case Completeness Score
(Architecture.md sections 25-27).

Completeness (0-100) measures INVESTIGATION completeness, not fraud
probability. Auditor routing decides: COMPLETE / MORE_EVIDENCE_REQUIRED /
ESCALATION_REQUIRED.
"""
from __future__ import annotations

FLOW_TYPOLOGIES = {"smurfing", "reverse_smurfing"}

CHECKS = [
    # (key, weight, description)
    ("evidence_package",   15, "evidence package built"),
    ("alerts_present",     10, "detection alerts attached to case"),
    ("transactions",       15, "transaction evidence in window"),
    ("network_for_flow",   15, "fund-flow network evidence for flow typologies"),
    ("security_for_swap",  15, "security timeline evidence for account_swap"),
    ("agents_output",      15, "three hypothesis agents produced output"),
    ("verdict",            5,  "contradiction verdict present"),
    ("regulatory_findings", 5, "regulatory rule engine executed"),
    ("beneficiary_evidence", 5, "beneficiary records reviewed"),
]
COMPLETE_THRESHOLD = 75


def audit(case: dict, evidence: dict, agents: dict, regulatory: dict) -> dict:
    flows = {t for t in (case.get("typologies") or "").split(",") if t}
    results, missing = [], []
    score = 0

    def add(key, ok, note=""):
        nonlocal score
        w = next(w for k, w, _ in CHECKS if k == key)
        results.append({"check": key, "passed": bool(ok),
                        "weight": w, "note": note})
        if ok:
            score += w
        else:
            missing.append(next(d for k, _, d in CHECKS if k == key))

    add("evidence_package", bool(evidence.get("account")))
    add("alerts_present", bool(evidence.get("alerts")))
    add("transactions", bool(evidence.get("transactions")))
    add("network_for_flow", not (flows & FLOW_TYPOLOGIES)
        or bool(evidence.get("network", {}).get("stats", {}).get("edge_count")),
        "network absent for fund-flow typology" if flows & FLOW_TYPOLOGIES
        and not evidence.get("network", {}).get("stats", {}).get("edge_count") else "")
    add("security_for_swap", "account_swap" not in flows
        or bool(evidence.get("security_timeline")))
    add("agents_output", bool(agents.get("scammer_hypothesis")
        and agents.get("legitimate_hypothesis")
        and agents.get("contradiction")))
    verdict = agents.get("contradiction", {}).get("verdict", "")
    add("verdict", verdict in ("scammer", "legitimate", "insufficient_evidence"))
    add("regulatory_findings", bool(regulatory.get("findings")))
    add("beneficiary_evidence", "beneficiaries" in evidence)

    score = min(100, score)
    if score < COMPLETE_THRESHOLD:
        routing = "MORE_EVIDENCE_REQUIRED"
    elif verdict == "insufficient_evidence" or (flows & FLOW_TYPOLOGIES
            and not evidence.get("network", {}).get("stats", {}).get("edge_count")):
        routing = "ESCALATION_REQUIRED"
    else:
        routing = "COMPLETE"

    restricted_needed = (
        evidence.get("role") == "JUNIOR"
        and (routing != "COMPLETE" or regulatory.get("str_required")))
    return {"score": score, "threshold": COMPLETE_THRESHOLD,
            "routing": routing, "checks": results, "missing": missing,
            "escalation_to_senior": restricted_needed,
            "str_required": regulatory.get("str_required", False)}
