"""Next-Best-Action (Architecture.md section 28) - rule-based, MVP.

CLEAR    sufficient evidence of likely legitimate / false positive
MONITOR  suspiciousness remains, blocking not justified
ESCALATE insufficient evidence / restricted info / senior review needed
BLOCK    only when deterministic investigation/compliance rules justify
"""
from __future__ import annotations

def next_best_action(agents: dict, regulatory: dict, auditor: dict) -> dict:
    verdict = agents.get("contradiction", {}).get("verdict", "insufficient_evidence")
    conf = float(agents.get("contradiction", {}).get("confidence", 0))
    max_sev = regulatory.get("max_severity", "INFO")
    str_required = regulatory.get("str_required", False)
    routing = auditor.get("routing")
    score = auditor.get("score", 0)

    # deterministic policy ladder
    if routing == "MORE_EVIDENCE_REQUIRED" or auditor.get("escalation_to_senior"):
        action, why = "ESCALATE", (
            f"auditor routing {routing}; "
            "senior review / restricted information required"
        )
    elif verdict == "scammer" and str_required and max_sev == "CRITICAL" \
            and score >= auditor.get("threshold", 75):
        action, why = "BLOCK", ("scammer verdict supported, STR warranted "
                                "(PMLA), investigation complete")
    elif verdict == "legitimate" and not str_required and max_sev in ("INFO", "MEDIUM") \
            and routing == "COMPLETE":
        action, why = "CLEAR", ("legitimate verdict supported, no critical "
                                "regulatory finding, investigation complete")
    else:
        action, why = "MONITOR", (
            "residual risk remains without complete deterministic grounds "
            "for blocking or clearing"
        )

    return {"action": action, "reason": why,
            "inputs": {"verdict": verdict, "confidence": conf,
                       "max_severity": max_sev, "str_required": str_required,
                       "auditor_routing": routing, "completeness": score}}
