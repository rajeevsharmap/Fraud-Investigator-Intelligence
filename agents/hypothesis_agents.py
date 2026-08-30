"""Three hypothesis agents (Architecture.md section 23, MVP).

Scammer / Legitimate / Contradiction agents receive ONLY the PII-sanitized
evidence package (hard sanitizer boundary, Checkpoint 3) and return
structured JSON. With GROK_API_KEY set, Grok produces the analysis; without
a key (or on API/JSON failure) a deterministic evidence-derived fallback is
used so the architecture stays testable. The fallback never invents
evidence - it only recombines fields already present in the package.
"""
from __future__ import annotations

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


def _score_total(alerts) -> float:
    return sum(float(a.get("score") or 0) for a in alerts)


def _security_signals(ev: dict) -> list[str]:
    sigs = []
    for d in ev.get("devices", []):
        if str(d.get("sim_change_detected", "")).lower() == "true":
            sigs.append("sim_change_detected")
        if d.get("is_trusted_device") is False:
            sigs.append("untrusted_device")
        if str(d.get("jailbroken_rooted", "")).lower() == "true":
            sigs.append("jailbroken_device")
    for g in ev.get("geo_events", []):
        if g.get("is_vpn_or_proxy") is True:
            sigs.append("vpn_or_proxy")
        if g.get("registered_country_match") is False:
            sigs.append("registered_country_mismatch")
        if float(g.get("distance_from_last_location_km") or 0) > 500:
            sigs.append("large_geo_jump")
    return sorted(set(sigs))


def _fundflow_signals(ev: dict) -> list[str]:
    return sorted({a["typology"] for a in ev.get("alerts", [])})


def _evidence_digest(ev: dict) -> str:
    """Compact, sanitized summary embedded into the Grok prompt."""
    import json
    return json.dumps({
        "case": ev.get("case"), "account": ev.get("account"),
        "alerts": ev.get("alerts"),
        "txn_count": len(ev.get("transactions", [])),
        "transactions": ev.get("transactions", [])[:40],
        "security_timeline": ev.get("security_timeline", [])[:20],
        "devices": ev.get("devices", []), "geo_events": ev.get("geo_events", [])[:20],
        "beneficiaries": ev.get("beneficiaries", [])[:15],
        "network": ev.get("network"),
    }, default=str)


class HypothesisAgents:
    def __init__(self, client: GrokClient | None = None):
        self.client = client or GrokClient()

    # ---------------- scammer ----------------
    def scammer(self, ev: dict) -> dict:
        if self.client.usable:
            try:
                return self.client.complete(TWO_HYP_SYSTEM,
                    "Argue the strongest SUSPICIOUS/criminal interpretation. "
                    "Evidence:\n" + _evidence_digest(ev))
            except RuntimeError:
                pass
        return self._fallback_scammer(ev)

    # ---------------- legitimate ----------------
    def legitimate(self, ev: dict) -> dict:
        if self.client.usable:
            try:
                return self.client.complete(TWO_HYP_SYSTEM,
                    "Argue the strongest LEGITIMATE interpretation without "
                    "inventing facts. Evidence:\n" + _evidence_digest(ev))
            except RuntimeError:
                pass
        return self._fallback_legitimate(ev)

    # ---------------- contradiction ----------------
    def contradiction(self, ev: dict, scam: dict, leg: dict) -> dict:
        if self.client.usable:
            try:
                return self.client.complete(CONTRA_SYSTEM,
                    "Evidence:\n" + _evidence_digest(ev) +
                    "\nScammer hypothesis:\n" + str(scam) +
                    "\nLegitimate hypothesis:\n" + str(leg))
            except RuntimeError:
                pass
        return self._fallback_contradiction(ev, scam, leg)

    # ------------- deterministic fallbacks -------------
    def _fallback_scammer(self, ev: dict) -> dict:
        alerts = ev.get("alerts", [])
        total = _score_total(alerts)
        flow = _fundflow_signals(ev)
        sec = _security_signals(ev)
        points = [f"detection rule {a['rule_id']} ({a['rule_name']}, "
                  f"{a['typology']}, score {a['score']}) fired" for a in alerts]
        net = ev.get("network", {}).get("stats", {})
        if flow:
            points.append(f"fund-flow typology signals: {', '.join(flow)}")
        if net.get("edge_count"):
            points.append(f"network shows {net['edge_count']} fund-flow edges "
                          f"(depth {net.get('max_depth')})")
        if sec:
            points.append(f"security compromise signals: {', '.join(sec)}")
        conf = min(0.9, 0.3 + total / 200 + (0.1 if sec else 0)
                   + (0.1 if net.get("edge_count") else 0))
        return {"hypothesis": "suspicious" if points else "no suspicious signals",
                "typology_assessment": ", ".join(flow) or "none",
                "supporting_points": points, "contradicting_points": [],
                "confidence": round(conf, 2), "provider": "fallback"}

    def _fallback_legitimate(self, ev: dict) -> dict:
        acc = ev.get("account", {})
        points = []
        if str(acc.get("kyc_status", "")) not in ("PENDING", "FAILED", ""):
            points.append(f"kyc_status={acc.get('kyc_status')}")
        baseline = float(acc.get("avg_monthly_txn_amount") or 0)
        txns = ev.get("transactions", [])
        if txns and baseline:
            avg = sum(t["amount"] for t in txns) / len(txns)
            if avg <= 2 * baseline:
                points.append(f"avg txn amount {avg:.0f} within 2x of "
                              f"monthly baseline {baseline:.0f}")
        known = [b for b in ev.get("beneficiaries", [])
                 if b.get("is_first_time_beneficiary") is False
                 or str(b.get("is_first_time_beneficiary", "")).lower() == "false"]
        if known:
            points.append(f"{len(known)} established (non first-time) beneficiaries")
        trusted = [d for d in ev.get("devices", [])
                   if d.get("is_trusted_device") is True
                   or str(d.get("is_trusted_device", "")).lower() == "true"]
        if trusted:
            points.append("activity from trusted registered device(s)")
        sec = _security_signals(ev)
        if not sec:
            points.append("no security compromise signals in evidence")
        conf = 0.4 if not points else min(0.8, 0.35 + 0.1 * len(points))
        return {"hypothesis": "potentially legitimate" if points
                else "no legitimate signals either",
                "typology_assessment": "n/a",
                "supporting_points": points, "contradicting_points": [],
                "confidence": round(conf, 2), "provider": "fallback"}

    def _fallback_contradiction(self, ev: dict, scam: dict, leg: dict) -> dict:
        s, l = float(scam.get("confidence", 0)), float(leg.get("confidence", 0))
        alerts = ev.get("alerts", [])
        total = _score_total(alerts)
        missing = []
        if not ev.get("network", {}).get("stats", {}).get("edge_count"):
            missing.append("no fund-flow network edges in window")
        if not ev.get("security_timeline") and not _security_signals(ev):
            missing.append("no security timeline evidence")
        if not ev.get("beneficiaries"):
            missing.append("no beneficiary records for outbound transfers")
        if s - l >= 0.2 and total >= 30:
            verdict, conf = "scammer", min(0.9, s)
        elif l - s >= 0.2 and total < 40:
            verdict, conf = "legitimate", min(0.85, l)
        else:
            verdict, conf = "insufficient_evidence", max(s, l) * 0.8
        return {"verdict": verdict, "confidence": round(conf, 2),
                "supporting_evidence": scam.get("supporting_points", []),
                "contradictions": leg.get("supporting_points", []),
                "missing_evidence": missing,
                "remaining_uncertainty": "fallback analysis - not LLM reasoning",
                "provider": "fallback"}


def run_all(ev: dict, client: GrokClient | None = None) -> dict:
    ag = HypothesisAgents(client)
    scam = ag.scammer(ev)
    leg = ag.legitimate(ev)
    contra = ag.contradiction(ev, scam, leg)
    return {"scammer_hypothesis": scam, "legitimate_hypothesis": leg,
            "contradiction": contra}
