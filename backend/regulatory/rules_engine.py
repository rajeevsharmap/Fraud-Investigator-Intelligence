"""Deterministic India-specific Regulatory Rule Engine (Architecture.md s25).

Evaluates the completed evidence + agent verdict against Indian regulatory
rules implemented for the MVP. LLM output can NEVER override these rules -
the engine is the authoritative compliance check.

Rules (MVP set, India):
  REG-PMLA-001  STR warranted       - PMLA 2002 s.13 + PMLA Maintenance of
                                      Records Rules 2015 r.3 (STR filing)
  REG-CTR-002   Cash threshold      - aggregate cash >= Rs 10,00,000 in the
                                      window (CTR, PMLA Records Rules r.3)
  REG-FEMA-003  Cross-border        - international txn review (FEMA 1999,
                                      RBI LRS Master Direction)
  REG-RBI-004   UPI cap breach      - single UPI txn > Rs 1,00,000
  REG-KYC-005   KYC deficiency      - KYC not completed (RBI KYC Master
                                      Direction 2016, as amended)
  REG-RBI-006   Rapid layering      - high onward transfer soon after inbound
                                      (RBI advisories on mule accounts)
  REG-ACCT-007  New-account velocity- - account < 90 days old with elevated
                                      activity (RBI new-account monitoring)
"""
from __future__ import annotations

from datetime import datetime, timedelta

UPI_SINGLE_CAP = 100_000.0
CTR_CASH_THRESHOLD = 10_00_000.0      # Rs 10 lakh
CASH_CHANNELS = {"ATM", "BRANCH"}

SEVERITY_ORDER = {"INFO": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def _findings_template() -> list[dict]:
    return [
        {"rule_id": "REG-PMLA-001", "title": "STR filing warranted",
         "citation": "PMLA 2002 s.13; PMLA Maintenance of Records Rules 2015 r.3",
         "applies": False, "severity": "INFO", "detail": ""},
        {"rule_id": "REG-CTR-002", "title": "Cash Transaction Report threshold",
         "citation": "PMLA Maintenance of Records Rules 2015 r.3 (CTR)",
         "applies": False, "severity": "INFO", "detail": ""},
        {"rule_id": "REG-FEMA-003", "title": "Cross-border / LRS review",
         "citation": "FEMA 1999; RBI LRS Master Direction 2015",
         "applies": False, "severity": "INFO", "detail": ""},
        {"rule_id": "REG-RBI-004", "title": "UPI per-transaction cap breach",
         "citation": "NPCI UPI circulars / RBI digital payments framework",
         "applies": False, "severity": "INFO", "detail": ""},
        {"rule_id": "REG-KYC-005", "title": "KYC deficiency",
         "citation": "RBI Master Direction on KYC, 2016 (as amended)",
         "applies": False, "severity": "INFO", "detail": ""},
        {"rule_id": "REG-RBI-006", "title": "Rapid layering (mule-like)",
         "citation": "RBI advisory on mule accounts / money mule awareness",
         "applies": False, "severity": "INFO", "detail": ""},
        {"rule_id": "REG-ACCT-007", "title": "New-account elevated velocity",
         "citation": "RBI KYC Master Direction - new account monitoring",
         "applies": False, "severity": "INFO", "detail": ""},
    ]


def _by_id(findings, rule_id):
    return next(f for f in findings if f["rule_id"] == rule_id)


def evaluate(evidence: dict, agents: dict) -> dict:
    """Run all deterministic rules. `evidence` = sanitized package,
    `agents` = three-agent output (analysis input only, never authoritative)."""
    findings = _findings_template()
    txns = evidence.get("transactions", [])
    alerts = evidence.get("alerts", [])
    total_alert_score = sum(float(a.get("score") or 0) for a in alerts)

    verdict = agents.get("contradiction", {}).get("verdict", "")
    v_conf = float(agents.get("contradiction", {}).get("confidence", 0))

    # REG-PMLA-001 STR: high aggregate alert score or strong scammer verdict
    if total_alert_score >= 45 or (verdict == "scammer" and v_conf >= 0.6):
        f = _by_id(findings, "REG-PMLA-001")
        f.update(applies=True, severity="CRITICAL",
                 detail=f"aggregate detection score {total_alert_score}, "
                        f"contradiction verdict={verdict} ({v_conf:.2f}); "
                        "STR filing to FIU-IND warranted")

    # REG-CTR-002 cash threshold
    cash = sum(t["amount"] for t in txns if t.get("channel") in CASH_CHANNELS)
    if cash >= CTR_CASH_THRESHOLD:
        _by_id(findings, "REG-CTR-002").update(
            applies=True, severity="HIGH",
            detail=f"aggregate cash-channel activity Rs {cash:,.0f} "
                   f">= Rs {CTR_CASH_THRESHOLD:,.0f} in evidence window")

    # REG-FEMA-003 international
    intl = [t for t in txns if str(t.get("is_international", "")).lower() == "true"]
    if intl:
        _by_id(findings, "REG-FEMA-003").update(
            applies=True, severity="MEDIUM",
            detail=f"{len(intl)} international transaction(s) in window; "
                   "FEMA/LRS purpose review required")

    # REG-RBI-004 UPI cap
    upi = [t for t in txns if t.get("channel") == "UPI" and t["amount"] > UPI_SINGLE_CAP]
    if upi:
        _by_id(findings, "REG-RBI-004").update(
            applies=True, severity="MEDIUM",
            detail=f"{len(upi)} UPI txn(s) above Rs {UPI_SINGLE_CAP:,.0f} cap; "
                   "channel anomaly review")

    # REG-KYC-005 KYC
    kyc = str(evidence.get("account", {}).get("kyc_status", "")).upper()
    if kyc in ("", "PENDING", "FAILED", "NOT_DONE"):
        _by_id(findings, "REG-KYC-005").update(
            applies=True, severity="HIGH", detail=f"kyc_status={kyc or 'missing'}")

    # REG-RBI-006 rapid layering: OUT ratio soon after IN
    inflow = sum(t["amount"] for t in txns if t.get("direction") == "IN")
    outflow = sum(t["amount"] for t in txns if t.get("direction") == "OUT")
    if inflow and outflow / inflow >= 0.8:
        _by_id(findings, "REG-RBI-006").update(
            applies=True, severity="HIGH",
            detail=f"outbound/inbound ratio {outflow / inflow:.2f} >= 0.80 "
                   "within evidence window (pass-through/layering pattern)")

    # REG-ACCT-007 new account velocity
    try:
        opened = datetime.strptime(evidence["account"]["account_open_date"], "%Y-%m-%d")
        first = min(datetime.strptime(t["timestamp"].split(" ")[0], "%Y-%m-%d")
                    for t in txns) if txns else None
        if first and (first - opened).days < 90:
            baseline = float(evidence["account"].get("avg_monthly_txn_amount") or 0)
            if baseline and outflow >= 3 * baseline:
                _by_id(findings, "REG-ACCT-007").update(
                    applies=True, severity="HIGH",
                    detail=f"account {(first - opened).days} days old at activity; "
                           f"outflow Rs {outflow:,.0f} >= 3x baseline")
    except (KeyError, ValueError):
        pass

    applied = [f for f in findings if f["applies"]]
    return {
        "engine": "deterministic_india_mvp",
        "findings": findings,
        "applied": [f["rule_id"] for f in applied],
        "max_severity": max((f["severity"] for f in applied),
                            key=lambda s: SEVERITY_ORDER[s], default="INFO"),
        "str_required": _by_id(findings, "REG-PMLA-001")["applies"],
    }
