"""Evidence Builder (Architecture.md section 21, Checkpoint 3).

Gathers and normalizes evidence for one case from accounts, transactions,
devices, geo events, beneficiaries, network output and detection alerts.
Feeds the PII Sanitizer to produce the LLM-safe package consumed by the
Scammer / Legitimate / Contradiction hypothesis agents (Checkpoint 4).
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta

from detection.loader import BankData, parse_ts
from detection.network_layer import build_case_network

MAX_TXNS = 200
MAX_GEO = 100
MAX_BENS = 30


class EvidenceBuilder:
    def __init__(self, data: BankData, evidence_dir: str = "./mockdata/evidence"):
        self.d = data
        self.evidence_dir = evidence_dir

    def build(self, case: dict, alerts: list[dict]) -> dict:
        d = self.d
        acc = case["account_id"]
        arow = d.accounts[acc]

        # evidence window: alert windows +- 24h
        wins = [(parse_ts(a["window_start"]), parse_ts(a["window_end"]))
                for a in alerts] or [(datetime.min, datetime.max)]
        lo = min(w[0] for w in wins) - timedelta(hours=24)
        hi = max(w[1] for w in wins) + timedelta(hours=72)

        # transactions touching the case account in-window (focal first)
        txns = []
        for t in d.txns_by_id.values():
            if acc not in (t["sender_account_id"], t["receiver_account_id"]):
                continue
            ts = parse_ts(t["timestamp"])
            if lo <= ts <= hi:
                txns.append((ts, t))
        txns.sort(key=lambda x: x[0])
        txn_rows = [{
            "transaction_id": t["transaction_id"],
            "counterparty": t["receiver_account_id"] if t["sender_account_id"] == acc
            else t["sender_account_id"],
            "direction": "OUT" if t["sender_account_id"] == acc else "IN",
            "timestamp": t["timestamp"], "amount": float(t["amount"]),
            "transaction_type": t["transaction_type"], "channel": t["channel"],
            "transaction_status": t["transaction_status"],
        } for _, t in txns[:MAX_TXNS]]

        devices = [{k: v for k, v in dv.items() if k != "account_id"}
                   for dv in d.devices_by_account[acc]]

        geos = [{
            "timestamp": g["timestamp"], "city": g["city"], "state": g["state"],
            "country": g["country"], "is_vpn_or_proxy": g["is_vpn_or_proxy"],
            "distance_from_last_location_km": g["distance_from_last_location_km"],
            "registered_country_match": g["registered_country_match"],
            "event_type": g["event_type"], "evidence_status": g["evidence_status"],
        } for g in d.geos_by_account[acc] if lo <= g["_ts"] <= hi][:MAX_GEO]

        used_bens = {t["beneficiary_id"] for t in d.txns_by_id.values()
                     if t["sender_account_id"] == acc and t["beneficiary_id"]}
        bens = [{k: v for k, v in b.items() if k != "account_id"}
                for bid, b in d.bens_by_owner[acc].items() if bid in used_bens][:MAX_BENS]

        network_raw = build_case_network(d, acc)
        network = {
            "stats": network_raw["stats"],
            "window": network_raw["window"],
            "nodes": [n["data"]["id"] for n in network_raw["elements"]
                      if "source" not in n["data"]],
            "edges": [{"source": e["data"]["source"], "target": e["data"]["target"],
                       "amount": e["data"]["amount"], "timestamp": e["data"]["timestamp"]}
                      for e in network_raw["elements"] if "source" in e["data"]],
        }

        return {
            "case_id": case["case_id"],
            "generated_at": datetime.now().replace(microsecond=0).isoformat(sep=" "),
            "case": {k: case[k] for k in ("primary_trigger", "typologies", "status",
                                          "created_at", "bundle_reason")},
            "account": {
                "account_id": acc, "account_type": arow["account_type"],
                "account_status": arow["account_status"],
                "account_open_date": arow["account_open_date"],
                "kyc_status": arow["kyc_status"], "risk_rating": arow["risk_rating"],
                "registered_country": arow["registered_country"],
                "customer_segment": arow["customer_segment"],
                "avg_monthly_txn_count": arow["avg_monthly_txn_count"],
                "avg_monthly_txn_amount": float(arow["avg_monthly_txn_amount"]),
            },
            "alerts": [{
                "alert_id": a["alert_id"], "rule_id": a["rule_id"],
                "rule_name": a["rule_name"], "typology": a["typology"],
                "score": a["score"], "detected_at": a["detected_at"],
                "window_start": a["window_start"], "window_end": a["window_end"],
                "evidence": json.loads(a["evidence"]),
            } for a in alerts],
            "transactions": txn_rows,
            "devices": devices,
            "geo_events": geos,
            "beneficiaries": bens,
            "network": network,
            "security_timeline": network_raw["security_timeline"][:MAX_GEO],
        }

    def save(self, package: dict) -> str:
        os.makedirs(self.evidence_dir, exist_ok=True)
        path = os.path.join(self.evidence_dir, f"{package['case_id']}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(package, f, indent=1, default=str)
        return path
