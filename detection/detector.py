"""Rule-based Detection Agent (Architecture.md sections 14-17).

Evaluates every account against the three rulebooks and emits suspected
alerts. Deterministic only - no LLM, no ground truth. Detection gating
(section 17): network typologies need >= 2 qualifying rules (reverse
smurfing additionally needs a distribution-side rule); account_swap needs
security + transaction context together.
"""
from __future__ import annotations

import json
import random
import string
from datetime import datetime, timedelta

from .loader import BankData
from .rulebook import (AS_SECURITY_RULES, AS_TRANSACTION_RULES,
                       RSMF_DISTRIBUTION_RULES, SMF_CORE_RULES, RULEBOOKS)

H24 = timedelta(hours=24)
H6 = timedelta(hours=6)
H72 = timedelta(hours=72)

# "Onward transfer" for SMF-003/007 means moving funds to another account,
# not consumption spending (card/UPI-merchant/ATM).
TRANSFER_TYPES = {"IMPS_TRANSFER", "NEFT_TRANSFER", "RTGS_TRANSFER", "UPI_P2P",
                  "BRANCH_TRANSFER", "CASH_DEPOSIT"}
# Received funds must be material (share of the account's monthly baseline)
# and include at least one internal peer for SMF-003/007 to qualify.
MIN_INBOUND_BASELINE_SHARE = 0.5


def _alert_id(rng):
    body = "".join(rng.choice(string.ascii_uppercase + string.digits) for _ in range(7))
    return f"ALR-{body}"


class DetectionAgent:
    def __init__(self, data: BankData, run_at: datetime | None = None):
        self.d = data
        self.run_at = run_at or datetime.now().replace(microsecond=0)
        self.rng = random.Random(20010911)   # id minting only, not decisions
        self.alerts: list[dict] = []

    # ---------- shared helpers ----------

    def _best_window(self, lst, need_count, need_unique):
        """Slide a 24h window; return the first window having >= need_count
        transfers and >= need_unique unique counterparties."""
        i = 0
        for j in range(len(lst)):
            while lst[j][0] - lst[i][0] > H24:
                i += 1
            rows = lst[i:j + 1]
            uniques = {x[2] for x in rows}
            if len(rows) >= need_count and len(uniques) >= need_unique:
                return (rows[0][0], rows[-1][0]), rows, uniques
        return None

    def _burst_window(self, acc):
        rows = sorted(self.d.inbound[acc] + self.d.outbound[acc], key=lambda x: x[0])
        return (rows[0][0], rows[-1][0]) if rows else (self.run_at, self.run_at)

    def _emit(self, acc, rule_id, typology, window, evidence):
        rule = RULEBOOKS[typology][rule_id]
        w0, w1 = window or self._burst_window(acc)
        self.alerts.append({
            "alert_id": _alert_id(self.rng),
            "account_id": acc,
            "rule_id": rule_id,
            "rule_name": rule["name"],
            "typology": typology,
            "score": rule["score"],
            "detected_at": self.run_at.strftime("%Y-%m-%d %H:%M:%S"),
            "window_start": w0.strftime("%Y-%m-%d %H:%M:%S"),
            "window_end": w1.strftime("%Y-%m-%d %H:%M:%S"),
            "evidence": json.dumps(evidence, default=str),
        })

    # ---------- smurfing rules (evaluated on the receiving account) ----------

    def eval_smurfing(self, acc):
        d = self.d
        inbound, outbound = d.inbound[acc], d.outbound[acc]
        base = d.baseline(acc)
        hits = []   # (rule_id, window, evidence)
        # distribution-style rules consider fund transfers, not shopping
        outbound_t = [x for x in outbound
                      if d.txns_by_id[x[3]]["transaction_type"] in TRANSFER_TYPES]

        hit = self._best_window(inbound, 3, 3)
        if hit:
            (w0, w1), rows, uniq = hit                          # SMF-001
            hits.append(("SMF-001", (w0, w1),
                         {"unique_inbound_senders": len(uniq), "senders": sorted(uniq),
                          "window_hours": round((w1 - w0).total_seconds() / 3600, 1)}))
            total, amts = sum(x[1] for x in rows), [x[1] for x in rows]
            mean = total / len(amts)
            cv = (sum((a - mean) ** 2 for a in amts) / len(amts)) ** 0.5 / mean
            if total > base and cv <= 0.8:                      # SMF-002
                hits.append(("SMF-002", (w0, w1),
                             {"inbound_count": len(rows), "aggregate_amount": round(total, 2),
                              "account_baseline": base, "amount_cv": round(cv, 2)}))

        best = None                                             # SMF-003 / SMF-007
        for ts, amt, peer, tid, bid in outbound:
            if d.txns_by_id[tid]["transaction_type"] not in TRANSFER_TYPES:
                continue
            prior = d.in_window(acc, ts - H6, ts, "in")
            s_in = sum(x[1] for x in prior)
            if s_in < MIN_INBOUND_BASELINE_SHARE * base:
                continue
            if not any(d.is_internal(x[2]) for x in prior):
                continue
            ratio = amt / s_in
            if best is None or ratio > best[0]:
                best = (ratio, ts, tid, s_in, (ts - prior[-1][0]).total_seconds() / 60)
        if best:
            ratio, ts, tid, s_in, gap_min = best
            if ratio >= 0.70 and gap_min <= 360:
                hits.append(("SMF-003", (ts - H6, ts),
                             {"transaction_id": tid, "outgoing_amount_ratio": round(ratio, 2),
                              "incoming_sum_6h": round(s_in, 2),
                              "minutes_after_inbound": round(gap_min)}))
            if ratio >= 0.80 and gap_min <= 360:
                hits.append(("SMF-007", (ts - H6, ts),
                             {"transaction_id": tid, "outgoing_incoming_ratio": round(ratio, 2),
                              "incoming_sum_6h": round(s_in, 2)}))

        hit = self._best_window(outbound_t, 2, 2)               # SMF-004
        if hit:
            (w0, w1), rows, uniq = hit
            hits.append(("SMF-004", (w0, w1),
                         {"unique_outbound_receivers": len(uniq), "receivers": sorted(uniq)}))

        month, mtotal = max(((m, d.month_flow.get((acc, m), 0.0)) for m in d.months),
                            key=lambda x: x[1], default=("", 0.0))
        if mtotal > 3 * base:                                   # SMF-005
            hits.append(("SMF-005", None,
                         {"month": month, "month_flow_amount": round(mtotal, 2),
                          "avg_monthly_txn_amount": base, "multiple": round(mtotal / base, 1)}))

        for ts, amt, peer, tid, bid in outbound:                # SMF-006 (2 hops)
            if not d.is_internal(peer):
                continue
            onward = d.onward_after(peer, ts, 72)
            if onward:
                hits.append(("SMF-006", (ts, onward[-1][0]),
                             {"chain": [acc, peer, onward[-1][2]],
                              "first_hop_txn": tid, "second_hop_txn": onward[-1][3]}))
                break

        bens = d.bens_by_owner[acc]                             # SMF-008
        for ts, amt, peer, tid, bid in outbound_t:
            b = bens.get(bid) if bid else None
            if b and b["is_first_time_beneficiary"] == "TRUE":
                prior = d.in_window(acc, ts - H6, ts, "in")
                if prior:
                    hits.append(("SMF-008", (prior[0][0], ts),
                                 {"transaction_id": tid, "beneficiary_id": bid,
                                  "minutes_after_inbound":
                                      round((ts - prior[-1][0]).total_seconds() / 60)}))
                    break

        return hits

    # ---------- reverse smurfing rules (distributing account) ----------

    def eval_reverse_smurfing(self, acc):
        d = self.d
        outbound = [x for x in d.outbound[acc]                  # transfers, not shopping
                    if d.txns_by_id[x[3]]["transaction_type"] in TRANSFER_TYPES]
        base = d.baseline(acc)
        hits = []

        hit = self._best_window(outbound, 3, 3)
        if hit:
            (w0, w1), rows, uniq = hit                          # RSMF-001
            hits.append(("RSMF-001", (w0, w1),
                         {"unique_outbound_receivers": len(uniq), "receivers": sorted(uniq)}))
            amts = [x[1] for x in rows]
            mean = sum(amts) / len(amts)
            cv = (sum((a - mean) ** 2 for a in amts) / len(amts)) ** 0.5 / mean
            if len(rows) >= 3 and cv <= 0.5:                    # RSMF-002
                hits.append(("RSMF-002", (w0, w1),
                             {"outbound_count": len(rows), "amount_cv": round(cv, 2),
                              "amounts": [round(a, 2) for a in amts]}))
            span_min = (w1 - w0).total_seconds() / 60
            if len(uniq) >= 3 and span_min <= 360:              # RSMF-003
                hits.append(("RSMF-003", (w0, w1),
                             {"distribution_window_minutes": round(span_min),
                              "receivers": len(uniq)}))

        seen: set[str] = set()                                  # RSMF-004/006/007
        for ts, amt, peer, tid, bid in outbound:
            if not d.is_internal(peer):
                continue
            onward = d.onward_after(peer, ts, 6)
            if onward and "RSMF-004" not in seen:
                seen.add("RSMF-004")
                hits.append(("RSMF-004", (ts, onward[-1][0]),
                             {"recipient": peer, "received_amount": round(amt, 2),
                              "onward_txn": onward[-1][3],
                              "onward_within_minutes":
                                  round((onward[-1][0] - ts).total_seconds() / 60)}))
                o_amt = sum(x[1] for x in onward)
                if o_amt / amt >= 0.70:
                    seen.add("RSMF-007")
                    hits.append(("RSMF-007", (ts, onward[-1][0]),
                                 {"recipient": peer, "received_amount": round(amt, 2),
                                  "onward_amount": round(o_amt, 2),
                                  "onward_ratio": round(o_amt / amt, 2)}))
            chain = d.onward_after(peer, ts, 72)
            if chain and "RSMF-006" not in seen:
                seen.add("RSMF-006")
                hits.append(("RSMF-006", (ts, chain[-1][0]),
                             {"chain": [acc, peer, chain[-1][2]], "depth": 2}))

        month, mtotal = max(((m, d.month_out.get((acc, m), 0.0)) for m in d.months),
                            key=lambda x: x[1], default=("", 0.0))
        if mtotal > 3 * base:                                   # RSMF-005
            hits.append(("RSMF-005", None,
                         {"month": month, "month_outbound_amount": round(mtotal, 2),
                          "avg_monthly_txn_amount": base, "multiple": round(mtotal / base, 1)}))

        return hits

    # ---------- account swap rules (security + transaction context) ----------

    def eval_account_swap(self, acc):
        d = self.d
        base = d.baseline(acc)
        bens = d.bens_by_owner[acc]
        dev_by_id = {dv["device_id"]: dv for dv in d.devices_by_account[acc]}
        hits = []
        out_ts = [(ts, tid, amt, bid) for ts, amt, peer, tid, bid in d.outbound[acc]]

        for ts, tid, amt, bid in out_ts:                        # device rules
            dev_id = d.txns_by_id[tid]["device_id"]
            dv = dev_by_id.get(dev_id) if dev_id else None
            if dv is None:
                continue
            if dv["is_trusted_device"] == "FALSE":              # AS-002
                hits.append(("AS-002", (ts, ts),
                             {"transaction_id": tid, "device_id": dev_id, "trusted": False}))
            if dv["previous_device_id"] and abs(                # AS-003
                    (ts - datetime.strptime(dv["first_seen_date"], "%Y-%m-%d")).total_seconds()
            ) <= 24 * 3600:
                hits.append(("AS-003", (ts, ts),
                             {"transaction_id": tid, "device_id": dev_id,
                              "previous_device_id": dv["previous_device_id"]}))

        for dv in d.devices_by_account[acc]:                    # AS-001
            if dv["sim_change_detected"] != "TRUE":
                continue
            sim_day = datetime.strptime(dv["first_seen_date"], "%Y-%m-%d")
            near = [ts for ts, *_ in out_ts if abs((ts - sim_day).total_seconds()) <= 24 * 3600]
            if near:
                hits.append(("AS-001", (sim_day, max(near)),
                             {"device_id": dv["device_id"], "sim_change_date": dv["first_seen_date"],
                              "transactions_within_24h": len(near)}))

        prev = None                                             # AS-004/005/006
        for g in d.geos_by_account[acc]:
            if g["evidence_status"] != "AVAILABLE":
                continue
            if g["is_vpn_or_proxy"] == "TRUE":                  # AS-005
                hits.append(("AS-005", (g["_ts"], g["_ts"]),
                             {"geo_event_id": g["geo_event_id"], "city": g["city"]}))
            if g["registered_country_match"] == "FALSE":        # AS-006
                hits.append(("AS-006", (g["_ts"], g["_ts"]),
                             {"geo_event_id": g["geo_event_id"], "country": g["country"],
                              "registered_country": d.accounts[acc]["registered_country"]}))
            if prev is not None:
                dist = float(g["distance_from_last_location_km"] or 0)
                dt_h = (g["_ts"] - prev[0]).total_seconds() / 3600
                if dist > 500 and 0 < dt_h <= 4:                # AS-004
                    hits.append(("AS-004", (prev[0], g["_ts"]),
                                 {"from_city": prev[1], "to_city": g["city"],
                                  "distance_km": dist, "hours": round(dt_h, 2)}))
            prev = (g["_ts"], g["city"])

        for ts, tid, amt, bid in out_ts:                        # AS-007 / AS-008
            b = bens.get(bid) if bid else None
            if b and b["is_first_time_beneficiary"] == "TRUE":
                hits.append(("AS-007", (ts, ts),
                             {"transaction_id": tid, "beneficiary_id": bid,
                              "amount": round(amt, 2)}))
            if amt > 3 * base:
                hits.append(("AS-008", (ts, ts),
                             {"transaction_id": tid, "amount": round(amt, 2),
                              "avg_monthly_txn_amount": base,
                              "multiple": round(amt / base, 1)}))

        fired_ids = {h[0] for h in hits}
        hits = [h for i, h in enumerate(hits)                   # one alert per rule
                if h[0] not in {x[0] for x in hits[:i]}]
        security = AS_SECURITY_RULES & fired_ids
        txn = AS_TRANSACTION_RULES & fired_ids
        if len(security) >= 2 and len(txn) >= 1:                # AS-009
            hits.append(("AS-009", None,
                         {"security_signals": sorted(security),
                          "transaction_signals": sorted(txn)}))
        return hits, security, txn

    # ---------- run + gating (section 17) ----------

    def run(self):
        for acc in self.d.accounts:
            smf = self.eval_smurfing(acc)
            if len(smf) >= 2 and {h[0] for h in smf} & SMF_CORE_RULES:
                for rid, w, ev in smf:
                    self._emit(acc, rid, "smurfing", w, ev)

            rsmf = self.eval_reverse_smurfing(acc)
            if len(rsmf) >= 2 and {h[0] for h in rsmf} & RSMF_DISTRIBUTION_RULES:
                for rid, w, ev in rsmf:
                    self._emit(acc, rid, "reverse_smurfing", w, ev)

            asw, as_sec, as_txn = self.eval_account_swap(acc)
            if len(as_sec) >= 2 and len(as_txn) >= 1:           # security + txn context
                for rid, w, ev in asw:
                    self._emit(acc, rid, "account_swap", w, ev)

        return self.alerts
