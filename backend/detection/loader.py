"""Load mock banking CSVs into indexed structures for the Detection Agent.

The Detection Agent never reads ground truth (Architecture.md sections 14, 46).
"""
from __future__ import annotations

import csv
from bisect import bisect_left, bisect_right
from collections import defaultdict
from datetime import datetime, timedelta

TS_FMT = "%Y-%m-%d %H:%M:%S"


def parse_ts(s: str) -> datetime:
    return datetime.strptime(s, TS_FMT)


class BankData:
    """In-memory index over accounts/transactions/devices/geo/beneficiaries."""

    def __init__(self, mockdata_dir: str):
        self.dir = mockdata_dir
        self._load()

    def _rows(self, name):
        with open(f"{self.dir}/{name}", encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    def _load(self):
        self.accounts = {r["account_id"]: r for r in self._rows("accounts.csv")}

        # counterparty transfers per account (SUCCESS, non-self), sorted by time
        self.inbound = defaultdict(list)    # acc -> [(ts, amt, peer, txn_id, ben_id)]
        self.outbound = defaultdict(list)
        self.month_flow = defaultdict(float)   # (acc, "YYYY-MM") -> sum(in+out+self)
        self.month_out = defaultdict(float)
        self.internal_edges = []               # [(ts, sender, receiver, amt, txn_id, channel)]
        self.txns_by_id = {}

        for t in self._rows("transactions.csv"):
            if t["transaction_status"] != "SUCCESS":
                continue
            ts, amt = parse_ts(t["timestamp"]), float(t["amount"])
            s, r = t["sender_account_id"], t["receiver_account_id"]
            rec = (ts, amt, s, t["transaction_id"], t["beneficiary_id"])
            self.txns_by_id[t["transaction_id"]] = t
            month = ts.strftime("%Y-%m")
            if s == r:
                if s in self.accounts:
                    self.month_flow[(s, month)] += amt
                continue
            if s in self.accounts:
                self.outbound[s].append((ts, amt, r, t["transaction_id"], t["beneficiary_id"]))
                self.month_flow[(s, month)] += amt
                self.month_out[(s, month)] += amt
            if r in self.accounts:
                self.inbound[r].append((ts, amt, s, t["transaction_id"], t["beneficiary_id"]))
                self.month_flow[(r, month)] += amt
            if s in self.accounts and r in self.accounts:
                self.internal_edges.append((ts, s, r, amt, t["transaction_id"], t["channel"]))

        for idx in (self.inbound, self.outbound):
            for lst in idx.values():
                lst.sort(key=lambda x: x[0])
        self.internal_edges.sort(key=lambda x: x[0])

        self.devices = self._rows("devices.csv")
        self.devices_by_account = defaultdict(list)
        for d in self.devices:
            self.devices_by_account[d["account_id"]].append(d)

        geos = self._rows("geo_events.csv")
        self.geos_by_account = defaultdict(list)
        for g in geos:
            g["_ts"] = parse_ts(g["timestamp"])
            self.geos_by_account[g["account_id"]].append(g)
        for lst in self.geos_by_account.values():
            lst.sort(key=lambda g: g["_ts"])

        self.bens_by_owner = defaultdict(dict)   # owner -> {ben_id: row}
        for b in self._rows("beneficiaries.csv"):
            self.bens_by_owner[b["account_id"]][b["beneficiary_id"]] = b

        self.months = sorted({m for (_, m) in self.month_flow})

    # ---------- lookup helpers ----------

    def baseline(self, acc: str) -> float:
        return float(self.accounts[acc]["avg_monthly_txn_amount"])

    def is_internal(self, acc: str) -> bool:
        return acc in self.accounts

    def in_window(self, acc: str, lo: datetime, hi: datetime, side="in"):
        """Counterparty transfers of `acc` within [lo, hi]."""
        lst = self.inbound[acc] if side == "in" else self.outbound[acc]
        keys = [x[0] for x in lst]
        i, j = bisect_left(keys, lo), bisect_right(keys, hi)
        return lst[i:j]

    def onward_after(self, acc: str, after: datetime, within_h: float):
        """Outbound internal transfers of `acc` in (after, after+within_h]."""
        lst = self.outbound[acc]
        keys = [x[0] for x in lst]
        i, j = bisect_right(keys, after), bisect_right(keys, after + timedelta(hours=within_h))
        return [x for x in lst[i:j] if self.is_internal(x[2])]
