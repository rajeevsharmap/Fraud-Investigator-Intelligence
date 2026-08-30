#!/usr/bin/env python3
"""
Tekmerion Intelligence - Checkpoint 1: Mock Data Generator
==========================================================

Generates realistic, India-focused mock source data for the financial-crime
investigation pipeline and writes it under ./mockdata/ :

    mockdata/
        accounts.csv
        transactions.csv
        geo_events.csv
        devices.csv
        beneficiaries.csv
        access_requests.csv                      (created empty, per spec)
        evaluation/
            ground_truth_suspected_alerts.csv    (evaluation-only, isolated)

Design constraints (Architecture.md, Section 5):
  * Creates SOURCE DATA only - no cases, no detection alerts, no bundles.
  * All activity is strictly dated BEFORE the generation date (nothing "today").
  * IDs are randomized and non-sequential (e.g. TXN-SGW235C, ACC-X7FD29A).
  * ~9-10% of accounts participate in suspicious scenarios.
  * Dataset covers: normal activity, smurfing, reverse smurfing, account
    compromise (swap), legitimate-but-anomalous activity, limited/missing
    evidence, fund-flow-without-compromise, compromise-without-fund-flow,
    and both dimensions together.

Usage:
    pip install -r requirements.txt
    python generate_mockdata.py                       # defaults: seed 42, 345 accounts
    python generate_mockdata.py --seed 7 --accounts 345 --outdir ./mockdata

External counterparties (employers, merchants, landlords, hospitals, ...) are
represented with "EXT-..." ids that intentionally have no row in accounts.csv.
balance_after is the sender account's balance after the debit; for credits from
external senders it is the receiver account's balance after the credit.
"""

from __future__ import annotations

import argparse
import csv
import math
import os
import random
import string
import sys
from collections import defaultdict
from datetime import date, datetime, timedelta

try:
    from faker import Faker

    _FAKE = Faker("en_IN")

    def person_name() -> str:
        return _FAKE.name()

    def job_title() -> str:
        return _FAKE.job()

except ImportError:  # graceful fallback so the generator still runs without Faker
    _FIRST = [
        "Aarav", "Vivaan", "Aditya", "Ishaan", "Kabir", "Rohan", "Rahul",
        "Amit", "Suresh", "Ramesh", "Priya", "Ananya", "Diya", "Kavya",
        "Meera", "Pooja", "Sneha", "Anita", "Deepa", "Kavita", "Arjun",
        "Vikram", "Neha", "Ravi", "Sunita", "Manoj", "Farhan", "Sameer",
    ]
    _LAST = [
        "Sharma", "Verma", "Gupta", "Patel", "Reddy", "Nair", "Iyer",
        "Joshi", "Desai", "Mehta", "Kulkarni", "Rao", "Singh", "Kumar",
        "Das", "Bose", "Chatterjee", "Malhotra", "Kapoor", "Bhat",
    ]
    _JOBS = ["Software Engineer", "Teacher", "Accountant", "Shop Owner",
             "Doctor", "Sales Manager", "Consultant", "Driver", "Analyst",
             "Businessman", "Housewife", "Retired"]

    def person_name() -> str:
        return f"{random.choice(_FIRST)} {random.choice(_LAST)}"

    def job_title() -> str:
        return random.choice(_JOBS)


# --------------------------------------------------------------------------
# Static reference data
# --------------------------------------------------------------------------

CITIES = {
    "Mumbai": ("Maharashtra", 19.0760, 72.8777),
    "Delhi": ("Delhi", 28.6139, 77.2090),
    "Bengaluru": ("Karnataka", 12.9716, 77.5946),
    "Hyderabad": ("Telangana", 17.3850, 78.4867),
    "Chennai": ("Tamil Nadu", 13.0827, 80.2707),
    "Kolkata": ("West Bengal", 22.5726, 88.3639),
    "Pune": ("Maharashtra", 18.5204, 73.8567),
    "Ahmedabad": ("Gujarat", 23.0225, 72.5714),
    "Jaipur": ("Rajasthan", 26.9124, 75.7873),
    "Lucknow": ("Uttar Pradesh", 26.8467, 80.9462),
    "Nagpur": ("Maharashtra", 21.1458, 79.0882),
    "Indore": ("Madhya Pradesh", 22.7196, 75.8577),
    "Patna": ("Bihar", 25.5941, 85.1376),
    "Kochi": ("Kerala", 9.9312, 76.2673),
    "Chandigarh": ("Chandigarh", 30.7333, 76.7794),
    "Guwahati": ("Assam", 26.1445, 91.7362),
    "Surat": ("Gujarat", 21.1702, 72.8311),
    "Bhopal": ("Madhya Pradesh", 23.2599, 77.4126),
    "Coimbatore": ("Tamil Nadu", 11.0168, 76.9558),
    "Visakhapatnam": ("Andhra Pradesh", 17.6868, 83.2185),
}

FOREIGN_CITIES = {
    "Dubai": ("Dubai", 25.2048, 55.2708),
    "Singapore": ("Singapore", 1.3521, 103.8198),
    "London": ("Greater London", 51.5074, -0.1278),
    "New York": ("New York", 40.7128, -74.0060),
}

BANKS = [
    ("HDFC Bank", "HDFC"), ("ICICI Bank", "ICIC"), ("State Bank of India", "SBIN"),
    ("Axis Bank", "UTIB"), ("Kotak Mahindra Bank", "KOTAK"), ("Punjab National Bank", "PUNB"),
    ("Bank of Baroda", "BARB"), ("Canara Bank", "CNRB"), ("Union Bank of India", "UBIN"),
    ("IDFC FIRST Bank", "IDFB"), ("IndusInd Bank", "INDB"), ("Yes Bank", "YESB"),
]

MERCHANTS = [
    "AIRTEL POSTPAID", "TATA POWER BILLING", "SWIGGY", "ZOMATO", "AMAZON PAY",
    "BIGBASKET", "INDIAN OIL", "JIO RECHARGE", "BLINKIT", "BOOKMYSHOW",
    "IRCTC", "RAPIDO", "DMART ONLINE", "RELIANCE DIGITAL", "MEDPLUS",
]

HOSPITALS = ["SUNRISE HOSPITAL", "CITY CARE HOSPITAL", "APOLLO CLINIC", "LIFELINE HOSPITAL"]

ID_CHARS = string.ascii_uppercase + string.digits

# Schemas (Architecture.md sections 6-12, 39)
SCHEMA_ACCOUNTS = [
    "account_id", "customer_id", "customer_name", "account_type", "account_status",
    "account_open_date", "kyc_status", "risk_rating", "registered_country",
    "avg_monthly_txn_count", "avg_monthly_txn_amount", "home_branch", "occupation",
    "annual_income", "customer_segment", "last_activity_date",
]
SCHEMA_TXNS = [
    "transaction_id", "sender_account_id", "receiver_account_id", "timestamp",
    "amount", "currency", "transaction_type", "channel", "beneficiary_id",
    "device_id", "geo_event_id", "is_international", "balance_after",
    "transaction_status", "payment_reference",
]
SCHEMA_GEO = [
    "geo_event_id", "account_id", "timestamp", "ip_address", "city", "state",
    "country", "latitude", "longitude", "is_vpn_or_proxy",
    "distance_from_last_location_km", "registered_country_match", "event_type",
    "evidence_status",
]
SCHEMA_DEVICES = [
    "device_id", "account_id", "device_type", "os", "device_fingerprint",
    "first_seen_date", "last_seen_date", "is_trusted_device", "sim_change_detected",
    "jailbroken_rooted", "device_status", "previous_device_id", "evidence_status",
]
SCHEMA_BEN = [
    "beneficiary_id", "account_id", "beneficiary_name", "beneficiary_account_number",
    "beneficiary_bank", "beneficiary_ifsc", "relationship_to_account_holder",
    "date_added", "is_first_time_beneficiary", "is_verified", "beneficiary_risk_flag",
    "total_transfers_to_date", "evidence_status",
]
SCHEMA_ACCESS = [
    "request_id", "investigator_id", "investigator_role", "account_id",
    "requested_fields", "reason", "requested_at", "status", "approved_by",
    "approved_at", "access_scope", "expires_at",
]
SCHEMA_GT = [
    "ground_truth_alert_id", "scenario_id", "account_id", "transaction_id",
    "expected_typology", "expected_detection", "expected_network_involvement",
    "network_root_account_id", "expected_network_depth",
]

FMT = {
    "amount": "{:.2f}",
    "balance_after": "{:.2f}",
    "avg_monthly_txn_amount": "{:.2f}",
    "latitude": "{:.6f}",
    "longitude": "{:.6f}",
    "distance_from_last_location_km": "{:.1f}",
}


def haversine_km(lat1, lon1, lat2, lon2) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1)
    dl = math.radians(lon2 - lon1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def fmt_d(d: date) -> str:
    return d.strftime("%Y-%m-%d")


def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def next_month_first(d: date) -> date:
    return date(d.year + (1 if d.month == 12 else 0), 1 if d.month == 12 else d.month + 1, 1)


def month_ranges(start: date, end: date):
    cur = date(start.year, start.month, 1)
    while cur <= end:
        nxt = next_month_first(cur)
        yield cur, min(nxt - timedelta(days=1), end)
        cur = nxt


# --------------------------------------------------------------------------
# Generator
# --------------------------------------------------------------------------

class MockDataGenerator:
    def __init__(self, seed: int, n_accounts: int, outdir: str, history_days: int):
        self.seed = seed
        self.rng = random.Random(seed)
        self.n_accounts = n_accounts
        self.outdir = outdir
        self.history_days = history_days

        self.today = date.today()
        self.day_end = self.today - timedelta(days=1)          # yesterday: latest activity day
        self.window_start = self.day_end - timedelta(days=history_days)

        self.accounts: dict[str, dict] = {}
        self.meta: dict[str, dict] = {}
        self.txns: list[dict] = []
        self.geos: list[dict] = []
        self.devices: list[dict] = []
        self.bens: list[dict] = []
        self.gt: list[dict] = []
        self.used_ids: set[str] = set()

        self.role: dict[str, str] = {}          # role name -> account_id
        self.normal_pool: list[str] = []
        self.ext_merchants: list[dict] = []
        self.ben_index: dict[tuple, str] = {}   # (owner, target_ref) -> beneficiary_id
        self.checks: list[tuple[bool, str]] = []

    # ---------------- ids ----------------

    def _id(self, prefix: str, n: int = 7) -> str:
        while True:
            body = "".join(self.rng.choice(ID_CHARS) for _ in range(n))
            if body.isdigit() or body.isalpha():
                continue
            iid = f"{prefix}-{body}"
            if iid not in self.used_ids:
                self.used_ids.add(iid)
                return iid

    def _ext_id(self) -> str:
        return self._id("EXT", 7)

    def _ifsc(self, bank_prefix: str) -> str:
        return f"{bank_prefix}0{self.rng.randint(100000, 999999)}"

    def _ip(self, vpn: bool = False, country: str = "INDIA") -> str:
        if vpn:
            return f"45.{self.rng.randint(2, 250)}.{self.rng.randint(2, 250)}.{self.rng.randint(2, 250)}"
        if country != "INDIA":
            return f"{self.rng.choice([81, 94, 119, 176])}.{self.rng.randint(2, 250)}.{self.rng.randint(2, 250)}.{self.rng.randint(2, 250)}"
        return f"{self.rng.choice([49, 103, 106, 117, 182, 157, 223])}.{self.rng.randint(2, 250)}.{self.rng.randint(2, 250)}.{self.rng.randint(2, 250)}"

    # ---------------- expectation helper ----------------

    def expect(self, cond: bool, msg: str):
        self.checks.append((bool(cond), msg))

    # ---------------- accounts ----------------

    def new_account(self, *, role=None, suspicious=None, opened_days_ago=None,
                    segment=None, city=None, acct_type=None, country="INDIA",
                    lifestyle=None, business_name=None):
        rng = self.rng
        aid = self._id("ACC")
        cid = self._id("CUS")
        segment = segment or rng.choice(
            ["RETAIL", "SALARIED", "SALARIED", "PREMIUM", "MASS_AFFLUENT",
             "STUDENT", "SENIOR_CITIZEN", "BUSINESS"])
        acct_type = acct_type or ("CURRENT" if segment == "BUSINESS" else
                                  rng.choice(["SAVINGS", "SALARY", "SAVINGS"]))
        city = city or rng.choice(list(CITIES.keys()))
        opened_days_ago = opened_days_ago if opened_days_ago is not None else rng.randint(200, 2600)
        open_date = self.today - timedelta(days=opened_days_ago)
        bank, prefix = rng.choice(BANKS)
        if country == "INDIA":
            income = {
                "STUDENT": rng.randint(120000, 300000),
                "SENIOR_CITIZEN": rng.randint(300000, 900000),
                "RETAIL": rng.randint(300000, 1200000),
                "SALARIED": rng.randint(500000, 2000000),
                "MASS_AFFLUENT": rng.randint(1200000, 3000000),
                "PREMIUM": rng.randint(2000000, 8000000),
                "BUSINESS": rng.randint(800000, 9000000),
            }[segment]
            occ = "Business Owner" if segment == "BUSINESS" else job_title()
        else:  # NRI
            income = rng.randint(1500000, 6000000)
            occ = job_title()
        name = business_name or person_name()

        self.accounts[aid] = {
            "account_id": aid,
            "customer_id": cid,
            "customer_name": name,
            "account_type": acct_type,
            "account_status": "ACTIVE",
            "account_open_date": fmt_d(open_date),
            "kyc_status": "VERIFIED" if rng.random() < 0.94 else "PENDING",
            "risk_rating": rng.choices(["LOW", "MEDIUM", "HIGH"], [0.80, 0.15, 0.05])[0],
            "registered_country": country,
            "avg_monthly_txn_count": 0,
            "avg_monthly_txn_amount": 0.0,
            "home_branch": self._ifsc(prefix),
            "occupation": occ,
            "annual_income": income,
            "customer_segment": segment,
            "last_activity_date": "",
        }
        self.meta[aid] = {
            "city": city,
            "devices": [],
            "primary_device": None,
            "last_geo": None,          # (dt, lat, lon) of last AVAILABLE geo location
            "scenario": role is not None,
            "suspicious": bool(role is not None) if suspicious is None else suspicious,
            "role": role,
            "lifestyle": lifestyle or {},
            "ben_of": {},
            "out_days": [],            # timestamps of internal outbound transfers (spacing)
            "in_days": [],             # timestamps of internal inbound credits (spacing)
            "payroll_ext": self._ext_id(),
        }
        if role:
            self.role[role] = aid
        else:
            self.normal_pool.append(aid)
        return aid

    # ---------------- devices / geo / beneficiaries / txns ----------------

    def add_device(self, aid, dtype, *, trusted=True, sim=False, jail=False,
                   status="ACTIVE", first_seen=None, last_seen=None, prev="",
                   evidence="AVAILABLE", os_name=None):
        rng = self.rng
        did = self._id("DEV", 6)
        if os_name is None:
            if dtype == "MOBILE":
                os_name = rng.choice(["Android 13", "Android 14", "iOS 17", "iOS 16", "Android 12"])
            elif dtype == "WEB":
                os_name = rng.choice(["Windows 11 / Chrome", "macOS / Safari", "Windows 10 / Edge"])
            else:
                os_name = rng.choice(["iPadOS 17", "Android 14 (Tablet)"])
        first_seen = first_seen or (self.today - timedelta(days=rng.randint(30, 900)))
        last_seen = last_seen or self.day_end
        self.devices.append({
            "device_id": did,
            "account_id": aid,
            "device_type": dtype,
            "os": os_name,
            "device_fingerprint": "fp-" + "".join(rng.choice("0123456789abcdef") for _ in range(12)),
            "first_seen_date": fmt_d(first_seen),
            "last_seen_date": fmt_d(last_seen),
            "is_trusted_device": "TRUE" if trusted else "FALSE",
            "sim_change_detected": "TRUE" if sim else "FALSE",
            "jailbroken_rooted": "TRUE" if jail else "FALSE",
            "device_status": status,
            "previous_device_id": prev,
            "evidence_status": evidence,
        })
        self.meta[aid]["devices"].append(did)
        if trusted and status == "ACTIVE" and self.meta[aid]["primary_device"] is None:
            self.meta[aid]["primary_device"] = did
        return did

    def add_geo(self, aid, ts, city, event_type, *, evidence="AVAILABLE",
                vpn=False, country="INDIA"):
        rng = self.rng
        row = {
            "geo_event_id": self._id("GEO", 6),
            "account_id": aid,
            "timestamp": fmt_ts(ts),
            "ip_address": "",
            "city": "", "state": "", "country": "",
            "latitude": "", "longitude": "",
            "is_vpn_or_proxy": "",
            "distance_from_last_location_km": "",
            "registered_country_match": "",
            "event_type": event_type,
            "evidence_status": evidence,
        }
        if evidence != "UNAVAILABLE":
            state, lat0, lon0 = (CITIES.get(city) or FOREIGN_CITIES.get(city) or ("", 0.0, 0.0))
            lat = lat0 + rng.uniform(-0.05, 0.05)
            lon = lon0 + rng.uniform(-0.05, 0.05)
            last = self.meta[aid]["last_geo"]
            dist = 0.0 if last is None else haversine_km(last[1], last[2], lat, lon)
            reg_country = self.accounts[aid]["registered_country"]
            row.update({
                "ip_address": self._ip(vpn, country),
                "city": city,
                "state": state,
                "country": country,
                "latitude": f"{lat:.6f}",
                "longitude": f"{lon:.6f}",
                "is_vpn_or_proxy": "TRUE" if vpn else "FALSE",
                "distance_from_last_location_km": f"{dist:.1f}",
                "registered_country_match": "TRUE" if country == reg_country else "FALSE",
            })
            if evidence == "AVAILABLE":
                self.meta[aid]["last_geo"] = (ts, lat, lon)
        self.geos.append(row)
        return row["geo_event_id"]

    def add_beneficiary(self, owner, *, name, acct_no, bank, ifsc, rel, added,
                        first_time=False, verified=True, risk="NONE",
                        evidence="AVAILABLE"):
        bid = self._id("BEN", 6)
        self.bens.append({
            "beneficiary_id": bid,
            "account_id": owner,
            "beneficiary_name": name,
            "beneficiary_account_number": acct_no,
            "beneficiary_bank": bank,
            "beneficiary_ifsc": ifsc,
            "relationship_to_account_holder": rel,
            "date_added": fmt_d(added),
            "is_first_time_beneficiary": "TRUE" if first_time else "FALSE",
            "is_verified": "TRUE" if verified else "FALSE",
            "beneficiary_risk_flag": risk,
            "total_transfers_to_date": 0,
            "evidence_status": evidence,
        })
        return bid

    def beneficiary_for(self, owner, target_ref, *, name=None, bank=None, ifsc=None,
                        rel="UNKNOWN", added=None, first_time=False, verified=True,
                        risk="NONE", evidence="AVAILABLE"):
        """Get-or-create the owner's beneficiary row for target_ref (an internal
        account_id or an EXT- account number)."""
        key = (owner, target_ref)
        if key in self.ben_index:
            return self.ben_index[key]
        added = added or (self.today - timedelta(days=self.rng.randint(300, 900)))
        bid = self.add_beneficiary(
            owner, name=name or person_name(), acct_no=target_ref,
            bank=bank or self.rng.choice(BANKS)[0],
            ifsc=ifsc or self._ifsc(self.rng.choice(BANKS)[1]),
            rel=rel, added=added, first_time=first_time, verified=verified,
            risk=risk, evidence=evidence)
        self.ben_index[key] = bid
        return bid

    def ben_acct_no(self, bid):
        for b in self.bens:
            if b["beneficiary_id"] == bid:
                return b["beneficiary_account_number"]
        return self._ext_id()

    def ext_merchant(self):
        return dict(self.rng.choice(self.ext_merchants))

    def add_txn(self, s, r, ts, amount, channel, ttype, *, status="SUCCESS",
                ben="", dev="", intl=False, ref=None, geo=None, geo_city=None,
                geo_vpn=False, geo_evidence="AVAILABLE", geo_country="INDIA"):
        rng = self.rng
        if geo is None:
            geo = channel != "BRANCH"
        if geo:
            owner = s if s in self.meta else r
            if geo_city is None:
                geo_city = self.meta[owner]["city"]
            gid = self.add_geo(owner, ts, geo_city, "TRANSACTION_AUTH",
                               evidence=geo_evidence, vpn=geo_vpn, country=geo_country)
        else:
            gid = ""
        refs = {
            "UPI": f"UPI/{rng.randint(100000000, 999999999)}",
            "IMPS": f"IMPS{rng.randint(10 ** 9, 10 ** 10 - 1)}",
            "NEFT": f"NEFT{rng.randint(10 ** 9, 10 ** 10 - 1)}",
            "RTGS": f"RTGS{rng.randint(10 ** 9, 10 ** 10 - 1)}",
            "ATM": f"ATM-CASH{rng.randint(100000, 999999)}",
            "CARD": f"E-COM/{rng.randint(1000000000, 9999999999)}",
            "BRANCH": f"BRN-CASH{rng.randint(100000, 999999)}",
        }
        self.txns.append({
            "transaction_id": self._id("TXN"),
            "sender_account_id": s,
            "receiver_account_id": r,
            "timestamp": fmt_ts(ts),
            "amount": round(float(amount), 2),
            "currency": "INR",
            "transaction_type": ttype,
            "channel": channel,
            "beneficiary_id": ben,
            "device_id": dev,
            "geo_event_id": gid,
            "is_international": "TRUE" if intl else "FALSE",
            "balance_after": "",     # filled by ledger pass
            "transaction_status": status,
            "payment_reference": ref or refs[channel],
            "_ts": ts,
            "_amount": round(float(amount), 2),
        })

    # ---------------- normal baseline activity ----------------

    def default_lifestyle(self, segment):
        rng = self.rng
        return {
            "STUDENT": {"salary": rng.randint(5000, 10000), "upi": rng.randint(6, 12),
                        "card": rng.randint(0, 2), "atm": rng.randint(2, 4), "out": 0},
            "SENIOR_CITIZEN": {"salary": rng.randint(20000, 40000), "upi": rng.randint(2, 5),
                               "card": rng.randint(0, 2), "atm": rng.randint(1, 2), "out": 0},
            "RETAIL": {"salary": rng.randint(25000, 60000), "upi": rng.randint(4, 8),
                       "card": rng.randint(1, 4), "atm": rng.randint(1, 3), "out": rng.randint(0, 1)},
            "SALARIED": {"salary": rng.randint(60000, 150000),
                         "rent": rng.choice([0, rng.randint(15000, 35000)]),
                         "upi": rng.randint(5, 10), "card": rng.randint(2, 6),
                         "atm": rng.randint(1, 3), "out": rng.randint(1, 2)},
            "MASS_AFFLUENT": {"salary": rng.randint(120000, 250000),
                              "rent": rng.choice([0, rng.randint(25000, 50000)]),
                              "upi": rng.randint(4, 8), "card": rng.randint(3, 8),
                              "atm": rng.randint(0, 2), "out": rng.randint(1, 2)},
            "PREMIUM": {"salary": rng.randint(150000, 400000),
                        "rent": rng.choice([0, rng.randint(30000, 80000)]),
                        "upi": rng.randint(3, 7), "card": rng.randint(5, 10),
                        "atm": rng.randint(0, 2), "out": rng.randint(1, 2)},
            "BUSINESS": {"salary": rng.randint(80000, 400000), "upi": rng.randint(2, 6),
                         "card": rng.randint(3, 8), "atm": rng.randint(0, 2),
                         "out": rng.randint(0, 2)},
        }[segment]

    def _space_out(self, days_log, dt, min_gap_h=36.0):
        for d in days_log:
            if abs((dt - d).total_seconds()) < min_gap_h * 3600:
                return False
        return True

    def gen_normal(self, aid):
        """Generate believable baseline activity for one account."""
        rng = self.rng
        row = self.accounts[aid]
        meta = self.meta[aid]
        ls = meta["lifestyle"] or self.default_lifestyle(row["customer_segment"])
        meta["lifestyle"] = ls
        open_d = datetime.strptime(row["account_open_date"], "%Y-%m-%d").date()
        acc_start = max(open_d + timedelta(days=2), self.window_start)
        acc_end = self.day_end

        # primary trusted mobile device
        dev = self.add_device(aid, "MOBILE", trusted=True,
                              first_seen=min(open_d + timedelta(days=rng.randint(1, 20)),
                                             acc_start))
        meta["primary_device"] = dev
        if rng.random() < 0.18:
            self.add_device(aid, rng.choice(["WEB", "TABLET"]), trusted=True,
                            first_seen=self.today - timedelta(days=rng.randint(60, 400)))
        # a replaced (retired) phone for ~10% - old SIM change, long settled
        if rng.random() < 0.10:
            retired_days_ago = rng.randint(130, 450)
            self.add_device(aid, "MOBILE", trusted=False, status="RETIRED",
                            sim=True, first_seen=open_d,
                            last_seen=self.today - timedelta(days=retired_days_ago),
                            evidence=rng.choice(["AVAILABLE", "AVAILABLE", "UNKNOWN"]))
            new_dev = self.add_device(aid, "MOBILE", trusted=True, sim=False,
                                      first_seen=self.today - timedelta(days=retired_days_ago),
                                      last_seen=self.day_end)
            self.devices[-1]["previous_device_id"] = self.meta[aid]["devices"][-2]
            meta["primary_device"] = new_dev

        partners = rng.sample([a for a in self.normal_pool if a != aid],
                              k=min(len(self.normal_pool) - 1, rng.randint(0, 3))) \
            if len(self.normal_pool) > 1 else []

        months = list(month_ranges(acc_start, acc_end))
        # occasional large RTGS payments for wealthier segments
        rtgs_plan = {}
        if row["customer_segment"] in ("BUSINESS", "PREMIUM", "MASS_AFFLUENT") \
                and rng.random() < 0.35 and months:
            rtgs_plan[rng.randrange(len(months))] = round(rng.uniform(250000, 1200000), -3)

        for m_i, (m_start, m_end) in enumerate(months):
            def day_in(h0=8, h1=21):
                d = m_start + timedelta(days=rng.randint(0, (m_end - m_start).days))
                return datetime(d.year, d.month, d.day, rng.randint(h0, h1), rng.randint(0, 59))

            def sparse_geo():
                return rng.random() < 0.6   # ~40% of transactions have no auth log

            # salary / pension / family-support / client inflow from external source
            if ls.get("salary", 0) > 0:
                d = min(m_start + timedelta(days=rng.randint(0, 2)), m_end)
                amt = ls["salary"] * rng.uniform(0.92, 1.08)
                if row["customer_segment"] == "STUDENT":
                    tt, ref = "NEFT_TRANSFER", f"FAMILY-SUPPORT-{m_start.strftime('%Y%m')}"
                elif row["customer_segment"] == "BUSINESS":
                    tt, ref = "NEFT_TRANSFER", f"CLIENT-PAYMENT-{m_start.strftime('%Y%m')}"
                else:
                    tt, ref = "SALARY_CREDIT", f"SALARY-{m_start.strftime('%Y%m')}"
                self.add_txn(meta["payroll_ext"], aid,
                             datetime(d.year, d.month, d.day, rng.randint(9, 12), rng.randint(0, 59)),
                             amt, "NEFT", tt, geo=False, ref=ref)

            # rent to an external landlord (one stable landlord per account)
            if ls.get("rent", 0) > 0 and rng.random() < 0.9:
                if "landlord_ext" not in meta:
                    meta["landlord_ext"] = self._ext_id()
                bid = self.beneficiary_for(aid, meta["landlord_ext"],
                                           rel="UNKNOWN", name=f"{person_name()} (Landlord)")
                self.add_txn(aid, self.ben_acct_no(bid), day_in(9, 11),
                             ls["rent"] * rng.uniform(0.98, 1.02), "IMPS", "IMPS_TRANSFER",
                             ben=bid, dev=dev, ref=f"RENT-{m_start.strftime('%Y%m')}", geo=sparse_geo())

            # utilities / subscriptions to saved merchants
            for _ in range(rng.randint(1, 2)):
                mer = self.ext_merchant()
                bid = self.beneficiary_for(aid, mer["acct"], name=mer["name"],
                                           bank=mer["bank"], ifsc=mer["ifsc"], rel="MERCHANT")
                self.add_txn(aid, mer["acct"], day_in(8, 22), rng.uniform(300, 4000),
                             "UPI", "UPI_MERCHANT", ben=bid, dev=dev, geo=sparse_geo())

            # everyday UPI spend (ad-hoc payees, no saved beneficiary)
            for _ in range(ls.get("upi", 0)):
                status = "FAILED" if rng.random() < 0.02 else "SUCCESS"
                self.add_txn(aid, self._ext_id(), day_in(8, 23), rng.uniform(100, 3000),
                             "UPI", "UPI_MERCHANT", dev=dev, status=status, geo=sparse_geo())

            # card purchases
            for _ in range(ls.get("card", 0)):
                mer = self.ext_merchant()
                self.add_txn(aid, mer["acct"], day_in(9, 22), rng.uniform(300, 15000),
                             "CARD", "CARD_PURCHASE", dev=dev, geo=sparse_geo(),
                             intl=row["registered_country"] != "INDIA" and rng.random() < 0.3)

            # ATM withdrawals (cash leaves the account)
            for _ in range(ls.get("atm", 0)):
                self.add_txn(aid, aid, day_in(8, 22),
                             rng.choice([500, 1000, 2000, 5000, 10000]),
                             "ATM", "ATM_WITHDRAWAL", geo=sparse_geo())

            # scheduled transfers to internal partners (spaced >= 36h apart)
            for p in partners:
                if rng.random() < 0.35:
                    dt = day_in(9, 20)
                    if self._space_out(meta["out_days"], dt) \
                            and self._space_out(self.meta[p]["in_days"], dt):
                        bid = self.beneficiary_for(aid, p, rel=rng.choice(["FAMILY", "FRIEND"]))
                        meta["out_days"].append(dt)
                        self.meta[p]["in_days"].append(dt)
                        ch = rng.choice(["IMPS", "NEFT"])
                        self.add_txn(aid, p, dt, rng.uniform(500, 25000), ch,
                                     "IMPS_TRANSFER" if ch == "IMPS" else "NEFT_TRANSFER",
                                     ben=bid, dev=dev)

            # occasional large RTGS business payment
            if m_i in rtgs_plan:
                ext_no = self._ext_id()
                bid = self.beneficiary_for(aid, ext_no, rel="UNKNOWN")
                self.add_txn(aid, ext_no, day_in(10, 16), rtgs_plan[m_i],
                             "RTGS", "RTGS_TRANSFER", ben=bid, dev=dev)

            # logins
            for _ in range(rng.randint(3, 7)):
                self.add_geo(aid, day_in(7, 23), meta["city"], "LOGIN",
                             evidence=rng.choices(["AVAILABLE", "UNKNOWN", "UNAVAILABLE"],
                                                  [0.93, 0.02, 0.05])[0],
                             vpn=rng.random() < 0.01)

        # sparse inbound credits from other normal accounts (never 3 senders/24h)
        for _ in range(rng.randint(0, 2)):
            if not partners:
                break
            p = rng.choice(partners)
            d = acc_start + timedelta(days=rng.randint(0, max(0, (acc_end - acc_start).days)))
            dt = datetime(d.year, d.month, d.day, rng.randint(9, 21), rng.randint(0, 59))
            if self._space_out(meta["in_days"], dt, min_gap_h=240.0):
                meta["in_days"].append(dt)
                self.add_txn(p, aid, dt, rng.uniform(500, 20000), "IMPS", "IMPS_TRANSFER")

    # ---------------- profiles ----------------

    def compute_profiles(self):
        """avg_monthly_* reflect the customer's BASELINE profile (computed from
        baseline activity only, before any scenario burst is added)."""
        sums = defaultdict(float)
        cnts = defaultdict(int)
        for t in self.txns:
            if t["transaction_status"] != "SUCCESS":
                continue
            s, r = t["sender_account_id"], t["receiver_account_id"]
            if s == r:  # ATM withdrawal: one movement, one count
                sums[s] += t["_amount"]
                cnts[s] += 1
                continue
            for a in (s, r):
                if a in self.accounts:
                    sums[a] += t["_amount"]
                    cnts[a] += 1
        for aid, row in self.accounts.items():
            open_d = datetime.strptime(row["account_open_date"], "%Y-%m-%d").date()
            start = max(open_d, self.window_start)
            months = max(1.0, (self.day_end - start).days / 30.0)
            row["avg_monthly_txn_amount"] = max(round(sums[aid] / months, 2), 1000.0)
            row["avg_monthly_txn_count"] = max(1, round(cnts[aid] / months))

    def profile_avg(self, aid):
        return self.accounts[aid]["avg_monthly_txn_amount"]

    # ---------------- ground truth ----------------

    def add_gt(self, scenario_id, account_id, txn_id, typology, network, root, depth):
        self.gt.append({
            "ground_truth_alert_id": self._id("GTA", 6),
            "scenario_id": scenario_id,
            "account_id": account_id,
            "transaction_id": txn_id,
            "expected_typology": typology,
            "expected_detection": "SUSPECTED_ALERT",
            "expected_network_involvement": network,
            "network_root_account_id": root,
            "expected_network_depth": depth,
        })

    # ---------------- time helpers ----------------

    def at(self, offset_days, h, m=0):
        d = self.day_end - timedelta(days=offset_days)
        return datetime(d.year, d.month, d.day, h, m)

    def _inbound_stats(self, aid, center, hours=24):
        lo = center - timedelta(hours=hours)
        return [t for t in self.txns
                if t["receiver_account_id"] == aid
                and t["transaction_status"] == "SUCCESS"
                and lo <= t["_ts"] <= center]

    # ---------------- scenarios ----------------

    # SCN-SMF-001: smurfing, rapid onward pass-through, multi-hop (fund-flow only)
    def scenario_smurf_s1(self):
        off = 18
        t_acc = self.role["S1_target"]
        s1, s2, s3 = self.role["S1_smurf1"], self.role["S1_smurf2"], self.role["S1_smurf3"]
        o_acc, h_acc = self.role["S1_onward"], self.role["S1_hop"]

        legs = [(s1, 52000, self.at(off, 10, 5), "IMPS", "IMPS_TRANSFER"),
                (s1, 47000, self.at(off, 12, 30), "BRANCH", "CASH_DEPOSIT"),
                (s2, 49000, self.at(off, 11, 15), "IMPS", "IMPS_TRANSFER"),
                (s2, 44000, self.at(off, 13, 40), "IMPS", "IMPS_TRANSFER"),
                (s3, 51000, self.at(off, 14, 20), "IMPS", "IMPS_TRANSFER")]
        for s, amt, ts, ch, tt in legs:
            self.add_txn(s, t_acc, ts, amt, ch, tt,
                         dev=self.meta[s]["primary_device"] if ch != "BRANCH" else "")
        total_in = sum(a for _, a, *_ in legs)

        onward_ts = self.at(off, 18, 20)
        self.add_txn(t_acc, o_acc, onward_ts, 206000, "NEFT", "NEFT_TRANSFER",
                     dev=self.meta[t_acc]["primary_device"])
        t_onward = self.txns[-1]
        hop_ts = self.at(off, 20, 10)
        self.add_txn(o_acc, h_acc, hop_ts, 185000, "IMPS", "IMPS_TRANSFER",
                     dev=self.meta[o_acc]["primary_device"])
        o_onward = self.txns[-1]

        in24 = self._inbound_stats(t_acc, onward_ts)
        self.expect(len({t["sender_account_id"] for t in in24}) >= 3,
                    "S1: >=3 unique inbound senders within 24h (SMF-001)")
        ratio = t_onward["_amount"] / total_in
        gap_min = (onward_ts - max(t["_ts"] for t in in24)).total_seconds() / 60
        self.expect(ratio >= 0.70 and gap_min <= 360,
                    f"S1: target onward ratio {ratio:.2f} within {gap_min:.0f} min (SMF-003/007)")
        o_in = self._inbound_stats(o_acc, hop_ts)
        o_ratio = o_onward["_amount"] / sum(t["_amount"] for t in o_in)
        o_gap = (hop_ts - max(t["_ts"] for t in o_in)).total_seconds() / 60
        self.expect(o_ratio >= 0.70 and o_gap <= 360,
                    f"S1: pass-through onward ratio {o_ratio:.2f} within {o_gap:.0f} min")

        self.add_gt("SCN-SMF-001", t_acc, t_onward["transaction_id"], "smurfing", "YES", t_acc, 2)
        self.add_gt("SCN-SMF-001", o_acc, o_onward["transaction_id"], "smurfing", "YES", t_acc, 2)

    # SCN-SMF-002: smurfing with rapid onward to a first-time beneficiary
    def scenario_smurf_s2(self):
        off = 9
        t_acc = self.role["S2_target"]
        z_acc = self.role["S2_receiver"]
        legs = [(self.role["S2_smurf1"], 22000, self.at(off, 9, 30), "UPI", "UPI_P2P"),
                (self.role["S2_smurf2"], 25000, self.at(off, 11, 0), "IMPS", "IMPS_TRANSFER"),
                (self.role["S2_smurf3"], 19000, self.at(off, 13, 15), "UPI", "UPI_P2P"),
                (self.role["S2_smurf4"], 23000, self.at(off, 14, 45), "IMPS", "IMPS_TRANSFER"),
                (self.role["S2_smurf4"], 31000, self.at(off, 16, 0), "IMPS", "IMPS_TRANSFER")]
        for s, amt, ts, ch, tt in legs:
            self.add_txn(s, t_acc, ts, amt, ch, tt, dev=self.meta[s]["primary_device"])
        total_in = sum(a for _, a, *_ in legs)

        added = self.day_end - timedelta(days=off)
        bid = self.beneficiary_for(t_acc, z_acc, rel="UNKNOWN", added=added,
                                   first_time=True, verified=False, risk="HIGH")
        onward_ts = self.at(off, 17, 40)
        self.add_txn(t_acc, z_acc, onward_ts, 95000, "NEFT", "NEFT_TRANSFER",
                     ben=bid, dev=self.meta[t_acc]["primary_device"])
        onward = self.txns[-1]

        in24 = self._inbound_stats(t_acc, onward_ts)
        self.expect(len({t["sender_account_id"] for t in in24}) >= 4,
                    "S2: >=3 unique inbound senders (SMF-001)")
        gap_h = (onward_ts - max(t["_ts"] for t in in24)).total_seconds() / 3600
        self.expect(onward["_amount"] / total_in >= 0.70 and gap_h <= 6,
                    f"S2: onward {onward['_amount'] / total_in:.2f} within {gap_h:.1f} h "
                    "to first-time beneficiary (SMF-003/008)")
        self.add_gt("SCN-SMF-002", t_acc, onward["transaction_id"], "smurfing", "YES", t_acc, 1)

    # SCN-RSMF-001: reverse smurfing with downstream pass-through (3 hops)
    def scenario_reverse_r1(self):
        off = 26
        src = self.role["R1_source"]
        r1, r2, r3 = self.role["R1_r1"], self.role["R1_r2"], self.role["R1_r3"]
        d1, d2, d3 = self.role["R1_d1"], self.role["R1_d2"], self.role["R1_d3"]

        self.add_txn(self._ext_id(), src, self.at(off + 1, 20, 40), 450000, "RTGS",
                     "RTGS_TRANSFER", ref="PROPERTY-REFUND")
        legs = [(r1, 140000, self.at(off, 9, 15), "IMPS", "IMPS_TRANSFER"),
                (r2, 145000, self.at(off, 9, 50), "NEFT", "NEFT_TRANSFER"),
                (r3, 148000, self.at(off, 10, 30), "IMPS", "IMPS_TRANSFER")]
        for rr, amt, ts, ch, tt in legs:
            self.add_txn(src, rr, ts, amt, ch, tt, dev=self.meta[src]["primary_device"])
        first_dist = self.txns[-3]

        self.add_txn(r1, d1, self.at(off, 12, 40), 112000, "IMPS", "IMPS_TRANSFER",
                     dev=self.meta[r1]["primary_device"])
        r1_out = self.txns[-1]
        self.add_txn(r2, d2, self.at(off, 13, 50), 116000, "NEFT", "NEFT_TRANSFER",
                     dev=self.meta[r2]["primary_device"])
        r2_out = self.txns[-1]
        self.add_txn(d2, d3, self.at(off, 15, 45), 98000, "IMPS", "IMPS_TRANSFER",
                     dev=self.meta[d2]["primary_device"])
        d2_out = self.txns[-1]

        outs = [t for t in self.txns if t["sender_account_id"] == src
                and t["transaction_status"] == "SUCCESS"
                and self.at(off, 0) <= t["_ts"] <= self.at(off, 23, 59)]
        self.expect(len({t["receiver_account_id"] for t in outs}) >= 3,
                    "R1: >=3 outbound receivers within 24h (RSMF-001)")
        win_min = (max(t["_ts"] for t in outs) - min(t["_ts"] for t in outs)).total_seconds() / 60
        self.expect(win_min <= 360, f"R1: distribution window {win_min:.0f} min (RSMF-003)")
        r1_ratio = r1_out["_amount"] / 140000
        r1_gap = (self.at(off, 12, 40) - self.at(off, 9, 15)).total_seconds() / 3600
        self.expect(r1_ratio >= 0.70 and r1_gap <= 6,
                    f"R1: r1 onward {r1_ratio:.2f} within {r1_gap:.1f} h (RSMF-004/007)")
        d2_ratio = d2_out["_amount"] / r2_out["_amount"]
        self.expect(d2_ratio >= 0.70,
                    f"R1: d2 downstream onward {d2_ratio:.2f} (depth-3 hop, RSMF-006)")

        self.add_gt("SCN-RSMF-001", src, first_dist["transaction_id"], "reverse_smurfing", "YES", src, 3)
        self.add_gt("SCN-RSMF-001", r1, r1_out["transaction_id"], "reverse_smurfing", "YES", src, 3)
        self.add_gt("SCN-RSMF-001", r2, r2_out["transaction_id"], "reverse_smurfing", "YES", src, 3)
        self.add_gt("SCN-RSMF-001", d2, d2_out["transaction_id"], "reverse_smurfing", "YES", src, 3)

    # SCN-RSMF-002: reverse smurfing, recipients retain funds, limited evidence
    def scenario_reverse_r2(self):
        off = 13
        src = self.role["R2_source"]
        recips = [self.role[f"R2_r{i}"] for i in (4, 5, 6, 7)]

        self.add_txn(self._ext_id(), src, self.at(off + 1, 10, 0), 170000, "NEFT",
                     "NEFT_TRANSFER", ref="CLIENT-PAYMENT")
        self.add_txn(self._ext_id(), src, self.at(off + 1, 12, 0), 150000, "NEFT",
                     "NEFT_TRANSFER", ref="INVOICE-SETTLEMENT")

        amounts = [75000, 78000, 80000, 76000]
        times = [(11, 0), (11, 40), (12, 20), (13, 0)]
        ev_flags = ["UNAVAILABLE", "AVAILABLE", "UNAVAILABLE", "AVAILABLE"]
        first = None
        for rr, amt, (h, m), ev in zip(recips, amounts, times, ev_flags):
            self.add_txn(src, rr, self.at(off, h, m), amt, "IMPS", "IMPS_TRANSFER",
                         dev=self.meta[src]["primary_device"], geo_evidence=ev)
            first = first or self.txns[-1]
        # one recipient's device evidence is unknown (limited evidence scenario)
        dev5 = self.meta[recips[1]]["primary_device"]
        for d in self.devices:
            if d["device_id"] == dev5:
                d["evidence_status"] = "UNKNOWN"

        outs = [t for t in self.txns if t["sender_account_id"] == src
                and t["transaction_status"] == "SUCCESS"
                and self.at(off, 0) <= t["_ts"] <= self.at(off, 23, 59)]
        self.expect(len({t["receiver_account_id"] for t in outs}) >= 4,
                    "R2: >=3 outbound receivers (RSMF-001)")
        self.expect(all(t["receiver_account_id"] != src for t in self.txns[-4:]),
                    "R2: recipients retain funds (no downstream pass-through)")
        self.add_gt("SCN-RSMF-002", src, first["transaction_id"], "reverse_smurfing", "YES", src, 1)

    # SCN-ASW-001: full account takeover (security + transaction anomalies, no network)
    def scenario_swap_as1(self):
        off = 8
        v = self.role["AS1_victim"]
        old_dev = self.meta[v]["primary_device"]
        new_dev = self.add_device(v, "MOBILE", trusted=False, sim=True,
                                  first_seen=self.day_end - timedelta(days=off),
                                  last_seen=self.day_end - timedelta(days=off),
                                  prev=old_dev)
        # victim's last legitimate login, then the takeover sequence overnight
        self.add_geo(v, self.at(off, 1, 0), self.meta[v]["city"], "LOGIN")
        self.add_geo(v, self.at(off, 2, 5), "Delhi", "DEVICE_REGISTRATION", vpn=True)
        self.add_geo(v, self.at(off, 2, 30), "Delhi", "LOGIN", vpn=True)
        added = self.day_end - timedelta(days=off)
        ext_no = self._ext_id()
        ben = self.add_beneficiary(v, name=person_name(), acct_no=ext_no,
                                   bank=self.rng.choice(BANKS)[0],
                                   ifsc=self._ifsc(self.rng.choice(BANKS)[1]),
                                   rel="UNKNOWN", added=added, first_time=True,
                                   verified=False, risk="HIGH")
        self.add_geo(v, self.at(off, 4, 35), "Delhi", "BENEFICIARY_ADD", vpn=True)
        ts = self.at(off, 4, 50)
        self.add_txn(v, ext_no, ts, 480000, "RTGS", "RTGS_TRANSFER", ben=ben,
                     dev=new_dev, geo_city="Delhi", geo_vpn=True)
        txn = self.txns[-1]

        dist_rows = [g for g in self.geos
                     if g["account_id"] == v and g["evidence_status"] == "AVAILABLE"]
        travel_ok = any(float(g["distance_from_last_location_km"] or 0) > 500
                        for g in dist_rows)
        self.expect(travel_ok, "AS1: impossible-travel evidence >500km (AS-004)")
        self.expect(txn["_amount"] > 3 * self.profile_avg(v),
                    f"AS1: amount {txn['_amount']:.0f} > 3x avg {self.profile_avg(v):.0f} (AS-008)")
        self.expect((ts - self.at(off, 2, 0)).total_seconds() <= 24 * 3600,
                    "AS1: txn within 24h of SIM change (AS-001)")
        self.add_gt("SCN-ASW-001", v, txn["transaction_id"], "account_swap", "NO", "", 0)

    # SCN-ASW-002: security compromise + one unusual payment, no fund-flow network
    def scenario_swap_as2(self):
        off = 5
        v = self.role["AS2_victim"]
        old_dev = self.meta[v]["primary_device"]
        new_dev = self.add_device(v, "MOBILE", trusted=False, sim=True,
                                  first_seen=self.day_end - timedelta(days=off),
                                  last_seen=self.day_end, prev=old_dev)
        self.add_geo(v, self.at(off, 8, 40), self.meta[v]["city"], "LOGIN")
        added = self.day_end - timedelta(days=off)
        ext_no = self._ext_id()
        ben = self.add_beneficiary(v, name="SUNRISE TRADERS", acct_no=ext_no,
                                   bank=self.rng.choice(BANKS)[0],
                                   ifsc=self._ifsc(self.rng.choice(BANKS)[1]),
                                   rel="UNKNOWN", added=added, first_time=True,
                                   verified=False, risk="HIGH")
        self.add_geo(v, self.at(off, 10, 50), self.meta[v]["city"], "BENEFICIARY_ADD")
        ts = self.at(off, 11, 20)
        self.add_txn(v, ext_no, ts, 210000, "IMPS", "IMPS_TRANSFER", ben=ben, dev=new_dev)
        txn = self.txns[-1]
        self.expect(txn["_amount"] > 3 * self.profile_avg(v),
                    f"AS2: amount {txn['_amount']:.0f} > 3x avg (AS-008)")
        self.add_gt("SCN-ASW-002", v, txn["transaction_id"], "account_swap", "NO", "", 0)

    # SCN-ASW-003: BOTH dimensions - compromised account used as smurf target
    def scenario_swap_both_as3(self):
        off = 11
        v = self.role["AS3_victim"]
        s8, s9, s10 = self.role["AS3_smurf1"], self.role["AS3_smurf2"], self.role["AS3_smurf3"]
        w1, w2 = self.role["AS3_out1"], self.role["AS3_out2"]
        old_dev = self.meta[v]["primary_device"]
        new_dev = self.add_device(v, "MOBILE", trusted=False, sim=True,
                                  first_seen=self.day_end - timedelta(days=off),
                                  last_seen=self.day_end, prev=old_dev)
        self.add_geo(v, self.at(off, 9, 12), self.meta[v]["city"], "DEVICE_REGISTRATION")

        legs = [(s8, 40000, self.at(off, 10, 30), "IMPS", "IMPS_TRANSFER"),
                (s9, 45000, self.at(off, 12, 45), "BRANCH", "CASH_DEPOSIT"),
                (s10, 42000, self.at(off, 15, 40), "IMPS", "IMPS_TRANSFER")]
        for s, amt, ts, ch, tt in legs:
            self.add_txn(s, v, ts, amt, ch, tt,
                         dev=self.meta[s]["primary_device"] if ch != "BRANCH" else "")
        total_in = sum(a for _, a, *_ in legs)

        added = self.day_end - timedelta(days=off)
        bid_w1 = self.beneficiary_for(v, w1, rel="UNKNOWN", added=added,
                                      first_time=True, verified=False, risk="HIGH")
        bid_w2 = self.beneficiary_for(v, w2, rel="FAMILY")   # long-known beneficiary
        out1_ts = self.at(off, 18, 30)
        self.add_txn(v, w1, out1_ts, 85000, "NEFT", "NEFT_TRANSFER", ben=bid_w1, dev=new_dev)
        out1 = self.txns[-1]
        self.add_txn(v, w2, self.at(off, 19, 10), 75000, "IMPS", "IMPS_TRANSFER",
                     ben=bid_w2, dev=new_dev)
        out2 = self.txns[-1]

        in24 = self._inbound_stats(v, out2["_ts"])
        self.expect(len({t["sender_account_id"] for t in in24}) >= 3,
                    "AS3: >=3 inbound senders (SMF-001)")
        out_total = out1["_amount"] + out2["_amount"]
        gap_h = (out1_ts - max(t["_ts"] for t in in24)).total_seconds() / 3600
        self.expect(out_total / total_in >= 0.80 and gap_h <= 6,
                    f"AS3: onward ratio {out_total / total_in:.2f} within {gap_h:.1f} h (SMF-003/007)")
        self.expect((out1_ts - self.at(off, 9, 0)).total_seconds() <= 24 * 3600,
                    "AS3: txns within 24h of SIM change (AS-001)")
        self.add_gt("SCN-ASW-003", v, out1["transaction_id"], "account_swap", "NO", "", 0)
        self.add_gt("SCN-ASW-003", v, out1["transaction_id"], "smurfing", "YES", v, 1)

    # SCN-ASW-004: compromise with limited/missing evidence
    def scenario_swap_as4(self):
        off = 3
        v = self.role["AS4_victim"]
        # baseline login with unavailable evidence, then foreign VPN activity
        self.add_geo(v, self.at(off, 22, 5), self.meta[v]["city"], "LOGIN",
                     evidence="UNAVAILABLE")
        new_dev = self.add_device(v, "WEB", trusted=False, jail=True,
                                  first_seen=self.day_end - timedelta(days=off),
                                  last_seen=self.day_end - timedelta(days=off),
                                  evidence="UNKNOWN")
        ext_no = self._ext_id()
        ts = self.at(off, 22, 45)
        self.add_txn(v, ext_no, ts, 240000, "CARD", "CARD_PURCHASE",
                     dev=new_dev, intl=True, geo_city="Dubai", geo_vpn=True,
                     geo_country="ARE")
        txn = self.txns[-1]
        geo_row = next(g for g in self.geos if g["geo_event_id"] == txn["geo_event_id"])
        self.expect(geo_row["registered_country_match"] == "FALSE"
                    and geo_row["is_vpn_or_proxy"] == "TRUE",
                    "AS4: foreign VPN auth, country mismatch (AS-005/006)")
        self.expect(txn["_amount"] > 3 * self.profile_avg(v),
                    f"AS4: amount {txn['_amount']:.0f} > 3x avg {self.profile_avg(v):.0f} (AS-008)")
        self.add_gt("SCN-ASW-004", v, txn["transaction_id"], "account_swap", "NO", "", 0)

    # --- legitimate-but-anomalous activity (single weak signals, must stay quiet) ---

    def scenario_legit_l1(self):
        off = 15
        a = self.role["L1_wedding"]
        dev = self.meta[a]["primary_device"]
        old = self.rng.sample([x for x in self.normal_pool if x != a], 4)
        rels = ["FAMILY", "FAMILY", "FRIEND", "FRIEND"]
        amounts = [(90000, "NEFT", "NEFT_TRANSFER", 0), (30000, "IMPS", "IMPS_TRANSFER", 1),
                   (55000, "IMPS", "IMPS_TRANSFER", 2), (20000, "NEFT", "NEFT_TRANSFER", 3)]
        slots = [(off, 10, 0), (off - 1, 12, 0), (off - 1, 18, 30), (off - 2, 11, 15)]
        for (amt, ch, tt, i), (o, h, m) in zip(amounts, slots):
            bid = self.beneficiary_for(a, old[i], rel=rels[i])
            self.add_txn(a, old[i], self.at(o, h, m), amt, ch, tt, ben=bid, dev=dev)

    def scenario_legit_l2(self):
        a = self.role["L2_travel"]
        home = self.meta[a]["city"]
        # new device registered 5 days before the trip, then trusted
        trip_dev = self.add_device(a, "MOBILE", trusted=True,
                                   first_seen=self.day_end - timedelta(days=24),
                                   last_seen=self.day_end)
        self.add_geo(a, self.at(24, 9, 0), home, "DEVICE_REGISTRATION")
        self.add_geo(a, self.at(20, 18, 0), home, "LOGIN")
        self.add_geo(a, self.at(19, 20, 30), "Delhi", "LOGIN")   # 26.5h later: plausible travel
        for h, amt in [(10, 4200), (15, 12500), (20, 7800)]:
            self.add_txn(a, self.ext_merchant()["acct"], self.at(19, h), amt, "CARD",
                         "CARD_PURCHASE", dev=trip_dev, geo_city="Delhi")
        self.add_txn(a, a, self.at(18, 13, 0), 8000, "ATM", "ATM_WITHDRAWAL",
                     dev=trip_dev, geo_city="Delhi")
        self.add_geo(a, self.at(16, 9, 0), home, "LOGIN")

    def scenario_legit_l3(self):
        a = self.role["L3_medical"]
        dev = self.meta[a]["primary_device"]
        ext_no = self._ext_id()
        bid = self.add_beneficiary(a, name=self.rng.choice(HOSPITALS), acct_no=ext_no,
                                   bank=self.rng.choice(BANKS)[0],
                                   ifsc=self._ifsc(self.rng.choice(BANKS)[1]),
                                   rel="UNKNOWN", added=self.today - timedelta(days=90),
                                   verified=True, risk="LOW")
        self.add_txn(a, a, self.at(8, 23, 40), 10000, "ATM", "ATM_WITHDRAWAL", dev=dev)
        self.add_txn(a, a, self.at(7, 0, 20), 10000, "ATM", "ATM_WITHDRAWAL", dev=dev)
        self.add_txn(a, a, self.at(7, 1, 5), 10000, "ATM", "ATM_WITHDRAWAL", dev=dev)
        self.add_txn(a, ext_no, self.at(7, 9, 30), 150000, "IMPS", "IMPS_TRANSFER",
                     ben=bid, dev=dev, ref="HOSPITAL-BILL")

    def scenario_nearmiss_n1(self):
        off = 12
        x = self.role["N1_target"]
        friends = [self.role["N1_friend1"], self.role["N1_friend2"]]
        for f, (h, m), amt in zip(friends, [(11, 0), (15, 30)], [60000, 55000]):
            self.add_txn(f, x, self.at(off, h, m), amt, "IMPS", "IMPS_TRANSFER",
                         dev=self.meta[f]["primary_device"])

    def scenario_nearmiss_n2(self):
        a = self.role["N2_payer"]
        partner = self.rng.choice([x for x in self.normal_pool if x != a])
        bid = self.beneficiary_for(a, partner, rel="FRIEND",
                                   added=self.today - timedelta(days=400))
        self.add_txn(a, partner, self.at(20, 14, 0), 250000, "RTGS", "RTGS_TRANSFER",
                     ben=bid, dev=self.meta[a]["primary_device"])

    # ---------------- scenario account scaffolding ----------------

    def _modest_lifestyle(self, salary=(15000, 25000)):
        rng = self.rng
        return {"salary": rng.randint(*salary), "upi": rng.randint(2, 4),
                "card": rng.randint(0, 2), "atm": rng.randint(0, 1), "out": rng.randint(0, 1)}

    def create_accounts(self):
        rng = self.rng
        # --- suspicious scenario accounts (33 total) ---
        # S1: classic smurfing chain (fund-flow only, no compromise)
        self.new_account(role="S1_target", opened_days_ago=400, city="Bengaluru",
                         segment="RETAIL", lifestyle=self._modest_lifestyle())
        for i in (1, 2, 3):
            self.new_account(role=f"S1_smurf{i}", opened_days_ago=rng.randint(200, 500),
                             segment="RETAIL", lifestyle=self._modest_lifestyle())
        self.new_account(role="S1_onward", opened_days_ago=rng.randint(60, 90),
                         segment="RETAIL", lifestyle=self._modest_lifestyle())
        self.new_account(role="S1_hop", opened_days_ago=rng.randint(30, 50),
                         segment="RETAIL", lifestyle=self._modest_lifestyle())

        # S2: smurfing with new-beneficiary onward transfer
        self.new_account(role="S2_target", opened_days_ago=350, city="Hyderabad",
                         segment="RETAIL", lifestyle=self._modest_lifestyle())
        for i in (1, 2, 3, 4):
            self.new_account(role=f"S2_smurf{i}", opened_days_ago=rng.randint(200, 500),
                             segment="RETAIL", lifestyle=self._modest_lifestyle())
        self.new_account(role="S2_receiver", opened_days_ago=rng.randint(45, 90),
                         segment="RETAIL", lifestyle=self._modest_lifestyle())

        # R1: reverse smurfing with downstream pass-through
        self.new_account(role="R1_source", opened_days_ago=300, city="Pune",
                         segment="SALARIED",
                         lifestyle={"salary": rng.randint(35000, 50000), "upi": rng.randint(3, 5),
                                    "card": rng.randint(1, 3), "atm": rng.randint(0, 1), "out": 0})
        for r in ("R1_r1", "R1_r2", "R1_r3"):
            self.new_account(role=r, opened_days_ago=rng.randint(90, 200),
                             segment="RETAIL", lifestyle=self._modest_lifestyle())
        for d in ("R1_d1", "R1_d2", "R1_d3"):
            self.new_account(role=d, opened_days_ago=rng.randint(25, 60),
                             segment="RETAIL", lifestyle=self._modest_lifestyle())

        # R2: reverse smurfing, limited evidence
        self.new_account(role="R2_source", opened_days_ago=280, city="Jaipur",
                         segment="RETAIL",
                         lifestyle={"salary": rng.randint(18000, 28000), "upi": rng.randint(2, 4),
                                    "card": rng.randint(0, 2), "atm": rng.randint(0, 1), "out": 0})
        for i in (4, 5, 6, 7):
            self.new_account(role=f"R2_r{i}", opened_days_ago=rng.randint(80, 240),
                             segment="RETAIL", lifestyle=self._modest_lifestyle())

        # AS1: full account takeover victim
        self.new_account(role="AS1_victim", opened_days_ago=900, city="Mumbai",
                         acct_type="CURRENT", segment="BUSINESS",
                         lifestyle={"salary": 45000, "rent": 18000, "upi": 4, "card": 6,
                                    "atm": 1, "out": 1})
        # AS2: compromise + single unusual payment (security-only dimension)
        self.new_account(role="AS2_victim", opened_days_ago=700, city="Nagpur",
                         segment="SALARIED",
                         lifestyle={"salary": 22000, "upi": 6, "card": 2, "atm": 1, "out": 0})
        # AS3: both dimensions (compromised AND smurf target)
        self.new_account(role="AS3_victim", opened_days_ago=600, city="Delhi",
                         segment="SALARIED",
                         lifestyle={"salary": 20000, "upi": 8, "card": 1, "atm": 1, "out": 0})
        for i in (1, 2, 3):
            self.new_account(role=f"AS3_smurf{i}", opened_days_ago=rng.randint(200, 450),
                             segment="RETAIL", lifestyle=self._modest_lifestyle())
        self.new_account(role="AS3_out1", opened_days_ago=rng.randint(50, 100),
                         segment="RETAIL", lifestyle=self._modest_lifestyle())
        self.new_account(role="AS3_out2", opened_days_ago=rng.randint(200, 400),
                         segment="RETAIL", lifestyle=self._modest_lifestyle())
        # AS4: compromise with limited evidence
        self.new_account(role="AS4_victim", opened_days_ago=800, city="Kolkata",
                         segment="SALARIED",
                         lifestyle={"salary": 30000, "upi": 3, "card": 2, "atm": 1, "out": 0})

        # --- legitimate-but-anomalous and near-miss accounts (not suspicious) ---
        self.new_account(role="L1_wedding", suspicious=False, opened_days_ago=1500,
                         city="Ahmedabad", segment="PREMIUM",
                         lifestyle={"salary": 150000, "upi": 6, "card": 6, "atm": 1, "out": 1})
        self.new_account(role="L2_travel", suspicious=False, opened_days_ago=1200,
                         city="Chennai", segment="SALARIED",
                         lifestyle={"salary": 90000, "upi": 6, "card": 4, "atm": 2, "out": 1})
        self.new_account(role="L3_medical", suspicious=False, opened_days_ago=1000,
                         city="Lucknow", segment="SALARIED",
                         lifestyle={"salary": 28000, "upi": 5, "card": 1, "atm": 2, "out": 0})
        self.new_account(role="N1_target", suspicious=False, opened_days_ago=500,
                         city="Indore", segment="SALARIED",
                         lifestyle={"salary": 25000, "upi": 5, "card": 2, "atm": 1, "out": 0})
        self.new_account(role="N1_friend1", suspicious=False, opened_days_ago=700,
                         segment="SALARIED", lifestyle=self._modest_lifestyle((40000, 55000)))
        self.new_account(role="N1_friend2", suspicious=False, opened_days_ago=650,
                         segment="SALARIED", lifestyle=self._modest_lifestyle((40000, 55000)))
        self.new_account(role="N2_payer", suspicious=False, opened_days_ago=1600,
                         city="Patna", segment="MASS_AFFLUENT",
                         lifestyle={"salary": 60000, "upi": 5, "card": 4, "atm": 1, "out": 1})

        # --- normal population fills the remainder ---
        for _ in range(self.n_accounts - len(self.role)):
            self.new_account()

    # ---------------- orchestration ----------------

    def build_static(self):
        rng = self.rng
        for name in MERCHANTS:
            bank, prefix = rng.choice(BANKS)
            self.ext_merchants.append({
                "name": name, "acct": self._ext_id(), "bank": bank,
                "ifsc": self._ifsc(prefix),
            })

    def run_all(self):
        self.build_static()
        self.create_accounts()
        for aid in list(self.accounts.keys()):
            self.gen_normal(aid)
        self.compute_profiles()
        self.scenario_smurf_s1()
        self.scenario_smurf_s2()
        self.scenario_reverse_r1()
        self.scenario_reverse_r2()
        self.scenario_swap_as1()
        self.scenario_swap_as2()
        self.scenario_swap_both_as3()
        self.scenario_swap_as4()
        self.scenario_legit_l1()
        self.scenario_legit_l2()
        self.scenario_legit_l3()
        self.scenario_nearmiss_n1()
        self.scenario_nearmiss_n2()
        self.ledger()
        self.beneficiary_totals()
        self.finish_accounts()

    def ledger(self):
        """Compute opening balances and running balance_after (sender's balance
        after debit; for credits from external senders, the receiver's balance
        after the credit)."""
        net = defaultdict(float)
        for t in self.txns:
            if t["transaction_status"] != "SUCCESS":
                continue
            s, r, amt = t["sender_account_id"], t["receiver_account_id"], t["_amount"]
            if s == r:
                net[s] -= amt
                continue
            if s in self.accounts:
                net[s] -= amt
            if r in self.accounts:
                net[r] += amt

        opening = {}
        for aid in self.accounts:
            base = self.rng.uniform(15000, 300000)
            opening[aid] = round(base + max(0.0, -net[aid]) + self.rng.uniform(10000, 90000), 2)
        bal = dict(opening)

        success = sorted((t for t in self.txns if t["transaction_status"] == "SUCCESS"),
                         key=lambda t: t["_ts"])
        for t in success:
            s, r, amt = t["sender_account_id"], t["receiver_account_id"], t["_amount"]
            if s == r:
                bal[s] -= amt
                t["balance_after"] = round(bal[s], 2)
                continue
            if s in bal:
                bal[s] -= amt
                t["balance_after"] = round(bal[s], 2)
            elif r in bal:
                bal[r] += amt
                t["balance_after"] = round(bal[r], 2)
            if s in bal and r in bal:
                bal[r] += amt

    def beneficiary_totals(self):
        counts = defaultdict(int)
        for t in self.txns:
            if t["transaction_status"] == "SUCCESS" and t["beneficiary_id"]:
                counts[t["beneficiary_id"]] += 1
        for b in self.bens:
            b["total_transfers_to_date"] = counts.get(b["beneficiary_id"], 0)

    def finish_accounts(self):
        last = {}
        for t in self.txns:
            for side in ("sender_account_id", "receiver_account_id"):
                a = t[side]
                if a in self.accounts:
                    d = t["_ts"].date()
                    if a not in last or d > last[a]:
                        last[a] = d
        for aid, row in self.accounts.items():
            row["last_activity_date"] = fmt_d(last.get(aid) or
                                              (self.today - timedelta(days=self.rng.randint(1, 30))))

    # ---------------- output ----------------

    @staticmethod
    def write_csv(path, fieldnames, rows):
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(fieldnames)
            for r in rows:
                out = []
                for k in fieldnames:
                    v = r.get(k, "")
                    if k in FMT and isinstance(v, (int, float)) and not isinstance(v, bool):
                        v = FMT[k].format(v)
                    out.append(v)
                w.writerow(out)

    def write_all(self):
        os.makedirs(self.outdir, exist_ok=True)
        os.makedirs(os.path.join(self.outdir, "evaluation"), exist_ok=True)
        self.write_csv(os.path.join(self.outdir, "accounts.csv"), SCHEMA_ACCOUNTS,
                       sorted(self.accounts.values(), key=lambda r: r["account_id"]))
        self.write_csv(os.path.join(self.outdir, "transactions.csv"), SCHEMA_TXNS,
                       sorted(self.txns, key=lambda t: t["_ts"]))
        self.write_csv(os.path.join(self.outdir, "geo_events.csv"), SCHEMA_GEO,
                       sorted(self.geos, key=lambda g: g["timestamp"]))
        self.write_csv(os.path.join(self.outdir, "devices.csv"), SCHEMA_DEVICES,
                       sorted(self.devices, key=lambda d: (d["account_id"], d["first_seen_date"])))
        self.write_csv(os.path.join(self.outdir, "beneficiaries.csv"), SCHEMA_BEN,
                       sorted(self.bens, key=lambda b: (b["account_id"], b["date_added"])))
        self.write_csv(os.path.join(self.outdir, "access_requests.csv"), SCHEMA_ACCESS, [])
        self.write_csv(os.path.join(self.outdir, "evaluation", "ground_truth_suspected_alerts.csv"),
                       SCHEMA_GT, sorted(self.gt, key=lambda g: (g["scenario_id"], g["account_id"])))

    # ---------------- validation ----------------

    def validate(self):
        errors = []
        today_midnight = datetime.combine(self.today, datetime.min.time())

        # no transaction may exist at/after the generation date
        latest = max(t["_ts"] for t in self.txns)
        if latest >= today_midnight:
            errors.append(f"transaction dated on/after generation date: {latest}")

        # unique ids
        for label, ids in [
            ("account_id", list(self.accounts.keys())),
            ("transaction_id", [t["transaction_id"] for t in self.txns]),
            ("geo_event_id", [g["geo_event_id"] for g in self.geos]),
            ("device_id", [d["device_id"] for d in self.devices]),
            ("beneficiary_id", [b["beneficiary_id"] for b in self.bens]),
            ("ground_truth_alert_id", [g["ground_truth_alert_id"] for g in self.gt]),
        ]:
            if len(ids) != len(set(ids)):
                errors.append(f"duplicate {label}")

        # referential integrity (EXT-* are external counterparties by design)
        dev_ids = {d["device_id"] for d in self.devices}
        geo_ids = {g["geo_event_id"] for g in self.geos}
        ben_ids = {b["beneficiary_id"] for b in self.bens}
        for t in self.txns:
            for side in ("sender_account_id", "receiver_account_id"):
                v = t[side]
                if v not in self.accounts and not v.startswith("EXT-"):
                    errors.append(f"txn {t['transaction_id']}: unknown {side} {v}")
            if t["device_id"] and t["device_id"] not in dev_ids:
                errors.append(f"txn {t['transaction_id']}: unknown device_id")
            if t["geo_event_id"] and t["geo_event_id"] not in geo_ids:
                errors.append(f"txn {t['transaction_id']}: unknown geo_event_id")
            if t["beneficiary_id"] and t["beneficiary_id"] not in ben_ids:
                errors.append(f"txn {t['transaction_id']}: unknown beneficiary_id")
        for g in self.geos:
            if g["account_id"] not in self.accounts:
                errors.append(f"geo {g['geo_event_id']}: unknown account")
        for d in self.devices:
            if d["account_id"] not in self.accounts:
                errors.append(f"device {d['device_id']}: unknown account")
            if d["previous_device_id"] and d["previous_device_id"] not in dev_ids:
                errors.append(f"device {d['device_id']}: unknown previous_device_id")
        for b in self.bens:
            if b["account_id"] not in self.accounts:
                errors.append(f"beneficiary {b['beneficiary_id']}: unknown account")
        for g in self.gt:
            if g["account_id"] not in self.accounts:
                errors.append(f"ground truth: unknown account {g['account_id']}")

        # scenario design checks (rulebook thresholds from Architecture.md s16)
        errors.extend(msg for ok, msg in self.checks if not ok)
        return errors

    def summary(self):
        n_total = len(self.accounts)
        n_susp = sum(1 for m in self.meta.values() if m["suspicious"])
        pct = 100.0 * n_susp / n_total
        print("=" * 64)
        print("Checkpoint 1 - Mock data generation complete")
        print("=" * 64)
        print(f"accounts.csv        {len(self.accounts):>7} rows")
        print(f"transactions.csv    {len(self.txns):>7} rows")
        print(f"geo_events.csv      {len(self.geos):>7} rows")
        print(f"devices.csv         {len(self.devices):>7} rows")
        print(f"beneficiaries.csv   {len(self.bens):>7} rows")
        print(f"access_requests.csv {0:>7} rows (created empty by design)")
        print(f"ground truth        {len(self.gt):>7} rows (evaluation-only, isolated)")
        print("-" * 64)
        print(f"suspicious-scenario accounts: {n_susp}/{n_total} = {pct:.2f}% "
              f"({'OK: within 9-10% target' if 9.0 <= pct <= 10.0 else 'WARNING: outside 9-10% target'})")
        print(f"activity window: {self.window_start} .. {self.day_end} (nothing on/after {self.today})")
        print(f"seed: {self.seed}")
        all_ok = all(ok for ok, _ in self.checks)
        print("scenario self-checks:", "ALL PASSED" if all_ok else "FAILURES PRESENT")
        for ok, msg in self.checks:
            print(f"  [{'PASS' if ok else 'FAIL'}] {msg}")


def main():
    ap = argparse.ArgumentParser(
        description="Tekmerion Intelligence - Checkpoint 1 mock data generator")
    ap.add_argument("--seed", type=int, default=42, help="random seed for reproducibility")
    ap.add_argument("--accounts", type=int, default=345,
                    help="total accounts (default keeps suspicious share at ~9-10%%)")
    ap.add_argument("--outdir", default="./mockdata", help="output directory")
    ap.add_argument("--history-days", type=int, default=150,
                    help="days of transaction history")
    args = ap.parse_args()

    gen = MockDataGenerator(args.seed, args.accounts, args.outdir, args.history_days)
    gen.run_all()
    gen.write_all()
    errors = gen.validate()
    gen.summary()
    if errors:
        print("\nVALIDATION ERRORS:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    print(f"\nOutput written to: {os.path.abspath(args.outdir)}")


if __name__ == "__main__":
    main()
