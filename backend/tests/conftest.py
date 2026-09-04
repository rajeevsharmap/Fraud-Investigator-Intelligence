"""Shared fixtures: a small deterministic banking dataset in tmp dirs."""
from __future__ import annotations

import csv
import os
from datetime import datetime

import pytest

DAY = "2025-06-10"
BASE = 20000.0  # avg_monthly_txn_amount for every fixture account

ACCOUNTS = ["ACC-A", "ACC-B", "ACC-C", "ACC-D", "ACC-E",
            "ACC-S1", "ACC-S2", "ACC-S3",
            "ACC-P", "ACC-Q1", "ACC-Q2", "ACC-Q3", "ACC-Q4",
            "ACC-V", "ACC-W", "ACC-N"]


def _write(path, fieldnames, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def _ts(h, m=0):
    return f"{DAY} {h:02d}:{m:02d}:00"


@pytest.fixture(scope="session")
def mockdata_dir(tmp_path_factory):
    d = tmp_path_factory.mktemp("mockdata")

    # --- accounts ---
    acc_rows = [{"account_id": a, "customer_id": f"CUS-{a}", "customer_name": f"Cust {a}",
                 "account_type": "SAVINGS", "account_status": "ACTIVE",
                 "account_open_date": "2024-01-01", "kyc_status": "VERIFIED",
                 "risk_rating": "LOW", "registered_country": "INDIA",
                 "avg_monthly_txn_count": 10, "avg_monthly_txn_amount": BASE,
                 "home_branch": "HDFC0000001", "occupation": "Engineer",
                 "annual_income": 1000000, "customer_segment": "SALARIED",
                 "last_activity_date": DAY}
                for a in ACCOUNTS]
    _write(d / "accounts.csv",
           ["account_id", "customer_id", "customer_name", "account_type", "account_status",
            "account_open_date", "kyc_status", "risk_rating", "registered_country",
            "avg_monthly_txn_count", "avg_monthly_txn_amount", "home_branch", "occupation",
            "annual_income", "customer_segment", "last_activity_date"], acc_rows)

    # --- transactions ---
    txn_rows = []
    n = [0]

    def add(s, r, h, amt, ttype, channel, m=0, device="", ben="", status="SUCCESS"):
        n[0] += 1
        txn_rows.append({
            "transaction_id": f"TXN-T{n[0]:04d}", "sender_account_id": s,
            "receiver_account_id": r, "timestamp": _ts(h, m), "amount": f"{amt:.2f}",
            "currency": "INR", "transaction_type": ttype, "channel": channel,
            "beneficiary_id": ben, "device_id": device,
            "geo_event_id": "", "is_international": "FALSE", "balance_after": "",
            "transaction_status": status, "payment_reference": f"REF{n[0]}"})

    # smurfing: S1..S3 fragment into A; A passes 80% onward to B; B to C (depth 2)
    add("ACC-S1", "ACC-A", 10, 50000, "IMPS_TRANSFER", "IMPS")
    add("ACC-S2", "ACC-A", 11, 48000, "IMPS_TRANSFER", "IMPS")
    add("ACC-S3", "ACC-A", 12, 52000, "IMPS_TRANSFER", "IMPS")
    add("ACC-A", "ACC-B", 14, 120000, "NEFT_TRANSFER", "NEFT")
    add("ACC-B", "ACC-C", 15, 100000, "IMPS_TRANSFER", "IMPS")
    # extend the chain to 4 hops from A to exercise the depth cap
    add("ACC-C", "ACC-D", 16, 50000, "IMPS_TRANSFER", "IMPS")
    add("ACC-D", "ACC-E", 17, 40000, "IMPS_TRANSFER", "IMPS")
    # reverse smurfing: P distributes to Q1..Q3; Q1 passes on within 2h
    add("ACC-P", "ACC-Q1", 9, 100000, "IMPS_TRANSFER", "IMPS")
    add("ACC-P", "ACC-Q2", 9, 100000, "IMPS_TRANSFER", "IMPS", m=30)
    add("ACC-P", "ACC-Q3", 10, 100000, "IMPS_TRANSFER", "IMPS")
    add("ACC-Q1", "ACC-Q4", 11, 80000, "IMPS_TRANSFER", "IMPS")
    # account swap: V makes one large payment to a first-time external payee
    # from a new untrusted SIM-changed device
    add("ACC-V", "EXT-X", 4, 300000, "IMPS_TRANSFER", "IMPS",
        device="DEV-V2", ben="BEN-V1")
    # single unusual payment from a trusted device to a known payee: no alert
    add("ACC-W", "EXT-Y", 10, 250000, "IMPS_TRANSFER", "IMPS", device="DEV-W1")
    # plain normal activity
    add("EXT-EMP", "ACC-N", 9, 30000, "SALARY_CREDIT", "NEFT")
    add("ACC-N", "EXT-M", 12, 1000, "UPI_MERCHANT", "UPI")
    _write(d / "transactions.csv",
           ["transaction_id", "sender_account_id", "receiver_account_id", "timestamp",
            "amount", "currency", "transaction_type", "channel", "beneficiary_id",
            "device_id", "geo_event_id", "is_international", "balance_after",
            "transaction_status", "payment_reference"], txn_rows)

    # --- devices ---
    dev_rows = [
        {"device_id": "DEV-V1", "account_id": "ACC-V", "device_type": "MOBILE",
         "os": "Android 14", "device_fingerprint": "fp-v1", "first_seen_date": "2025-01-01",
         "last_seen_date": DAY, "is_trusted_device": "TRUE", "sim_change_detected": "FALSE",
         "jailbroken_rooted": "FALSE", "device_status": "ACTIVE", "previous_device_id": "",
         "evidence_status": "AVAILABLE"},
        {"device_id": "DEV-V2", "account_id": "ACC-V", "device_type": "MOBILE",
         "os": "Android 14", "device_fingerprint": "fp-v2", "first_seen_date": DAY,
         "last_seen_date": DAY, "is_trusted_device": "FALSE", "sim_change_detected": "TRUE",
         "jailbroken_rooted": "FALSE", "device_status": "ACTIVE",
         "previous_device_id": "DEV-V1", "evidence_status": "AVAILABLE"},
        {"device_id": "DEV-W1", "account_id": "ACC-W", "device_type": "MOBILE",
         "os": "iOS 17", "device_fingerprint": "fp-w1", "first_seen_date": "2025-01-01",
         "last_seen_date": DAY, "is_trusted_device": "TRUE", "sim_change_detected": "FALSE",
         "jailbroken_rooted": "FALSE", "device_status": "ACTIVE", "previous_device_id": "",
         "evidence_status": "AVAILABLE"},
    ]
    _write(d / "devices.csv",
           ["device_id", "account_id", "device_type", "os", "device_fingerprint",
            "first_seen_date", "last_seen_date", "is_trusted_device", "sim_change_detected",
            "jailbroken_rooted", "device_status", "previous_device_id", "evidence_status"],
           dev_rows)

    # --- geo events (impossible travel for V: 1200 km within 2h) ---
    geo_rows = [
        {"geo_event_id": "GEO-V1", "account_id": "ACC-V", "timestamp": _ts(2),
         "ip_address": "49.1.2.3", "city": "Mumbai", "state": "Maharashtra",
         "country": "INDIA", "latitude": "19.076000", "longitude": "72.877700",
         "is_vpn_or_proxy": "FALSE", "distance_from_last_location_km": "0.0",
         "registered_country_match": "TRUE", "event_type": "LOGIN",
         "evidence_status": "AVAILABLE"},
        {"geo_event_id": "GEO-V2", "account_id": "ACC-V", "timestamp": _ts(4),
         "ip_address": "45.1.2.3", "city": "Delhi", "state": "Delhi",
         "country": "INDIA", "latitude": "28.613900", "longitude": "77.209000",
         "is_vpn_or_proxy": "TRUE", "distance_from_last_location_km": "1200.0",
         "registered_country_match": "TRUE", "event_type": "TRANSACTION_AUTH",
         "evidence_status": "AVAILABLE"},
    ]
    _write(d / "geo_events.csv",
           ["geo_event_id", "account_id", "timestamp", "ip_address", "city", "state",
            "country", "latitude", "longitude", "is_vpn_or_proxy",
            "distance_from_last_location_km", "registered_country_match", "event_type",
            "evidence_status"], geo_rows)

    # --- beneficiaries ---
    ben_rows = [
        {"beneficiary_id": "BEN-V1", "account_id": "ACC-V", "beneficiary_name": "New Payee",
         "beneficiary_account_number": "EXT-X", "beneficiary_bank": "ICICI Bank",
         "beneficiary_ifsc": "ICIC0000001", "relationship_to_account_holder": "UNKNOWN",
         "date_added": DAY, "is_first_time_beneficiary": "TRUE", "is_verified": "FALSE",
         "beneficiary_risk_flag": "HIGH", "total_transfers_to_date": 1,
         "evidence_status": "AVAILABLE"},
        {"beneficiary_id": "BEN-W1", "account_id": "ACC-W", "beneficiary_name": "Old Payee",
         "beneficiary_account_number": "EXT-Y", "beneficiary_bank": "HDFC Bank",
         "beneficiary_ifsc": "HDFC0000001", "relationship_to_account_holder": "FAMILY",
         "date_added": "2024-06-01", "is_first_time_beneficiary": "FALSE",
         "is_verified": "TRUE", "beneficiary_risk_flag": "NONE",
         "total_transfers_to_date": 1, "evidence_status": "AVAILABLE"},
    ]
    _write(d / "beneficiaries.csv",
           ["beneficiary_id", "account_id", "beneficiary_name", "beneficiary_account_number",
            "beneficiary_bank", "beneficiary_ifsc", "relationship_to_account_holder",
            "date_added", "is_first_time_beneficiary", "is_verified", "beneficiary_risk_flag",
            "total_transfers_to_date", "evidence_status"], ben_rows)

    # access_requests.csv exists but stays empty (created dynamically later)
    _write(d / "access_requests.csv", ["request_id"], [])

    return str(d)


@pytest.fixture(scope="session")
def run_results(mockdata_dir):
    """Run the pipeline once on the fixture dataset."""
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from detection.pipeline import run_pipeline
    alerts, cases = run_pipeline(mockdata_dir, run_at=datetime(2025, 6, 11, 9, 0, 0))
    return alerts, cases
