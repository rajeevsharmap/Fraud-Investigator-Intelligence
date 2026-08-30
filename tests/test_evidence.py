"""Checkpoint 3 tests: evidence bundling per case + PII masking."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.loader import BankData
from evidence.builder import EvidenceBuilder
from evidence.sanitizer import PIISanitizer, DROP_FIELDS


def _package(mockdata_dir, run_results, acc="ACC-A", role="JUNIOR"):
    alerts, cases = run_results
    case = next(c for c in cases if c["account_id"] == acc)
    builder = EvidenceBuilder(BankData(mockdata_dir),
                              os.path.join(mockdata_dir, "evidence"))
    raw = builder.build(case, [a for a in alerts if a["account_id"] == acc])
    return PIISanitizer().mask_package(raw, role), raw


def _walk_keys(obj):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k
            yield from _walk_keys(v)
    elif isinstance(obj, list):
        for x in obj:
            yield from _walk_keys(x)


def test_evidence_grouped_by_case(mockdata_dir, run_results):
    pkg, _ = _package(mockdata_dir, run_results)
    assert pkg["case_id"]
    assert pkg["case"]["primary_trigger"] == "smurfing"
    assert len(pkg["alerts"]) >= 2                       # bundled alerts present
    assert len(pkg["transactions"]) >= 4                 # 3 inbound + 1 onward
    assert {"IN", "OUT"} == {t["direction"] for t in pkg["transactions"]}
    assert pkg["network"]["stats"]["nodes"] >= 6         # network output attached
    assert pkg["network"]["edges"]
    assert pkg["generated_at"]


def test_ids_masked_to_consistent_aliases(mockdata_dir, run_results):
    pkg, raw = _package(mockdata_dir, run_results)
    # focal account is the first id encountered -> ACC-0001
    assert pkg["account"]["account_id"] == "ACC-0001"
    assert raw["account"]["account_id"] == "ACC-A"       # raw had the real id
    dump = json.dumps(pkg)
    for raw_id in ("ACC-A", "ACC-B", "ACC-S1", "TXN-T0001"):   # nothing raw leaks
        assert raw_id not in dump
    # aliases are used consistently across sections
    assert pkg["network"]["nodes"][0] == "ACC-0001" or "ACC-0001" in pkg["network"]["nodes"]
    assert all(t["transaction_id"].startswith("TXN-") for t in pkg["transactions"])


def test_no_pii_fields_in_llm_package(mockdata_dir, run_results):
    pkg, _ = _package(mockdata_dir, run_results, role="SENIOR")
    keys = set(_walk_keys(pkg))
    assert not (keys & DROP_FIELDS)                      # no direct identifiers


def test_role_aware_masking(mockdata_dir, run_results):
    junior, _ = _package(mockdata_dir, run_results, role="JUNIOR")
    senior, _ = _package(mockdata_dir, run_results, role="SENIOR")
    assert junior["role"] == "JUNIOR" and senior["role"] == "SENIOR"
    assert junior["pii_sanitized"] and senior["pii_sanitized"]
    # restricted KYC detail is withheld from Junior, released to Senior
    assert "kyc_status" not in set(_walk_keys(junior))
    assert "kyc_status" in set(_walk_keys(senior))


def test_sanitizer_aliases_are_stable_and_idempotent():
    s = PIISanitizer()
    a1 = s.alias("ACC-DFJNW23")
    a2 = s.alias("ACC-DFJNW23")
    assert a1 == a2 == "ACC-0001"
    assert s.alias("ACC-K9P3XA") == "ACC-0002"
    # already-aliased values pass through untouched (pure-digit bodies)
    assert s.sanitize_text("link ACC-0001 to ACC-DFJNW23") == "link ACC-0001 to ACC-0001"


def test_evidence_persisted_and_fetchable(mockdata_dir, run_results):
    alerts, cases = run_results
    case = next(c for c in cases if c["account_id"] == "ACC-A")
    builder = EvidenceBuilder(BankData(mockdata_dir),
                              os.path.join(mockdata_dir, "evidence"))
    path = builder.save({"case_id": case["case_id"], "stub": True})
    assert os.path.exists(path)
    with open(path, encoding="utf-8") as f:
        assert json.load(f)["case_id"] == case["case_id"]
