"""Detection rulebook, gating and case-bundling tests (Checkpoint 2)."""
import csv
import os


def _cases(mockdata_dir):
    with open(os.path.join(mockdata_dir, "cases.csv"), encoding="utf-8") as f:
        return {c["account_id"]: c for c in csv.DictReader(f)}


def _alerts(run_results):
    alerts, _ = run_results
    return alerts


def _case_for(cases_by_acc, acc):
    return cases_by_acc.get(acc)


def test_smurfing_target_detected(mockdata_dir, run_results):
    cases = _cases(mockdata_dir)
    case = _case_for(cases, "ACC-A")
    assert case is not None
    assert case["primary_trigger"] == "smurfing"
    signals = set(case["evidence_signals"].split(","))
    assert {"SMF-001", "SMF-002", "SMF-003", "SMF-005"} & signals
    assert case["status"] == "JUNIOR"          # new cases go to the Junior queue


def test_reverse_smurfing_source_detected(mockdata_dir, run_results):
    cases = _cases(mockdata_dir)
    case = _case_for(cases, "ACC-P")
    assert case is not None
    assert case["primary_trigger"] == "reverse_smurfing"
    signals = set(case["evidence_signals"].split(","))
    assert {"RSMF-001", "RSMF-002", "RSMF-003", "RSMF-004"} & signals


def test_account_swap_detected_with_security_and_transaction_context(mockdata_dir, run_results):
    cases = _cases(mockdata_dir)
    case = _case_for(cases, "ACC-V")
    assert case is not None
    assert case["primary_trigger"] == "account_swap"
    signals = set(case["evidence_signals"].split(","))
    assert {"AS-001", "AS-002", "AS-003", "AS-009"} <= signals


def test_single_weak_signal_does_not_alert(mockdata_dir, run_results):
    """One large payment from a trusted device to a known payee: no case."""
    cases = _cases(mockdata_dir)
    assert "ACC-W" not in cases


def test_no_money_mule_typology(run_results):
    alerts, cases = run_results
    assert all(a["typology"] != "money_mule" for a in alerts)
    assert all("money_mule" not in c["typologies"] for c in cases)
    assert all(c["primary_trigger"] != "money_mule" for c in cases)


def test_alerts_from_one_account_bundled_into_one_case(mockdata_dir, run_results):
    alerts, cases = run_results
    cases_by_acc = {c["account_id"]: c for c in cases}
    a_alerts = [a for a in alerts if a["account_id"] == "ACC-A"]
    assert len(a_alerts) >= 2
    case = cases_by_acc["ACC-A"]
    assert case["alert_ids"].split(",") == [a["alert_id"] for a in a_alerts]


def test_rule_scores_and_case_metadata(mockdata_dir, run_results):
    alerts, cases = run_results
    assert all(a["score"] > 0 for a in alerts)
    assert all(a["detected_at"] for a in alerts)
    assert all(c["created_at"] and c["bundle_reason"] for c in cases)
