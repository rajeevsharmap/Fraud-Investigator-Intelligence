"""Checkpoints 5+6: regulatory engine, India RAG, auditor, NBA, trail."""
from __future__ import annotations

from datetime import datetime

from agents.hypothesis_agents import run_all
from audit.auditor import audit as run_auditor
from audit.next_best_action import next_best_action
from audit.trail import read as read_trail, record as record_event
from evidence.builder import EvidenceBuilder
from evidence.sanitizer import PIISanitizer
from regulatory.rag import retrieve
from regulatory.rules_engine import evaluate

from tests.conftest import DAY


def _case_for(cases, account_id):
    return next(c for c in cases if c["account_id"] == account_id)


def _prep(mockdata_dir, run_results, account_id, role="JUNIOR"):
    data = __import__("detection.loader", fromlist=["BankData"]).BankData(mockdata_dir)
    alerts, cases = run_results
    case = _case_for(cases, account_id)
    case_alerts = [a for a in alerts if a["account_id"] == account_id]
    raw = EvidenceBuilder(data, mockdata_dir + "/evidence").build(case, case_alerts)
    return case, PIISanitizer().mask_package(raw, role)


def test_full_chain_smurfing_case(mockdata_dir, run_results):
    alerts, cases = run_results
    case, ev = _prep(mockdata_dir, run_results, "ACC-A")
    agents = run_all(ev)                      # offline fallback (no API key)
    regulatory = evaluate(ev, agents)
    auditor = run_auditor(case, ev, agents, regulatory)
    nba = next_best_action(agents, regulatory, auditor)

    # three agents always reply, verdict is a valid enum
    assert agents["scammer_hypothesis"]["supporting_points"]
    assert agents["legitimate_hypothesis"]["supporting_points"]
    assert agents["contradiction"]["verdict"] in (
        "scammer", "legitimate", "insufficient_evidence")

    # India regulatory: strong smurfing (score > 45) => STR warranted
    assert regulatory["str_required"]
    assert "REG-PMLA-001" in regulatory["applied"]
    # layering rule fires (80% pass-through) and cites Indian sources
    assert "REG-RBI-006" in regulatory["applied"]

    # RAG returns India-only corpus docs with citations
    docs = retrieve("smurfing str fiu-ind layering rapid onward transfer")
    assert docs and all("citation" in d for d in docs)
    assert any(d["doc_id"] in ("PMLA-S13", "RBI-MULE") for d in docs)

    # auditor: completeness in range, routing valid
    assert 0 <= auditor["score"] <= 100
    assert auditor["routing"] in ("COMPLETE", "MORE_EVIDENCE_REQUIRED",
                                  "ESCALATION_REQUIRED")

    # NBA: deterministic ladder produces a valid action with a reason
    assert nba["action"] in ("CLEAR", "MONITOR", "ESCALATE", "BLOCK")
    assert nba["reason"]


def test_llm_never_overrides_regulatory(mockdata_dir, run_results):
    """Even a scammer-verdict agent output cannot clear an STR finding."""
    case, ev = _prep(mockdata_dir, run_results, "ACC-A")
    fake_agents = {"contradiction": {"verdict": "legitimate", "confidence": 0.99}}
    regulatory = evaluate(ev, fake_agents)
    # the LLM's 'legitimate' verdict cannot suppress the deterministic
    # score-based STR trigger (alert total >= 45)
    assert regulatory["str_required"]
    # but the score-based trigger stays deterministic regardless of LLM claim
    fake_agents2 = {"contradiction": {"verdict": "legitimate", "confidence": 0.0}}
    reg2 = evaluate(ev, fake_agents2)
    assert reg2["str_required"]                  # alert score still >= 45


def test_audit_trail_appends(mockdata_dir, run_results):
    case, _ = _prep(mockdata_dir, run_results, "ACC-A")
    record_event(mockdata_dir, case["case_id"], "JUNIOR", "ANALYSIS_RUN", "test")
    events = read_trail(mockdata_dir, case["case_id"])
    assert events[-1]["event_type"] == "ANALYSIS_RUN"
    assert events[-1]["case_id"] == case["case_id"]


def test_account_swap_case_runs_end_to_end(mockdata_dir, run_results):
    alerts, cases = run_results
    case = next((c for c in cases if c["account_id"] == "ACC-V"), None)
    if case is None:
        return                                    # fixture produced no swap case
    _, ev = _prep(mockdata_dir, run_results, "ACC-V")
    agents = run_all(ev)
    regulatory = evaluate(ev, agents)
    auditor = run_auditor(case, ev, agents, regulatory)
    nba = next_best_action(agents, regulatory, auditor)
    assert agents["contradiction"]["verdict"]
    assert nba["action"] in ("CLEAR", "MONITOR", "ESCALATE", "BLOCK")
