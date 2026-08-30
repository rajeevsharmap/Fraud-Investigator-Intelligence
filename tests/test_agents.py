"""Checkpoint 4 tests: masking boundary, parallel hypothesis agents,
contradiction ordering, demasking, and the API endpoint (fake LLM client —
no live API calls)."""
import asyncio
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import agents.pipeline as pipeline_module
from agents.llm_client import parse_llm_json
from agents.pipeline import _demask, run_investigation
from evidence.builder import EvidenceBuilder
from evidence.sanitizer import PIISanitizer

SCAMMER_REPLY = {"hypothesis": "ACC-0001 received fragmented inbound funds and "
                 "passed them onward rapidly - consistent with smurfing.",
                 "typology_signals": {"smurfing": "strong",
                                      "reverse_smurfing": "none",
                                      "account_swap": "none"},
                 "supporting_evidence": ["multiple inbound senders"],
                 "weaknesses": [], "confidence": 0.7}

LEGITIMATE_REPLY = {"hypothesis": "ACC-0001 consolidated family transfers.",
                    "explains": ["multiple inbound transfers"],
                    "unexplained_by_legitimate_story": ["rapid onward movement"],
                    "supporting_evidence": [], "confidence": 0.4}

CONTRADICTION_REPLY = {"verdict": "SCAMMER",
                       "reasoning": "pass-through pattern is unexplained by the "
                       "legitimate story for ACC-0001.",
                       "supports_scammer": ["rapid onward transfer"],
                       "supports_legitimate": ["regular senders"],
                       "contradictions": [], "missing_evidence": ["KYC documents"],
                       "evidence_quality": "moderate", "confidence": 0.65}


class FakeLLMClient:
    """Records prompts, simulates latency, tracks concurrent calls."""

    def __init__(self):
        self.prompts: list[str] = []
        self.active = 0
        self.max_active = 0

    async def chat(self, system, user, temperature=0.2):
        self.prompts.append(user)
        self.active += 1
        self.max_active = max(self.max_active, self.active)
        await asyncio.sleep(0.05)
        self.active -= 1
        if "Scammer Hypothesis Agent" in system:
            return json.dumps(SCAMMER_REPLY)
        if "Legitimate Hypothesis Agent" in system:
            return json.dumps(LEGITIMATE_REPLY)
        return json.dumps(CONTRADICTION_REPLY)


# ---------------- unit: sanitizer roundtrip ----------------

def test_mask_demask_roundtrip():
    s = PIISanitizer()
    masked = s.sanitize_text("ACC-DFJNW23 paid BEN-H7K2LP")
    assert "ACC-DFJNW23" not in masked and "BEN-H7K2LP" not in masked
    back = _demask(masked, {a: r for r, a in s.aliases.items()})
    assert back == "ACC-DFJNW23 paid BEN-H7K2LP"


def test_demask_handles_nested_structures():
    raw = _demask({"note": "funds left TXN-0002 to ACC-0001",
                   "refs": ["GEO-0001"], "n": 3},
                  {"ACC-0001": "ACC-XYZ", "TXN-0002": "TXN-Q", "GEO-0001": "GEO-Z"})
    assert raw == {"note": "funds left TXN-Q to ACC-XYZ",
                   "refs": ["GEO-Z"], "n": 3}


def test_parse_llm_json_variants():
    assert parse_llm_json('{"a": 1}') == {"a": 1}
    assert parse_llm_json('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_llm_json('Sure! {"a": {"b": 2}} done') == {"a": {"b": 2}}


# ---------------- pipeline: parallelism, ordering, masking, demasking ----------------

def test_run_investigation_full_flow(mockdata_dir, tmp_path, run_results):
    _, cases = run_results
    case = next(c for c in cases if c["primary_trigger"] == "smurfing")
    alert_ids = set(case["alert_ids"].split(","))
    alerts = [a for a in run_results[0] if a["alert_id"] in alert_ids]
    builder = EvidenceBuilder(_data(mockdata_dir), str(tmp_path / "evidence"))
    fake = FakeLLMClient()

    result = asyncio.run(run_investigation(case, alerts, "JUNIOR", builder,
                                           client=fake,
                                           out_dir=str(tmp_path / "investigations")))

    # all three agents ran, in the required order
    assert result["status"] == "COMPLETED"
    assert set(result["agents"]) == {"scammer_hypothesis",
                                     "legitimate_hypothesis", "contradiction"}

    # scammer + legitimate ran in PARALLEL (overlapping calls observed)
    assert fake.max_active >= 2

    # every agent saw ONLY masked ids: no raw account ids in any prompt
    raw_ids = {case["account_id"]} | {alerts[0]["account_id"]}
    for prompt in fake.prompts:
        for rid in raw_ids:
            assert rid not in prompt

    # contradiction agent received BOTH hypothesis responses
    contradiction_prompt = fake.prompts[-1]
    assert "scammer_hypothesis_report" in contradiction_prompt
    assert "legitimate_hypothesis_report" in contradiction_prompt

    # responses were DEMASKED: alias ACC-0001 maps back to the real account
    serialized = json.dumps(result["agents"])
    focal_alias = "ACC-0001"
    assert focal_alias not in serialized
    assert case["account_id"] in serialized

    # result stored for the frontend
    path = os.path.join(str(tmp_path / "investigations"), f"{case['case_id']}.json")
    assert os.path.exists(path)
    with open(path, encoding="utf-8") as f:
        stored = json.load(f)
    assert stored["agents"]["contradiction"]["verdict"] == "SCAMMER"


def _data(mockdata_dir):
    from detection.loader import BankData
    return BankData(mockdata_dir)


# ---------------- API endpoint ----------------

def test_investigate_endpoint_and_result_fetch(mockdata_dir, tmp_path, run_results,
                                               monkeypatch):
    import main as app_module
    from fastapi.testclient import TestClient

    app_module.MOCKDATA_DIR = mockdata_dir
    app_module.INVESTIGATIONS_DIR = str(tmp_path / "investigations")
    monkeypatch.setattr(app_module, "GroqClient", FakeLLMClient)

    with TestClient(app_module.app) as client:
        cases = client.get("/cases",
                           headers={"X-Investigator-Role": "JUNIOR"}).json()["cases"]
        case_id = cases[0]["case_id"]
        r = client.post(f"/cases/{case_id}/investigate",
                        headers={"X-Investigator-Role": "JUNIOR"})
        assert r.status_code == 200
        body = r.json()
        assert set(body["agents"]) == {"scammer_hypothesis",
                                       "legitimate_hypothesis", "contradiction"}
        assert "ACC-0001" not in json.dumps(body["agents"])

        r2 = client.get(f"/cases/{case_id}/investigation",
                        headers={"X-Investigator-Role": "JUNIOR"})
        assert r2.status_code == 200
        assert r2.json()["case_id"] == case_id

    assert pipeline_module  # import sanity
