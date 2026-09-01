"""SAR PII-boundary tests (masked LLM input, backend-only restoration,
encrypted PDF, no demasked JSON at the API)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from pypdf import PdfReader

from detection.loader import BankData
from evidence.builder import EvidenceBuilder
from evidence.sanitizer import PIISanitizer, load_aliases
from reports.sar import (_compact_dossier, _build_pdf, generate, password_for,
                         resolve_aliases, resolve_narrative)

CASE_ACC = "ACC-A"


def _setup(mockdata_dir, run_results):
    """Build + persist masked evidence, analysis and alias map for one case."""
    alerts, cases = run_results
    case = next(c for c in cases if c["account_id"] == CASE_ACC)
    ev_dir = os.path.join(mockdata_dir, "evidence")
    builder = EvidenceBuilder(BankData(mockdata_dir), ev_dir)
    sanitizer = PIISanitizer()
    ev = sanitizer.mask_package(builder.build(case, alerts), "JUNIOR")
    builder.save(ev)
    al_path = os.path.join(ev_dir, f"{case['case_id']}_aliases.json")
    sanitizer.save_aliases(al_path)
    analysis = {"agents": {"contradiction": {"verdict": "scammer",
                                             "confidence": 0.8}},
                "regulatory": {"str_required": False},
                "regulatory_rag": [],
                "auditor": {"score": 80, "routing": "COMPLETE",
                            "checks": [], "missing": [], "str_required": False},
                "next_best_action": {"action": "MONITOR", "reason": "test",
                                     "inputs": {}}}
    an_path = os.path.join(ev_dir, f"{case['case_id']}_analysis.json")
    json.dump(analysis, open(an_path, "w"))
    return case, ev, analysis, load_aliases(al_path)


FAKE_NARRATIVE = {
    "executive_summary": "ACC-0001 showed rapid pass-through behaviour.",
    "suspicious_activity_narrative": "ACC-0001 received structured transfers "
                                     "referenced TXN-0001 and moved funds onward.",
    "subject_analysis": "Subject ACC-0001 deviated from baseline.",
    "assessment_conclusion": "The scammer hypothesis better fits ACC-0001; "
                             "unknown alias ACC-9999 remains as-is.",
}


def test_1_llm_receives_masked_data(mockdata_dir, run_results):
    case, ev, analysis, aliases = _setup(mockdata_dir, run_results)
    dossier = _compact_dossier(ev, analysis, [])
    dump = json.dumps(dossier)
    assert "ACC-0001" in dump and "ACC-A" not in dump
    assert "TXN-0001" in dump and "TXN-T0001" not in dump
    assert all(a.startswith(("ACC-", "TXN-")) and a[4:].isdigit()
               for a in [ev["account"]["account_id"]])


def test_2_alias_mapping_never_reaches_llm(mockdata_dir, run_results):
    case, ev, analysis, aliases = _setup(mockdata_dir, run_results)
    dossier = _compact_dossier(ev, analysis, [])
    dump = json.dumps(dossier)
    for alias, raw in aliases.items():
        assert raw not in dump            # no real ids in the LLM dossier
    assert "alias_map" not in dump and "aliases" not in dump


def test_3_backend_restoration():
    m = {"ACC-0001": "ACC-DFJNW23"}
    out = resolve_aliases("ACC-0001 received structured transfers.", m)
    assert out == "ACC-DFJNW23 received structured transfers."
    resolved = resolve_narrative(FAKE_NARRATIVE, {"ACC-0001": "ACC-DFJNW23",
                                                  "TXN-0001": "TXN-SGW235C"})
    assert "ACC-DFJNW23" in resolved["executive_summary"]
    assert "TXN-SGW235C" in resolved["suspicious_activity_narrative"]


def test_4_unknown_aliases_unchanged():
    m = {"ACC-0001": "ACC-DFJNW23"}
    out = resolve_aliases("ACC-9999 and ACC-0001 and plain text!", m)
    assert "ACC-9999" in out and "ACC-DFJNW23" in out and "plain text!" in out
    assert resolve_aliases("no aliases here", m) == "no aliases here"


def _pdf_case(mockdata_dir, run_results, tmp_path):
    case, ev, analysis, aliases = _setup(mockdata_dir, run_results)
    pdf = str(tmp_path / "SAR_test.pdf")
    resolved = resolve_narrative(FAKE_NARRATIVE, aliases)
    _build_pdf(pdf, case, case["account_id"], resolved,
               _compact_dossier(ev, analysis, []))
    return pdf, case, aliases


def test_5_pdf_contains_restored_values(mockdata_dir, run_results, tmp_path):
    pdf, case, aliases = _pdf_case(mockdata_dir, run_results, tmp_path)
    reader = PdfReader(pdf)
    reader.decrypt(password_for(case["account_id"]))
    text = "".join(p.extract_text() for p in reader.pages)
    assert aliases["ACC-0001"] in text            # real id restored into PDF
    assert "ACC-0001" not in text                 # alias gone from narrative


def test_6_pdf_is_encrypted(mockdata_dir, run_results, tmp_path):
    pdf, case, aliases = _pdf_case(mockdata_dir, run_results, tmp_path)
    reader = PdfReader(pdf)
    assert reader.is_encrypted
    # without the password the content is inaccessible
    with pytest.raises(Exception):
        "".join((p.extract_text() or "") for p in reader.pages)
    reader2 = PdfReader(pdf)
    reader2.decrypt(password_for(case["account_id"]))
    assert len(reader2.pages) >= 1


def test_7_api_returns_pdf_only(mockdata_dir, run_results, monkeypatch):
    import main as app_module
    from fastapi.testclient import TestClient
    case, ev, analysis, aliases = _setup(mockdata_dir, run_results)
    monkeypatch.setattr(app_module, "MOCKDATA_DIR", mockdata_dir)
    monkeypatch.setattr("reports.sar.sar_summary",
                        lambda dossier: dict(FAKE_NARRATIVE))   # no live LLM
    with TestClient(app_module.app) as client:
        r = client.post(f"/cases/{case['case_id']}/sar-report",
                        headers={"X-Investigator-Role": "JUNIOR"})
        assert r.status_code == 200
        assert r.headers["content-type"] == "application/pdf"
        assert r.content[:4] == b"%PDF"
        body = r.content.decode("latin-1", "ignore")
        assert "executive_summary" not in body        # no JSON narrative body
        # demasked narrative is not exposed anywhere in the response
        assert not any(k in str(r.headers) for k in ("alias", "narrative"))


def test_8_existing_behavior_still_works(mockdata_dir, run_results, tmp_path):
    """generate() end-to-end (LLM mocked) still: PDF, password, audit-ready."""
    import reports.sar as sar
    case, ev, analysis, aliases = _setup(mockdata_dir, run_results)
    sar.sar_summary = lambda dossier: dict(FAKE_NARRATIVE)
    res = generate(case, ev, analysis, [], mockdata_dir, aliases)
    assert os.path.exists(res["report_path"])
    assert res["password"] == password_for(case["account_id"])
    reader = PdfReader(res["report_path"])
    assert reader.is_encrypted
    with open(os.path.join(mockdata_dir, "audit_ready_cases.csv"),
              encoding="utf-8") as f:
        assert case["case_id"] in f.read()
    assert not os.path.exists(res["report_path"] + ".tmp")   # temp cleaned up
