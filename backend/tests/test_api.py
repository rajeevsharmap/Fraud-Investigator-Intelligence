"""FastAPI boundary tests: auth, case listing, on-demand network."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import main as app_module
from fastapi.testclient import TestClient


def _client(mockdata_dir):
    app_module.MOCKDATA_DIR = mockdata_dir
    return TestClient(app_module.app)


def test_cases_require_role(mockdata_dir):
    with _client(mockdata_dir) as client:
        assert client.get("/cases").status_code == 401
        r = client.get("/cases", headers={"X-Investigator-Role": "INTERN"})
        assert r.status_code == 401


def test_junior_sees_cases(mockdata_dir):
    with _client(mockdata_dir) as client:
        r = client.get("/cases", headers={"X-Investigator-Role": "JUNIOR"})
        assert r.status_code == 200
        body = r.json()
        assert body["role"] == "JUNIOR"
        assert body["count"] >= 3
        assert all(c["status"] == "JUNIOR" for c in body["cases"])


def test_case_detail_with_alerts(mockdata_dir):
    with _client(mockdata_dir) as client:
        cases = client.get("/cases", headers={"X-Investigator-Role": "JUNIOR"}).json()["cases"]
        case_id = cases[0]["case_id"]
        r = client.get(f"/cases/{case_id}", headers={"X-Investigator-Role": "JUNIOR"})
        assert r.status_code == 200
        body = r.json()
        assert body["case"]["case_id"] == case_id
        assert len(body["alerts"]) == len(body["case"]["alert_ids"].split(","))


def test_network_on_demand_for_selected_case(mockdata_dir):
    with _client(mockdata_dir) as client:
        cases = client.get("/cases", headers={"X-Investigator-Role": "JUNIOR"}).json()["cases"]
        target = next(c for c in cases if c["primary_trigger"] == "smurfing")
        r = client.get(f"/cases/{target['case_id']}/network",
                       headers={"X-Investigator-Role": "JUNIOR"})
        assert r.status_code == 200
        net = r.json()
        assert net["case_account"] == target["account_id"]
        assert net["elements"]
        assert net["window"]["max_depth"] == 3


def test_unknown_case_404(mockdata_dir):
    with _client(mockdata_dir) as client:
        r = client.get("/cases/CASE-NOPE/network",
                       headers={"X-Investigator-Role": "SENIOR"})
        assert r.status_code == 404


def test_detection_pipeline_can_be_retriggered(mockdata_dir):
    with _client(mockdata_dir) as client:
        r = client.post("/detection/run")
        assert r.status_code == 200
        assert r.json()["cases"] >= 3
