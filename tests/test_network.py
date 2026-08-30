"""Network Layer tests: graph construction, depth cap, Cytoscape shape."""
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detection.loader import BankData
from detection.network_layer import build_case_network, MAX_DEPTH


def test_smurfing_network_built(mockdata_dir):
    data = BankData(mockdata_dir)
    net = build_case_network(data, "ACC-A")
    ids = {e["data"]["id"] for e in net["elements"] if "source" not in e["data"]}
    assert {"ACC-A", "ACC-B", "ACC-C", "ACC-S1", "ACC-S2", "ACC-S3"} <= ids
    assert net["stats"]["nodes"] >= 6
    assert net["stats"]["max_reached_depth"] >= 2
    assert net["case_account"] == "ACC-A"


def test_max_traversal_depth_three_hops(mockdata_dir):
    """A->B->C->D->E exists in the fixture; only up to 3 hops may be returned."""
    data = BankData(mockdata_dir)
    net = build_case_network(data, "ACC-A")
    ids = {e["data"]["id"] for e in net["elements"] if "source" not in e["data"]}
    assert "ACC-D" in ids          # depth 3
    assert "ACC-E" not in ids      # depth 4 - beyond the cap
    assert net["stats"]["max_reached_depth"] == MAX_DEPTH


def test_cytoscape_element_shape(mockdata_dir):
    data = BankData(mockdata_dir)
    net = build_case_network(data, "ACC-A")
    nodes = [e for e in net["elements"] if "source" not in e["data"]]
    edges = [e for e in net["elements"] if "source" in e["data"]]
    assert nodes and edges
    for e in edges:
        assert {"id", "source", "target", "amount", "timestamp"} <= set(e["data"])
    assert all(n["data"]["is_case_account"] is False for n in nodes
               if n["data"]["id"] != "ACC-A")
    assert any(n["data"]["is_case_account"] for n in nodes)


def test_account_swap_security_timeline(mockdata_dir):
    """Swap cases get a security/geo timeline instead of a fund-flow network."""
    data = BankData(mockdata_dir)
    net = build_case_network(data, "ACC-V")
    kinds = {e["kind"] for e in net["security_timeline"]}
    assert "DEVICE_SEEN" in kinds and "LOGIN" in kinds
    device_entries = [e for e in net["security_timeline"] if e["kind"] == "DEVICE_SEEN"]
    assert any(e["detail"]["sim_change"] == "TRUE" for e in device_entries)
    assert net["stats"]["edges"] == 0     # no fund-flow network for the swap case
