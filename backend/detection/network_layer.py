"""Network Layer (Architecture.md section 18) - on demand, per case.

Builds a NetworkX graph around the case account using a time window centred
on the case's alert window. Maximum traversal depth: 3 hops. Returns
Cytoscape.js-ready JSON. Invoked by FastAPI when an investigator opens a
specific case - not at dashboard load.
"""
from __future__ import annotations

from datetime import timedelta

import networkx as nx

from .loader import BankData, parse_ts

MAX_DEPTH = 3
DEFAULT_WINDOW_DAYS = 14
EDGE_ATTRS = ("transaction_id", "amount", "channel", "timestamp", "transaction_type")


def _window_for(data: BankData, account_id: str, window_days: int):
    """Time window around the account's burst activity (alert evidence)."""
    rows = sorted(data.inbound[account_id] + data.outbound[account_id],
                  key=lambda x: x[0])
    if not rows:
        return None, None
    lo, hi = rows[0][0], rows[-1][0]
    pad = timedelta(days=window_days)
    return lo - pad, hi + pad


def build_case_network(data: BankData, account_id: str,
                       window_days: int = DEFAULT_WINDOW_DAYS) -> dict:
    """Directed fund-flow graph (<= 3 hops) for one case account, plus the
    security/timeline evidence used for Account Swap analysis."""
    if account_id not in data.accounts:
        raise ValueError(f"unknown account {account_id}")
    lo, hi = _window_for(data, account_id, window_days)
    g = nx.DiGraph()
    timeline = []
    root_depth = {account_id: 0}
    frontier = [account_id]

    while frontier:   # BFS up to MAX_DEPTH over internal edges in-window
        cur = frontier.pop(0)
        if root_depth[cur] >= MAX_DEPTH:
            continue
        for ts, amt, peer, tid, _bid in data.outbound[cur]:
            if lo <= ts <= hi and data.is_internal(peer):
                g.add_edge(cur, peer, **{
                    "transaction_id": tid, "amount": amt, "channel": "transfer",
                    "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                    "transaction_type": "fund_transfer"})
                if peer not in root_depth:
                    root_depth[peer] = root_depth[cur] + 1
                    frontier.append(peer)
        for ts, amt, peer, tid, _bid in data.inbound[cur]:
            if lo <= ts <= hi and data.is_internal(peer):
                g.add_edge(peer, cur, **{
                    "transaction_id": tid, "amount": amt, "channel": "transfer",
                    "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                    "transaction_type": "fund_transfer"})
                if peer not in root_depth:
                    root_depth[peer] = root_depth[cur] + 1
                    frontier.append(peer)

    # security / geo timeline for the case account (Account Swap analysis)
    for dv in data.devices_by_account[account_id]:
        timeline.append({
            "ts": dv["first_seen_date"], "kind": "DEVICE_SEEN",
            "detail": {"device_id": dv["device_id"], "type": dv["device_type"],
                       "trusted": dv["is_trusted_device"],
                       "sim_change": dv["sim_change_detected"],
                       "jailbroken": dv["jailbroken_rooted"],
                       "status": dv["device_status"]}})
    for gv in data.geos_by_account[account_id]:
        timeline.append({
            "ts": gv["timestamp"], "kind": gv["event_type"],
            "detail": {"city": gv["city"], "country": gv["country"],
                       "vpn": gv["is_vpn_or_proxy"],
                       "distance_km": gv["distance_from_last_location_km"],
                       "country_match": gv["registered_country_match"],
                       "evidence": gv["evidence_status"]}})
    timeline.sort(key=lambda e: e["ts"])

    # Cytoscape.js elements
    elements = []
    for node, attrs in g.nodes(data=True):
        elements.append({"data": {
            "id": node,
            "label": data.accounts[node]["customer_name"] if node in data.accounts else node,
            "is_case_account": node == account_id,
            "depth": root_depth.get(node, None),
            "segment": data.accounts.get(node, {}).get("customer_segment", ""),
        }})
    for u, v, attrs in g.edges(data=True):
        elements.append({"data": {
            "id": attrs["transaction_id"], "source": u, "target": v,
            "amount": attrs["amount"], "timestamp": attrs["timestamp"],
            "channel": attrs["channel"], "transaction_type": attrs["transaction_type"],
        }})

    return {
        "case_account": account_id,
        "window": {"start": lo.strftime("%Y-%m-%d %H:%M:%S"),
                   "end": hi.strftime("%Y-%m-%d %H:%M:%S"),
                   "max_depth": MAX_DEPTH},
        "stats": {"nodes": g.number_of_nodes(), "edges": g.number_of_edges(),
                  "max_reached_depth": max(root_depth.values()) if root_depth else 0},
        "elements": elements,
        "security_timeline": timeline,
    }
