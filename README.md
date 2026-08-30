# Fraud-Investigator-Intelligence (Tekmerion Intelligence)

Autonomous, multi-agent financial-crime investigation system for an Indian
banking context. See `Architecture.md` for the full system design.

## Status

| Checkpoint | Scope | Status |
| ---------- | ----- | ------ |
| 1 | Mock Data Generator | **Complete** (`generate_mockdata.py`, data in `mockdata/`) |
| 2 | Rule-Based Detection & Network Layer | Not started |
| 3 | PII Sanitizer & Evidence Builder | Not started |
| 4 | Three Grok-based LLM Agents | Not started |
| 5 | Regulatory Compliance & Investigation Auditor | Not started |
| 6 | Next-Best-Action, Audit Trail, Human Review | Not started |
| 7 | SAR Report & Case Memory | Not started |

## Checkpoint 1 — Mock Data Generator

Generates raw banking source data only. It does **not** create cases, alerts,
escalations, or any downstream investigation output (those belong to the
Detection Agent / Case Intake stage in Checkpoint 2).

### Output

```
mockdata/
  accounts.csv                       345 accounts
  transactions.csv                   ~24.7k transactions (INR, 150-day window)
  geo_events.csv                     login/auth geo telemetry
  devices.csv                        trusted/untrusted devices, SIM changes
  beneficiaries.csv                  saved payees
  access_requests.csv                empty by design (created dynamically later)
  evaluation/
    ground_truth_suspected_alerts.csv  EVALUATION-ONLY, never read by the pipeline
```

### Scenario coverage

* Smurfing (2 scenarios: rapid onward pass-through + multi-hop; new-beneficiary onward)
* Reverse smurfing (2 scenarios: downstream pass-through 3 hops; recipients retain funds, limited evidence)
* Account swap (4 scenarios: full takeover; single unusual payment without fund-flow network; both dimensions combined; foreign-VPN compromise with missing evidence)
* Legitimate-but-anomalous (wedding payouts, international travel with new device, medical emergency) — designed to stay below alert thresholds
* Near-miss single-signal cases (2 senders only; one large transfer to a known beneficiary)
* ~9–10% of accounts participate in suspicious scenarios (33/345 = 9.57%)

All transactions are strictly dated before the generation date, IDs are
randomized (`TXN-SGW235C` style), and external counterparties use `EXT-*` ids
with no account row by design.

### Usage

```
pip install -r requirements.txt
python generate_mockdata.py                                # seed 42, 345 accounts
python generate_mockdata.py --seed 7 --accounts 500        # custom run
```

The generator validates its own output (referential integrity, unique IDs,
date boundaries, and rulebook-threshold self-checks per scenario) and exits
non-zero on failure.

### Ground truth (evaluation-only)

`mockdata/evaluation/ground_truth_suspected_alerts.csv` maps scenario
accounts/transactions to the expected typology, detection outcome, and network
involvement. It is used exclusively to evaluate Checkpoint 2 detection results.
No operational component may read it (Architecture.md §11).
