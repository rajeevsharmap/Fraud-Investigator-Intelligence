# Fraud-Investigator-Intelligence (Tekmerion Intelligence)

Autonomous, multi-agent financial-crime investigation system for an Indian
banking context. See `Architecture.md` for the full system design.

## Status

| Checkpoint | Scope | Status |
| ---------- | ----- | ------ |
| 1 | Mock Data Generator | **Complete** (`generate_mockdata.py`, data in `mockdata/`) |
| 2 | Rule-Based Detection & Network Layer | **Complete** (`detection/`, `main.py`) |
| 3 | PII Sanitizer & Evidence Builder | **Complete** (`evidence/`) |
| 4 | Three Grok-based LLM Agents | **Complete** (`agents/`, Groq provider layer in `agents/llm_client.py`) |
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

## Checkpoint 2 — Rule-Based Detection & Network Layer

### Layout

```
detection/
  rulebook.py       the 24 rules from Architecture.md §16, verbatim scores
  loader.py         CSV loader with per-account time-indexed transfer lists
  detector.py       Detection Agent: evaluates every account, deterministic
  case_intake.py    bundles one account's alerts into a single case (status JUNIOR)
  pipeline.py       entry point: run detection -> write cases.csv / suspected_alerts.csv
  network_layer.py  on-demand NetworkX graph (<= 3 hops) + Cytoscape.js JSON
main.py             FastAPI service boundary
tests/              pytest suite (detection, network, API)
```

### Execution model (MVP requirement)

- The Detection pipeline runs **at application startup** (and via
  `POST /detection/run`) — never when an investigator opens the dashboard.
- `GET /cases` **reads the already-generated cases** and returns only cases
  authorized for the caller's role (`X-Investigator-Role: JUNIOR|SENIOR`;
  Junior sees the Junior queue).
- The Network Layer is **on demand per case**: `GET /cases/{case_id}/network`
  builds the ≤3-hop fund-flow graph plus the security timeline for that case
  and returns Cytoscape.js elements.

### Run

```
python -m detection.pipeline            # standalone pipeline run
uvicorn main:app --reload               # API (runs detection at startup)

# try it:
curl -H "X-Investigator-Role: JUNIOR" http://127.0.0.1:8000/cases
curl -H "X-Investigator-Role: JUNIOR" http://127.0.0.1:8000/cases/<case_id>/network
python -m pytest tests/ -q
```

### Results on the committed dataset (seed 42)

- 14 cases from 345 accounts; **12/12 ground-truth expected alert accounts
  detected** (smurfing chains, reverse-smurfing sources, all 4 account-swap
  victims) with 2 borderline false positives (payroll-like distribution and a
  profile-deviation + chain combination) — realistic noise for the LLM layer
  to assess in Checkpoint 4.
- Detection gating per §17: ≥2 qualifying rules per network typology (plus a
  core/distribution-side signal), security+transaction context for
  account_swap; no `money_mule` typology exists anywhere.
- Every new case is assigned `status=JUNIOR`; escalation comes later.

## Checkpoint 3 — Evidence Builder + PII Sanitizer

`evidence/builder.py` groups all evidence for one case (CASE_ID): case
metadata, account profile, bundled alerts with rule evidence, in/out
transactions in the alert window, devices, geo events, used beneficiaries,
network output (≤3 hops) and the security timeline.

`evidence/sanitizer.py` is the hard PII boundary before anything reaches an
LLM:

- consistent per-case aliases: `ACC-DFJNW23 -> ACC-0001`, `TXN-... -> TXN-0001`, ...
- direct identifiers never enter the package (customer/beneficiary names,
  account numbers, IFSC, occupation, income, IPs, coordinates, fingerprints)
- role-aware: JUNIOR additionally loses restricted KYC/beneficiary detail

Flow: authenticated investigator presses **Start Investigation** ->
`POST /cases/{case_id}/investigate` -> bundles, sanitizes, persists the
package to `mockdata/evidence/{case_id}.json` and returns it together with
the pending handoff (`scammer_hypothesis`, `legitimate_hypothesis`,
`contradiction` - consumed in Checkpoint 4). Stored packages are fetchable
via `GET /cases/{case_id}/evidence`.

## Checkpoint 4 — Three LLM Hypothesis Agents

### Layout

```
agents/
  llm_client.py   isolated provider layer (Groq, OpenAI-compatible) + robust JSON parsing
  prompts.py      the three system prompts (JSON-only, never invent evidence)
  hypothesis.py   scammer / legitimate / contradiction agents
  pipeline.py     orchestration: mask -> parallel hypotheses -> contradiction -> demask
static/index.html minimal MVP frontend (role, case list, Start Investigation, results)
tests/test_agents.py masking boundary, parallelism, ordering, demasking, API (fake client)
```

### Execution model (MVP requirement)

Pressing **Start Investigation** (`POST /cases/{case_id}/investigate`) runs:

1. Evidence Builder assembles the case evidence (raw).
2. PII Sanitizer **masks** it — one sanitizer instance per case, so its alias
   map doubles as the demask key.
3. **Scammer + Legitimate agents run in parallel** (`asyncio.gather`) on the
   masked package only.
4. When **both** responses have arrived they are passed, with the masked
   evidence, to the **Contradiction Agent**, which returns a verdict
   (`SCAMMER` / `LEGITIMATE` / `INCONCLUSIVE`).
5. All three responses are **demasked** (aliases -> raw ids) and stored to
   `mockdata/investigations/{case_id}.json` for frontend display.

Agents see **only masked evidence**; raw ids never leave the PII boundary, and
demasking happens exclusively after responses return.

### Endpoints

```
POST /cases/{case_id}/investigate    run the full agent pipeline (returns the demasked result)
GET  /cases/{case_id}/investigation  fetch the stored result (frontend display)
GET  /                               minimal MVP frontend
```

### Configuration

The provider is isolated behind `agents/llm_client.py`, so the model/provider
can be swapped without touching the investigation pipeline. Credentials and
model come from environment variables (`.env`, git-ignored):

```
GROQ_API_KEY=...                     # required
GROQ_MODEL=llama-3.1-8b-instant      # optional, fastest working model first (MVP)
```

Tests use a fake LLM client — the suite never makes live API calls.

### Run

```
uvicorn main:app --reload
# open http://127.0.0.1:8000/ , pick a role + case, press Start Investigation
python -m pytest tests/ -q
```
