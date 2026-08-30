# Fraud-Investigator-Intelligence (Tekmerion Intelligence)

Autonomous, multi-agent financial-crime investigation system for an Indian
banking context. See `Architecture.md` for the full system design.

## Status

| Checkpoint | Scope | Status |
| ---------- | ----- | ------ |
| 1 | Mock Data Generator | **Complete** (`generate_mockdata.py`, data in `mockdata/`) |
| 2 | Rule-Based Detection & Network Layer | **Complete** (`detection/`, `main.py`) |
| 3 | PII Sanitizer & Evidence Builder | **Complete** (`evidence/`) |
| 4 | Three Grok-based LLM Agents | **Complete (MVP)** (`agents/`; Grok via API key, deterministic offline fallback) |
| 5 | Regulatory Compliance & Investigation Auditor | **Complete (MVP)** (`regulatory/`, `audit/auditor.py`) |
| 6 | Next-Best-Action, Audit Trail, Human Review | **Complete (MVP)** (`audit/next_best_action.py`, `audit/trail.py`, escalation endpoint) |
| 7 | SAR Report & Case Memory | **Complete** (`reports/sar.py`, `POST /cases/{id}/sar-report`) |

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

## Checkpoint 4 — Three Grok-Based LLM Agents (MVP)

`agents/grok_client.py` is the isolated provider boundary (Architecture.md
§24): the key comes from `GROK_API_KEY` in `.env` and the rest of the
pipeline never touches the API. `agents/hypothesis_agents.py` implements the
Scammer, Legitimate and Contradiction agents; each receives ONLY the
PII-sanitized evidence package and returns structured JSON.

- With `GROK_API_KEY` set, Grok produces the analysis (JSON-validated,
  temperature 0.2).
- Without a key (or on API/JSON failure) a **deterministic fallback** runs:
  it only recombines fields already in the package (alert scores, network
  stats, security signals, baselines) and never invents evidence. This keeps
  the full architecture testable offline — accuracy improves by swapping in
  the real model, not by changing the pipeline.

`POST /cases/{case_id}/investigate` now returns the sanitized package plus
the three agent replies (persisted to `mockdata/evidence/{case_id}_agents.json`).

## Checkpoint 5 — Regulatory Compliance & Investigation Auditor (MVP)

`regulatory/rules_engine.py` — **deterministic, India-specific** rule engine.
LLM output is analysis input only and can never override it:

| Rule | Trigger | Citation |
| ---- | ------- | -------- |
| REG-PMLA-001 | STR warranted (alert score >= 45 or strong scammer verdict) | PMLA 2002 s.13; PMLA Records Rules 2015 r.3 |
| REG-CTR-002 | aggregate cash >= Rs 10 lakh in window | PMLA Records Rules 2015 r.3 (CTR) |
| REG-FEMA-003 | international transactions | FEMA 1999; RBI LRS Master Direction |
| REG-RBI-004 | single UPI txn > Rs 1 lakh | NPCI UPI guidelines |
| REG-KYC-005 | KYC missing/pending/failed | RBI KYC Master Direction 2016 |
| REG-RBI-006 | outbound/inbound >= 0.80 (layering) | RBI mule-account advisories |
| REG-ACCT-007 | account < 90 days old, outflow >= 3x baseline | RBI new-account monitoring |

`regulatory/rag.py` — India-only RAG over a curated corpus (PMLA, RBI KYC
Master Direction, FEMA/LRS, NPCI UPI, RBI mule/takeover advisories). Pure
stdlib keyword retrieval; output is supporting context with citations, never
an authorization mechanism.

`audit/auditor.py` — rule-based Investigation Auditor: weighted evidence
checklist -> completeness score 0–100 (investigation completeness, NOT fraud
probability) -> routing (COMPLETE / MORE_EVIDENCE_REQUIRED /
ESCALATION_REQUIRED) plus a Junior->Senior escalation flag when restricted
information is needed.

## Checkpoint 6 — Next-Best-Action, Audit Trail, Human Review (MVP)

- `audit/next_best_action.py` — deterministic ladder: ESCALATE (auditor
  routing/escalation flag) > BLOCK (scammer verdict + STR warranted +
  complete investigation) > CLEAR (legitimate + no critical finding) >
  MONITOR (default residual suspicion). The LLM recommends; rules decide.
- `audit/trail.py` — append-only `mockdata/audit_trail.csv` (EVT-* events for
  agent runs, analyses, escalations); readable per case via
  `GET /cases/{case_id}/audit-trail`.
- `POST /cases/{case_id}/escalate` — Junior-only human action; appends a row
  to `mockdata/case_escalation.csv` (starts empty, populated only on a real
  escalation event per Architecture.md §29) and moves the case to the Senior
  queue. Original case history is preserved.

### Dashboard-facing API (Checkpoints 5+6)

```
POST /cases/{case_id}/investigate   evidence + three agent replies
POST /cases/{case_id}/analysis      full chain: agents -> regulatory -> RAG
                                    -> auditor -> NBA (dashboard payload)
GET  /cases/{case_id}/analysis      fetch stored analysis
GET  /cases/{case_id}/audit-trail   case audit history
POST /cases/{case_id}/escalate      Junior -> Senior escalation
```

All endpoints enforce `X-Investigator-Role` server-side. Run one case
end-to-end:

```
curl -X POST -H "X-Investigator-Role: JUNIOR" http://127.0.0.1:8000/cases/<case_id>/investigate
curl -X POST -H "X-Investigator-Role: JUNIOR" http://127.0.0.1:8000/cases/<case_id>/analysis
```

Tests for the new layers live in `tests/test_regulatory_audit.py`
(regulatory determinism, RAG citations, auditor scoring, NBA ladder,
audit trail, and a regression test that an LLM verdict cannot suppress an
STR finding).

## Checkpoint 7 - SAR Report (final step)

`reports/sar.py` finalizes an investigation:

1. **LLM-based SAR narrative** - Grok summarizes the complete dossier
   (sanitized evidence, the three hypothesis-agent responses, regulatory
   findings, RAG references, auditor result, next-best-action, audit trail)
   into executive summary, suspicious-activity narrative, subject analysis
   and assessment conclusion. Facts only - the prompt forbids inventing
   evidence.
2. **Password-protected PDF** (`mockdata/reports/SAR_{case_id}.pdf`,
   reportlab + pypdf). The password is the account holder's account id last
   four digits; the API response returns an explicit alert stating this
   format (and the value for the generated report).
3. **Audit-ready lifecycle** - the finalized case moves into
   `audit_ready_cases.csv` (with completeness score, NBA action and report
   path) and its status becomes `SAR_READY` in `cases.csv`. A
   `SAR_GENERATED` event is appended to the audit trail.

Frontend flow (backend implemented): Junior or Senior presses the
**SAR Report** button -> `POST /cases/{case_id}/sar-report` (requires the
case to have evidence + analysis) -> returns report path, password and the
alert message.

Note: the LLM layer is strictly online (no offline fallback). The provider
endpoint/model/key are env-configurable via `.env` (`GROK_API_KEY`,
`GROK_API_URL`, `GROK_MODEL`), so any OpenAI-compatible endpoint (x.ai
Grok, Groq, ...) can be used without touching the pipeline.
