# Tekmerion Intelligence — Autonomous Financial Crime Investigation System

## 1. System Objective

Tekmerion Intelligence is an autonomous, multi-agent financial-crime investigation system designed for an Indian banking context.

The system combines:

* Rule-based transaction and security detection
* Financial network analysis
* Evidence aggregation
* PII-controlled LLM investigation
* Legitimate-vs-suspicious hypothesis analysis
* Contradiction resolution
* India-specific regulatory compliance checks
* Investigation auditing
* Case completeness assessment
* Next-best-action routing
* Human investigator review
* Audit trail and action replay
* SAR-ready report generation
* Investigator-controlled case memory/reference storage

The system must remain **auditable and deterministic wherever a rule-based decision is appropriate**. Grok is used for hypothesis/reasoning tasks, not as the authoritative source for deterministic detection, compliance, routing, or investigator authorization.

---

# 2. Final Architecture

```text
                              BANK SYSTEM
                                   |
                                   | Database / CSV data access
                                   | Accounts + Transactions +
                                   | Devices + Geo + Beneficiaries
                                   ↓
                         ┌─────────────────────┐
                         │  DETECTION AGENT    │
                         │    Rule-Based       │
                         └──────────┬──────────┘
                                    |
                                    ↓
                              ANOMALY CHECK
                                    |
                     ┌──────────────┴──────────────┐
                     ↓                             ↓
                  FALSE                       SUSPECTED
                / NORMAL                       ALERT
                     |                             |
                     ↓                             ↓
              CLEAR / NO ACTION              CASE INTAKE
                                                   |
                                                   ↓
                         ┌─────────────────────────────────┐
                         │   CASE / EVIDENCE COLLECTION   │
                         └─────────────────────────────────┘
                                  |
              ┌───────────────────┼───────────────────┐
              ↓                   ↓                   ↓
       Beneficiary Agent   Transaction Agent   Device/Geo Agent
              └───────────────────┼───────────────────┘
                                  ↓
                       NETWORK GRAPH LAYER
                                  |
             ┌────────────────────┼────────────────────┐
             ↓                    ↓                    ↓
          SMURFING         REVERSE SMURFING       ACCOUNT SWAP
             |                    |                    |
             |     Money-mule / pass-through          |
             |          signals embedded              |
             └────────────────────┼────────────────────┘
                                  ↓
                         NETWORK EVIDENCE
                                  ↓
                           EVIDENCE STORE
                                  ↓
                       PII SANITIZATION BOUNDARY
                                  ↓
                  ┌───────────────┴────────────────┐
                  ↓                                ↓
        SCAMMER HYPOTHESIS                  LEGITIMATE HYPOTHESIS
             (Grok)                              (Grok)
                  |                                |
                  └───────────────┬────────────────┘
                                  ↓
                       CONTRADICTION AGENT
                              (Grok)
                                  ↓
                    REGULATORY RULE ENGINE
                                  ↓
                       REGULATORY RAG
                    India-specific context
                                  ↓
                  INVESTIGATION AUDITOR
                         Rule-Based
                                  ↓
                     CASE COMPLETENESS
                                  ↓
                       AUDITOR ROUTING
                                  ↓
                     NEXT-BEST-ACTION
                         Rule-Based
                                  ↓
                           AUDIT TRAIL
                                  ↓
                       HUMAN REVIEW
                                  ↓
                    ┌─────────────┴─────────────┐
                    ↓                           ↓
                 JUNIOR                      SENIOR
              INVESTIGATOR               INVESTIGATOR
                    |                           ↑
                    |                           |
                    └──── ESCALATION ──────────┘
                                |
                                ↓
                        INVESTIGATOR ACTION
                                |
                 ┌──────────────┼───────────────┐
                 ↓              ↓               ↓
              Clear          Monitor          Block
                                |
                           Escalate
                                |
                                ↓
                         CASE FINALIZATION
                                |
                 ┌──────────────┴──────────────┐
                 ↓                             ↓
        AUDIT-READY CASE                REFERENCE CASE
        audit_ready_cases.csv           reference_cases.csv
                 |
                 ↓
            SAR REPORT
       Password-protected PDF
```

---

# 3. Core Typology Model

Tekmerion Intelligence uses **three primary detection domains**:

```text
1. SMURFING
2. REVERSE SMURFING
3. ACCOUNT SWAP
```

There is **no separate MONEY_MULE detection typology**.

Money-mule behavior is treated as a **fund-flow behavioral signal** that strengthens Smurfing or Reverse Smurfing investigations.

## 3.1 Smurfing

Smurfing primarily represents:

```text
Multiple accounts
      ↓
Funds consolidated
      ↓
Target account
```

The target account may then rapidly transfer received funds onward.

Therefore, pass-through behavior is a **signal inside the Smurfing investigation**, rather than a separate Money Mule case.

Example:

```text
A ──┐
B ──┼──→ X ───→ Z
C ──┘
```

If X receives fragmented funds from multiple accounts and rapidly transfers a substantial portion onward, the system records:

* Smurfing signals
* Fund-flow/pass-through signal
* Network evidence

It does **not** create a separate `money_mule` typology.

---

## 3.2 Reverse Smurfing

Reverse Smurfing primarily represents:

```text
Source account
      ↓
Multiple recipient accounts
```

Example:

```text
             ┌──→ B
             |
A ───────────┼──→ C
             |
             └──→ D
```

If B/C/D subsequently transfer received funds onward, that becomes a **downstream pass-through signal** within the Reverse Smurfing investigation.

Again, no separate Money Mule case is created.

---

## 3.3 Account Swap / Account Takeover

Account Swap is independent from fund-flow typologies.

It can be detected when the account is compromised through security anomalies such as:

* SIM change
* New/untrusted device
* Device fingerprint change
* Impossible travel
* VPN/proxy
* New beneficiary
* Abnormal transaction
* Other security-compromise signals

### Important distinction

An Account Swap does **not require a fund-flow network**.

Example:

```text
Normal account
      |
      ↓
SIM change
      |
      ↓
New device
      |
      ↓
One unusual payment
      |
      ↓
Detection Agent
```

This can become an Account Swap investigation even though there is:

```text
No smurfing
No reverse smurfing
No pass-through
No multi-hop network
```

The LLM agents subsequently assess whether the payment is more consistent with:

* Account takeover
* Legitimate user activity
* Insufficient evidence

The LLM must not invent security evidence that does not exist.

---

# 4. Detection Decision Model

Detection operates through **two independent dimensions**.

## Fund-Flow Behaviour

Checks:

* Smurfing
* Reverse Smurfing
* Fragmentation
* Multiple counterparties
* Rapid onward movement
* Downstream pass-through
* Multi-hop movement
* Transaction profile deviation

## Account Security Behaviour

Checks:

* SIM change
* Device anomaly
* Device fingerprint change
* Impossible travel
* VPN/proxy
* New beneficiary
* Transaction anomaly

These dimensions must not be incorrectly conflated.

### Money-mule interpretation

For a potential mule-like account:

```text
Fund-flow behaviour
        +
Security compromise
        ↓
Possible compromised mule / mule-like activity
```

But:

```text
Security compromise WITHOUT fund-flow behaviour
        ↓
Account Swap investigation
```

And:

```text
Fund-flow behaviour WITHOUT security compromise
        ↓
Smurfing / Reverse Smurfing investigation
```

This separation is important because a compromised account can make a single payment without behaving like a mule.

---

# 5. Checkpoint 1 — Mock Data Generator

Create a Python mock-data generator.

Generated source data must be stored under:

```text
./mockdata/
```

The generator must create:

```text
accounts.csv
transactions.csv
geo_events.csv
devices.csv
beneficiaries.csv
```

It must **not create cases**.

It must **not create detection alerts**.

It must **not bundle cases**.

Case generation belongs to the Detection Agent / Case Intake stage.

---

## 5.1 Data Requirements

The dataset must contain:

* Normal activity
* Suspicious activity
* Legitimate-but-anomalous activity
* Account compromise scenarios
* Smurfing scenarios
* Reverse Smurfing scenarios
* Cases with limited evidence
* Cases with missing evidence
* Cases where security evidence exists without fund-flow behaviour
* Cases where fund-flow behaviour exists without account compromise
* Cases where both dimensions are present

All transactions must use dates **before the current generation date**.

No transaction should be generated as occurring "today."

IDs must be randomized and non-sequential.

Examples:

```text
TXN-SGW235C
CUS-ADG23R2
ACC-X7FD29A
DEV-K9P3XA
GEO-8QW21M
BEN-H7K2LP
```

Avoid:

```text
TXN000234
CUS000123
ACC000001
```

---

## 5.2 Suspicious Account Distribution

Approximately:

```text
9%–10%
```

of total accounts should participate in suspicious/alert-generating scenarios.

This is a dataset-generation target, not a detection rule.

---

# 6. accounts.csv

Schema:

```text
account_id
customer_id
customer_name
account_type
account_status
account_open_date
kyc_status
risk_rating
registered_country
avg_monthly_txn_count
avg_monthly_txn_amount
home_branch
occupation
annual_income
customer_segment
last_activity_date
```

### Access sensitivity

Senior-only or restricted fields include:

```text
customer_name
occupation
annual_income
full customer/KYC information
```

The raw dataset may contain these values, but investigator-facing access must be controlled by the PII/data-access layer.

---

# 7. transactions.csv

Schema:

```text
transaction_id
sender_account_id
receiver_account_id
timestamp
amount
currency
transaction_type
channel
beneficiary_id
device_id
geo_event_id
is_international
balance_after
transaction_status
payment_reference
```

Supported transaction channels:

```text
UPI
IMPS
NEFT
RTGS
ATM
CARD
BRANCH
```

Currency:

```text
INR
```

The MVP is India-focused and should primarily generate domestic transactions.

---

# 8. geo_events.csv

Schema:

```text
geo_event_id
account_id
timestamp
ip_address
city
state
country
latitude
longitude
is_vpn_or_proxy
distance_from_last_location_km
registered_country_match
event_type
evidence_status
```

Supported event types:

```text
LOGIN
TRANSACTION_AUTH
BENEFICIARY_ADD
DEVICE_REGISTRATION
```

Evidence status:

```text
AVAILABLE
UNAVAILABLE
UNKNOWN
```

Missing security evidence must be represented realistically rather than artificially filling every field.

---

# 9. devices.csv

Schema:

```text
device_id
account_id
device_type
os
device_fingerprint
first_seen_date
last_seen_date
is_trusted_device
sim_change_detected
jailbroken_rooted
device_status
previous_device_id
evidence_status
```

Supported device types:

```text
MOBILE
WEB
TABLET
```

Device status:

```text
ACTIVE
RETIRED
BLOCKED
```

Evidence status:

```text
AVAILABLE
UNAVAILABLE
UNKNOWN
```

---

# 10. beneficiaries.csv

Schema:

```text
beneficiary_id
account_id
beneficiary_name
beneficiary_account_number
beneficiary_bank
beneficiary_ifsc
relationship_to_account_holder
date_added
is_first_time_beneficiary
is_verified
beneficiary_risk_flag
total_transfers_to_date
evidence_status
```

Beneficiary details must be subject to the same role-based access controls as customer information.

---

# 11. Ground Truth and Evaluation

Ground truth is **evaluation-only data**.

It must never be read by:

* Detection Agent
* Network Layer
* Evidence Builder
* LLM Agents
* Investigation Auditor
* Next-Best-Action logic
* Investigator UI

Ground truth exists only for testing/evaluation.

It should contain only information necessary to evaluate whether the generated source scenario produced the expected detection/network result.

Do not add unnecessary labels merely to make the dataset appear more sophisticated.

Recommended evaluation-only schema:

```text
ground_truth_alert_id
scenario_id
account_id
transaction_id
expected_typology
expected_detection
expected_network_involvement
network_root_account_id
expected_network_depth
```

The ground-truth file is not part of the operational investigation pipeline.

---

# 12. access_requests.csv

Schema:

```text
request_id
investigator_id
investigator_role
account_id
requested_fields
reason
requested_at
status
approved_by
approved_at
access_scope
expires_at
```

For the initial MVP:

```text
access_requests.csv
```

should be created empty.

Requests are generated dynamically by investigators.

---

# 13. Investigator Access Model

All cases initially belong to the **Junior Investigator queue**.

```text
Detection
   ↓
Case
   ↓
Junior Investigator
```

A Junior Investigator may investigate using permitted information.

Restricted customer information remains masked.

If additional information is required:

```text
Junior
  ↓
Access Request
  ↓
Senior Approval
  ↓
Restricted information released
```

Alternatively, when the case itself requires escalation:

```text
Junior
  ↓
Escalate
  ↓
Senior
```

---

## Access Matrix

| Information                | Junior         | Senior  |
| -------------------------- | -------------- | ------- |
| Account ID                 | Allowed        | Allowed |
| Customer ID                | Masked/Limited | Full    |
| Customer Name              | Restricted     | Full    |
| Account Type               | Allowed        | Allowed |
| Account Status             | Allowed        | Allowed |
| Account Open Date          | Allowed        | Allowed |
| KYC Status                 | Limited        | Full    |
| Risk Rating                | Allowed        | Allowed |
| Transaction Details        | Allowed        | Allowed |
| Device Details             | Allowed        | Allowed |
| Geo Events                 | Allowed        | Allowed |
| Beneficiary Relationship   | Limited        | Full    |
| Beneficiary Name           | Masked/Limited | Full    |
| Beneficiary Account Number | Masked         | Full    |
| Occupation                 | Restricted     | Full    |
| Annual Income              | Restricted     | Full    |
| Full Customer/KYC Details  | Restricted     | Full    |

The backend must enforce these restrictions. Frontend hiding alone is insufficient.

---

# 14. Checkpoint 2 — Rule-Based Detection and Network Layer

The Detection Agent reads:

```text
accounts.csv
transactions.csv
devices.csv
geo_events.csv
beneficiaries.csv
```

It produces suspected alerts based on deterministic rules.

The Detection Agent is responsible for:

1. Detecting anomalies.
2. Classifying the primary trigger.
3. Producing suspected alerts.
4. Bundling alerts belonging to the same account/case.
5. Creating `cases.csv`.

It must never read ground truth.

---

# 15. Detection Typologies

The operational typologies are:

```text
smurfing
reverse_smurfing
account_swap
```

There is no operational:

```text
money_mule
```

typology.

Money-mule behaviour is represented through fund-flow signals inside Smurfing and Reverse Smurfing.

---

# 16. Detection Rulebook

```python
SMURFING_RULES = {

    "SMF-001": {
        "name": "multiple_inbound_counterparties",
        "description": "Account receives funds from multiple distinct accounts within a short period.",
        "condition": {
            "unique_inbound_senders": ">= 3",
            "time_window_hours": "<= 24"
        },
        "score": 15
    },

    "SMF-002": {
        "name": "fragmented_inbound_transactions",
        "description": "Multiple relatively smaller incoming transactions aggregate into a materially larger amount.",
        "condition": {
            "inbound_transaction_count": ">= 3",
            "aggregate_inbound_amount": "> account_baseline",
            "amount_variance": "low_or_moderate"
        },
        "score": 15
    },

    "SMF-003": {
        "name": "rapid_onward_transfer",
        "description": "Funds received by the account are transferred onward shortly after receipt.",
        "condition": {
            "incoming_to_outgoing_time_minutes": "<= 360",
            "outgoing_amount_ratio_of_incoming": ">= 0.70"
        },
        "score": 20
    },

    "SMF-004": {
        "name": "multiple_outbound_counterparties",
        "description": "Account distributes received funds to multiple beneficiaries or accounts.",
        "condition": {
            "unique_outbound_receivers": ">= 2",
            "time_window_hours": "<= 24"
        },
        "score": 10
    },

    "SMF-005": {
        "name": "transaction_profile_deviation",
        "description": "Current transaction activity materially exceeds the customer's normal profile.",
        "condition": {
            "current_period_amount": "> 3 * avg_monthly_txn_amount"
        },
        "score": 15
    },

    "SMF-006": {
        "name": "multi_hop_fund_flow",
        "description": "Funds can be followed through multiple connected accounts.",
        "condition": {
            "network_depth": ">= 2"
        },
        "score": 15
    },

    "SMF-007": {
        "name": "fund_retention_anomaly",
        "description": "A large proportion of received funds leaves the account shortly after receipt.",
        "condition": {
            "outgoing_incoming_ratio": ">= 0.80",
            "outgoing_after_inbound_hours": "<= 6"
        },
        "score": 20
    },

    "SMF-008": {
        "name": "new_beneficiary_after_inbound",
        "description": "Received funds are followed by a transfer to a newly added or first-time beneficiary.",
        "condition": {
            "is_first_time_beneficiary": True,
            "outgoing_after_inbound_hours": "<= 6"
        },
        "score": 10
    }
}


REVERSE_SMURFING_RULES = {

    "RSMF-001": {
        "name": "multiple_outbound_counterparties",
        "description": "One account distributes funds to multiple distinct receiving accounts.",
        "condition": {
            "unique_outbound_receivers": ">= 3",
            "time_window_hours": "<= 24"
        },
        "score": 20
    },

    "RSMF-002": {
        "name": "outbound_amount_fragmentation",
        "description": "A source amount is divided into multiple smaller transfers.",
        "condition": {
            "outbound_transaction_count": ">= 3",
            "individual_amounts": "relatively_similar"
        },
        "score": 15
    },

    "RSMF-003": {
        "name": "rapid_distribution",
        "description": "Funds are distributed to several accounts within a short period.",
        "condition": {
            "distribution_window_minutes": "<= 360"
        },
        "score": 15
    },

    "RSMF-004": {
        "name": "downstream_pass_through",
        "description": "Recipients rapidly transfer received funds onward.",
        "condition": {
            "recipient_onward_transfer_within_hours": "<= 6"
        },
        "score": 20
    },

    "RSMF-005": {
        "name": "transaction_profile_deviation",
        "description": "Distribution activity exceeds the source account's normal profile.",
        "condition": {
            "current_amount": "> 3 * avg_monthly_txn_amount"
        },
        "score": 15
    },

    "RSMF-006": {
        "name": "multi_hop_distribution_network",
        "description": "Distributed funds continue through downstream accounts.",
        "condition": {
            "network_depth": ">= 2"
        },
        "score": 15
    },

    "RSMF-007": {
        "name": "downstream_fund_retention_anomaly",
        "description": "Recipients transfer a substantial proportion of received funds onward shortly after receipt.",
        "condition": {
            "recipient_outgoing_incoming_ratio": ">= 0.70",
            "recipient_onward_transfer_within_hours": "<= 6"
        },
        "score": 20
    }
}


ACCOUNT_SWAP_RULES = {

    "AS-001": {
        "name": "sim_change",
        "description": "SIM change detected near suspicious transaction activity.",
        "condition": {
            "sim_change_detected": True,
            "transaction_within_hours": "<= 24"
        },
        "score": 25
    },

    "AS-002": {
        "name": "new_device",
        "description": "Transaction occurs from a previously unseen or untrusted device.",
        "condition": {
            "is_trusted_device": False
        },
        "score": 15
    },

    "AS-003": {
        "name": "device_fingerprint_change",
        "description": "Device fingerprint changes around suspicious activity.",
        "condition": {
            "new_device_fingerprint": True
        },
        "score": 15
    },

    "AS-004": {
        "name": "impossible_travel",
        "description": "Large geographic movement occurs within an implausibly short period.",
        "condition": {
            "distance_from_last_location_km": "> 500",
            "time_difference_hours": "<= 4"
        },
        "score": 20
    },

    "AS-005": {
        "name": "vpn_or_proxy_signal",
        "description": "Transaction or authentication activity is associated with VPN or proxy usage.",
        "condition": {
            "is_vpn_or_proxy": True
        },
        "score": 10
    },

    "AS-006": {
        "name": "registered_country_mismatch",
        "description": "Transaction-related location differs from the registered country.",
        "condition": {
            "registered_country_match": False
        },
        "score": 10
    },

    "AS-007": {
        "name": "new_beneficiary",
        "description": "Large or unusual transfer is made to a newly added beneficiary.",
        "condition": {
            "is_first_time_beneficiary": True
        },
        "score": 10
    },

    "AS-008": {
        "name": "transaction_amount_anomaly",
        "description": "Transaction amount significantly exceeds customer's normal activity.",
        "condition": {
            "transaction_amount": "> 3 * avg_monthly_txn_amount"
        },
        "score": 15
    },

    "AS-009": {
        "name": "compound_account_takeover_signal",
        "description": "Multiple independent security and transaction anomalies occur together.",
        "condition": {
            "minimum_security_signals": ">= 2",
            "minimum_transaction_signals": ">= 1"
        },
        "score": 20
    }
}


RULEBOOKS = {
    "smurfing": SMURFING_RULES,
    "reverse_smurfing": REVERSE_SMURFING_RULES,
    "account_swap": ACCOUNT_SWAP_RULES
}
```

---

# 17. Detection Gating

The detection layer should avoid creating a suspected alert from a single weak signal wherever the rule design requires corroboration.

For network typologies:

```text
Minimum qualifying rules >= 2
```

should be applied where appropriate.

For Account Swap:

```text
Security signals
+
Transaction/security context
```

must provide sufficient evidence for an alert.

A single unusual payment by itself should not automatically be declared an Account Takeover.

---

# 18. Network Layer

NetworkX is used to construct financial relationship graphs.

The network layer must support:

```text
Smurfing
Reverse Smurfing
```

and security/timeline analysis for:

```text
Account Swap
```

Maximum graph traversal depth:

```text
3 hops
```

Example:

```text
A → B        depth 1
B → C        depth 2
C → D        depth 3
```

Network traversal must use a relevant time window around the detected transaction/event.

The system should not expand indefinitely through historical transactions.

---

# 19. Case Intake

Multiple suspected alerts associated with the same account are bundled into a single case.

The case has:

```text
case_id
account_id
created_at
primary_trigger
alert_ids
evidence_signals
typologies
status
bundle_reason
```

Possible primary triggers:

```text
account_swap
smurfing
reverse_smurfing
unknown
```

No `money_mule` primary trigger exists.

---

# 20. cases.csv

`cases.csv` is the operational case queue created by the Detection Agent.

Schema:

```text
case_id
account_id
created_at
primary_trigger
alert_ids
evidence_signals
typologies
status
bundle_reason
```

### Initial ownership

Every newly created case is assigned to:

```text
JUNIOR
```

The case must not automatically go directly to Senior.

---

# 21. Checkpoint 3 — PII Sanitizer and Evidence Builder

The Evidence Builder gathers and normalizes evidence from:

```text
accounts
transactions
devices
geo_events
beneficiaries
network outputs
detection alerts
```

The PII Sanitizer establishes a hard boundary between:

```text
Raw Banking Data
       ↓
Scoped Data Access
       ↓
PII Sanitizer
       ↓
LLM-safe Evidence
```

Grok must not receive unnecessary raw PII.

The LLM evidence package should contain relevant analytical information rather than unrestricted customer identity information.

---

# 22. Role-Aware Evidence

Junior investigator data:

```text
Masked customer identity
Restricted KYC details
Masked beneficiary information
Permitted transaction/device/geo evidence
```

Senior investigator data:

```text
Full permitted customer/KYC information
Full beneficiary details
Full investigation context
```

The role-based restrictions must be enforced server-side.

---

# 23. Checkpoint 4 — Three Grok-Based LLM Agents

There are three LLM agents.

## 23.1 Scammer Hypothesis Agent

Purpose:

Assess evidence supporting suspicious/criminal activity.

It should evaluate:

* Fund-flow anomalies
* Network structure
* Pass-through behaviour
* Transaction anomalies
* Security compromise
* Beneficiary anomalies
* Profile deviation
* Contradictory evidence

It must distinguish:

```text
Smurfing evidence
Reverse-smurfing evidence
Account-compromise evidence
```

and must not automatically classify every compromised account as a mule.

---

## 23.2 Legitimate Hypothesis Agent

Purpose:

Construct the strongest legitimate explanation supported by the evidence.

Examples:

* Legitimate business payments
* Family transfers
* Unusual but explainable transaction
* Travel-related activity
* Device replacement
* Genuine SIM replacement
* Known beneficiary
* Temporary transaction-profile deviation

The agent must not invent explanations unsupported by evidence.

---

## 23.3 Contradiction Agent

Purpose:

Compare:

```text
Scammer Hypothesis
        vs
Legitimate Hypothesis
```

and determine which explanation is better supported.

It should explicitly identify:

* Supporting evidence
* Contradicting evidence
* Missing evidence
* Evidence quality
* Confidence
* Remaining uncertainty

For Account Swap scenarios with:

```text
No fund-flow network
+
Security compromise
+
One unusual payment
```

the Contradiction Agent can assess whether the evidence supports Account Takeover.

It should **not require a mule/pass-through pattern** to investigate Account Swap.

---

# 24. LLM Provider

Grok is the LLM/API provider.

The Grok integration must be isolated behind a service/client layer.

The API key must be stored in environment configuration.

Example:

```text
GROK_API_KEY=<secret>
```

Use:

```text
python-dotenv
```

to load environment variables.

Never hard-code API credentials.

The architecture should allow the model provider to be replaced without rewriting the investigation pipeline.

---

# 25. Checkpoint 5 — Regulatory Compliance and Investigation Auditor

## Regulatory Rule Engine

The regulatory rule engine is deterministic.

It evaluates the completed evidence and investigation against the applicable Indian regulatory/compliance rules implemented for the MVP.

It must not allow an LLM to override deterministic compliance rules.

---

## Regulatory RAG

The Regulatory RAG component provides supporting regulatory context to the investigation.

The RAG layer should be India-specific for the MVP.

The RAG result is supporting evidence/context, not an unrestricted authorization mechanism.

---

## Investigation Auditor

The Investigation Auditor is rule-based.

It evaluates:

* Required evidence
* Evidence completeness
* Required investigation steps
* Contradictions
* Investigator actions
* Escalation requirements
* Compliance-rule findings
* Whether the case is sufficiently investigated

---

# 26. Case Completeness Score

The auditor calculates a deterministic completeness score.

Example conceptual range:

```text
0–100
```

The score represents investigation completeness, not probability of fraud.

A high completeness score does **not** automatically mean fraud.

A low completeness score does **not** automatically mean legitimate.

---

# 27. Auditor Routing

The auditor determines whether:

```text
Investigation complete
```

or:

```text
More evidence/review required
```

Cases requiring restricted information may require:

```text
Junior → Senior escalation
```

---

# 28. Checkpoint 6 — Next-Best-Action, Audit Trail and Human Review

The Next-Best-Action component is rule-based.

Possible actions:

```text
CLEAR
MONITOR
ESCALATE
BLOCK
```

## CLEAR

Used when the investigation has sufficient evidence that the activity is likely legitimate/false positive.

## MONITOR

Used when suspiciousness remains but immediate blocking is not justified.

## ESCALATE

Used when:

* Evidence is insufficient
* Restricted information is required
* Senior review is required
* Investigation complexity exceeds Junior authority

## BLOCK

Used only when the configured investigation/compliance rules justify the action.

The LLM recommends/analyses; deterministic policy rules and human authority govern the final operational action.

---

# 29. case_escalation.csv

File:

```text
case_escalation.csv
```

Schema:

```text
escalation_id
case_id
escalation_reason
completeness_score_at_escalation
primary_trigger
evidence_signals
escalated_at
escalated_by
status
```

### Important lifecycle rule

The escalation record must **not be pre-populated by the mock-data generator**.

It is created dynamically when a Junior Investigator actually escalates a case.

The escalation record should therefore initially be empty:

```text
No rows
```

until an actual escalation occurs.

The relevant fields are populated from the real investigation event.

---

# 30. Junior → Senior Escalation

Initial state:

```text
Detection
   ↓
Junior
```

If Junior requires Senior intervention:

```text
Junior
   ↓
Escalation
   ↓
Senior
```

A copy/reference of the case is placed into the Senior investigation queue.

The Senior receives the case with:

* Existing evidence
* Previous investigator reasoning
* Escalation reason
* Completeness score
* Audit history
* Requested restricted information, where applicable

The Junior's original investigation history must not be destroyed.

---

# 31. Authentication and Authorization

Authentication must apply to operational case files.

At minimum, access must distinguish:

```text
JUNIOR
SENIOR
```

The backend must verify the authenticated investigator before allowing:

* Case access
* Case modification
* Escalation
* Restricted-information access
* Investigator action
* Case finalization
* Reference-case storage
* SAR generation
* Audit-trail operations

Frontend controls are not sufficient for authorization.

---

# 32. Case State Lifecycle

A case follows an explicit lifecycle.

```text
NEW
 ↓
JUNIOR_INVESTIGATION
 ↓
UNDER_REVIEW
 ↓
 ┌───────────────┬────────────────┬─────────────────┐
 ↓               ↓                ↓                 ↓
CLEAR          MONITOR         ESCALATE          BLOCK
                                  ↓
                               SENIOR
                                  ↓
                         SENIOR_INVESTIGATION
                                  ↓
                         FINAL INVESTIGATOR ACTION
                                  ↓
                              SAR READY
                                  ↓
                         AUDIT-READY CASE
```

---

# 33. Checkpoint 7 — SAR Report and Case Memory

After the investigation has been completed and the case is audit-ready, the system generates a SAR-ready report.

The report should contain, as applicable:

* Case identification
* Primary trigger
* Relevant typologies
* Evidence summary
* Network findings
* Security findings
* Scammer hypothesis
* Legitimate hypothesis
* Contradiction analysis
* Regulatory findings
* Completeness score
* Auditor findings
* Next-best-action
* Investigator action
* Escalation history
* Relevant audit trail
* Final disposition

The SAR report must not expose information beyond the authorized report scope.

---

# 34. Password-Protected SAR PDF

The generated SAR PDF must be password protected.

The password must not be hard-coded into source code.

The report generation component must produce the final report after the case has reached the appropriate completed state.

---

# 35. audit_ready_cases.csv

`audit_ready_cases.csv` stores cases that have completed the investigation lifecycle and have reached the audit-ready/reporting stage.

A case moves from:

```text
cases.csv
```

to:

```text
audit_ready_cases.csv
```

when the investigation is completed and the SAR-ready report has been generated.

The move must preserve the relevant case identity and audit linkage.

This is a lifecycle operation, not a new detection event.

---

# 36. reference_cases.csv

`reference_cases.csv` stores cases that the investigator explicitly chooses to retain for future reference/case memory.

It is **not automatically populated with every completed case**.

The investigator decides whether a case should be retained as reference knowledge.

The stored case should preserve useful investigation information such as:

* Case identity
* Typology
* Evidence summary
* Network findings
* Investigation reasoning
* Final investigator action
* Outcome
* Relevant audit history
* Investigator-provided reference notes, where supported

The case memory must respect authentication and authorization.

---

# 37. Case Memory Principle

Case memory is not automatically treated as ground truth.

A historical case stored in:

```text
reference_cases.csv
```

is a reference/investigative artifact.

It must not silently become a detection rule or automatically alter model behaviour.

If future model/rule improvements use reference cases, they should pass through an explicit validation/review process.

---

# 38. audit_ready_cases.csv vs reference_cases.csv

These have different purposes.

| File                    | Purpose                                                         |
| ----------------------- | --------------------------------------------------------------- |
| `cases.csv`             | Active operational cases                                        |
| `case_escalation.csv`   | Actual escalation records                                       |
| `audit_ready_cases.csv` | Completed cases ready for audit/SAR record                      |
| `reference_cases.csv`   | Cases explicitly retained by investigators for future reference |

A case may be audit-ready without being saved as reference memory.

A case may also be retained as reference material according to investigator preference.

---

# 39. Operational CSV vs Evaluation CSV

## Operational data

```text
accounts.csv
transactions.csv
geo_events.csv
devices.csv
beneficiaries.csv
cases.csv
case_escalation.csv
audit_ready_cases.csv
reference_cases.csv
access_requests.csv
```

These participate in the application workflow.

## Evaluation-only data

```text
ground_truth_suspected_alerts.csv
```

Ground truth must remain isolated from the operational pipeline.

---

# 40. Frontend

The frontend uses:

```text
React
JavaScript
Cytoscape.js
```

Cytoscape.js is used for interactive financial network visualization.

The frontend receives network data from FastAPI.

It must not directly access:

```text
NetworkX internals
raw CSV files
ground truth
restricted customer information
```

The backend determines what data the authenticated investigator is allowed to see.

---

# 41. Backend Technology Stack

The backend uses:

```text
Python
FastAPI
Uvicorn[standard]
python-dotenv
Faker
NetworkX
Matplotlib
pytest
```

### FastAPI

Provides:

* Authentication endpoints
* Case endpoints
* Investigation endpoints
* Evidence endpoints
* Escalation endpoints
* Investigator action endpoints
* SAR/report endpoints
* Case-memory endpoints
* Audit endpoints

### Uvicorn

Runs the FastAPI ASGI application.

Example:

```text
uvicorn main:app --reload
```

---

# 42. Python Dependencies

Required backend stack:

```text
fastapi
uvicorn[standard]
python-dotenv
faker
networkx
matplotlib
pytest
```

Additional libraries may be introduced only when required by an implemented feature.

---

# 43. Environment Configuration

Secrets must be supplied through environment variables.

Example:

```text
GROK_API_KEY=...
```

Do not store secrets in:

```text
Python source
CSV files
frontend source
Git repository
test fixtures
prompt files
```

Use `.env` locally where appropriate and ensure it is excluded from version control.

---

# 44. API Architecture

FastAPI should expose a clear service boundary:

```text
Frontend
   ↓
FastAPI
   ↓
Authentication / Authorization
   ↓
Case Service
   ↓
Investigation Pipeline
   ↓
Evidence / Agents / Auditor / NBA
   ↓
CSV/Data Store
```

The frontend must never bypass authorization by directly reading backend storage.

---

# 45. Testing Strategy

`pytest` must cover at minimum:

### Detection

* Smurfing detection
* Reverse Smurfing detection
* Account Swap detection
* No false Money Mule typology
* Alert generation
* Case bundling

### Network

* Graph construction
* Maximum depth
* Smurfing network
* Reverse Smurfing network
* Downstream pass-through signals
* Account Swap timeline

### Evidence

* Evidence construction
* Missing evidence
* Partial evidence
* PII masking
* Role-based access

### LLM Boundary

* Grok client integration
* Sanitized payload
* Structured JSON response handling
* Invalid response handling
* API failure handling

### Investigation

* Regulatory rules
* Auditor
* Completeness
* Next-best-action
* Escalation

### Case Lifecycle

* Junior receives new case
* Junior escalation
* Senior receives escalated copy/reference
* Final action
* SAR generation
* Audit-ready transition
* Reference-case storage
* Authentication/authorization

---

# 46. Critical Architectural Constraints

The implementation must follow these constraints.

### 1. No Money Mule as a separate operational typology

Do not generate:

```text
money_mule
```

as a primary detection typology.

Use mule-like/pass-through behaviour as evidence inside:

```text
smurfing
reverse_smurfing
```

---

### 2. Account Swap is independent

Account Swap can exist without:

```text
fund-flow network
pass-through
smurfing
reverse smurfing
```

A compromised account making one unusual payment remains a valid Account Swap investigation candidate.

---

### 3. LLMs do not invent evidence

If there is:

```text
No network evidence
```

the LLM must not manufacture network behaviour.

If there is:

```text
No security evidence
```

the LLM must not manufacture takeover evidence.

---

### 4. Ground truth is isolated

Ground truth exists for evaluation only.

No production agent may read it.

---

### 5. Detection creates cases

The mock-data generator creates source behaviour.

The Detection Agent creates alerts.

Case Intake bundles alerts into cases.

---

### 6. Cases initially belong to Junior

```text
Detection → Junior
```

not:

```text
Detection → Senior
```

unless an explicit system-level policy requires otherwise.

---

### 7. Escalation is dynamic

`case_escalation.csv` starts empty.

It is populated only when an actual Junior Investigator escalates a case.

---

### 8. Senior receives escalated cases

When Junior escalates:

```text
Junior Case
    ↓
Escalation Event
    ↓
Senior Case Copy / Queue Entry
```

The original investigation history is retained.

---

### 9. Finalized cases are audit-ready

Once the investigation and SAR generation requirements are satisfied:

```text
cases.csv
    ↓
audit_ready_cases.csv
```

---

### 10. Case memory is optional

Only investigator-selected cases enter:

```text
reference_cases.csv
```

---

### 11. Authentication applies to case lifecycle

Authentication and authorization must cover:

```text
cases.csv
case_escalation.csv
audit_ready_cases.csv
reference_cases.csv
access_requests.csv
```

and all corresponding API operations.

---

# 47. Final End-to-End Flow

```text
BANK DATA
   ↓
Detection Agent
   ↓
Anomaly Check
   ↓
Suspected Alert
   ↓
Case Intake
   ↓
cases.csv
   ↓
Junior Investigator
   ↓
Beneficiary Agent
Transaction Agent
Device/Geo Agent
   ↓
Network Layer
   ↓
Evidence Store
   ↓
PII Sanitization
   ↓
┌───────────────────────┐
│ Scammer Hypothesis    │
│       Grok            │
└──────────┬────────────┘
           │
           │
┌──────────▼────────────┐
│ Legitimate Hypothesis │
│       Grok            │
└──────────┬────────────┘
           ↓
Contradiction Agent
       Grok
           ↓
Regulatory Rule Engine
           ↓
Regulatory RAG
           ↓
Investigation Auditor
           ↓
Completeness Score
           ↓
Auditor Routing
           ↓
Next-Best-Action
           ↓
Audit Trail
           ↓
Human Review
           ↓
Junior Investigator Action
           |
           ├──────── CLEAR
           ├──────── MONITOR
           ├──────── BLOCK
           |
           └──────── ESCALATE
                       ↓
                     Senior
                       ↓
              Senior Investigation
                       ↓
                Final Action
                       ↓
                 SAR Generation
                       ↓
             Password-Protected PDF
                       ↓
              audit_ready_cases.csv
                       |
                       └── Investigator chooses
                              ↓
                       reference_cases.csv
```

---

# 48. Final Design Principle

Tekmerion Intelligence should distinguish three fundamentally different questions:

```text
QUESTION 1:
Is there suspicious financial-flow behaviour?

→ Smurfing / Reverse Smurfing

QUESTION 2:
Is the account itself showing signs of compromise?

→ Account Swap / Account Takeover investigation

QUESTION 3:
Given the evidence, what is the strongest explanation?

→ Grok:
   Scammer Hypothesis
   Legitimate Hypothesis
   Contradiction
```

Therefore:

```text
Fund-flow behaviour
        ≠
Account compromise
```

and:

```text
Money-mule/pass-through behaviour
        = signal within fund-flow investigations
```

rather than an independent fourth typology.

This separation prevents a single compromised account making one unusual payment from being incorrectly classified as a money mule while still allowing the LLM investigation layer to determine whether the payment is consistent with account takeover.
