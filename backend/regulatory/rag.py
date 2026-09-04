"""India-specific Regulatory RAG (Architecture.md section 25, MVP).

Lightweight retrieval over a curated, India-only regulatory snippet corpus
(PMLA, RBI KYC Master Direction, FEMA/LRS, NPCI UPI, FIU-IND). Pure-stdlib
keyword scoring - no external vector DB. RAG output is supporting context
for the investigation/auditor only; it never authorizes or overrides the
deterministic rule engine or investigator authority.
"""
from __future__ import annotations

import re
from collections import Counter

CORPUS = [
    {"doc_id": "PMLA-S13", "title": "Suspicious Transaction Reporting",
     "citation": "PMLA 2002 s.13; PMLA Maintenance of Records Rules 2015 r.3",
     "keywords": ["str", "suspicious transaction", "fiu-ind", "reporting entity",
                  "smurfing", "layering"],
     "text": "Every reporting entity (banking company, financial institution) "
             "must furnish information of all suspicious transactions to the "
             "Director, FIU-IND within prescribed time, whether or not the "
             "transaction was completed. Suspicious transactions include "
             "complex/unusually large transactions with no apparent economic "
             "lawful purpose and patterns indicative of layering or smurfing."},
    {"doc_id": "PMLA-CTR", "title": "Cash Transaction Report threshold",
     "citation": "PMLA Maintenance of Records Rules 2015 r.3(1)",
     "keywords": ["cash", "ctr", "10 lakh", "1000000", "threshold", "atm", "branch"],
     "text": "All cash transactions of value more than Rs 10 lakh or equivalent "
             "must be reported to FIU-IND. Series of integrally connected cash "
             "transactions below Rs 10 lakh in a month must be aggregated and "
             "reported as a CTR."},
    {"doc_id": "RBI-KYC-MD", "title": "KYC Master Direction",
     "citation": "RBI Master Direction on KYC 2016 (as amended)",
     "keywords": ["kyc", "customer due diligence", "cdd", "periodic updation",
                  "identity verification", "beneficial owner"],
     "text": "Banks must undertake customer due diligence including "
             "identification and verification of the customer, maintain "
             "records, and apply enhanced due diligence to high-risk "
             "customers. Failure of periodic KYC updation restricts account "
             "operations until compliance is restored."},
    {"doc_id": "RBI-MULE", "title": "Money mule accounts advisory",
     "citation": "RBI advisories / cyber security circulars on mule accounts",
     "keywords": ["mule", "pass-through", "layering", "rapid onward transfer",
                  "fund retention", "smurfing"],
     "text": "Accounts used to receive and rapidly transfer funds on behalf of "
             "others (money mules) are a key channel for cyber-enabled fraud. "
             "Banks are advised to monitor pass-through behaviour, rapid "
             "onward transfers after inbound credit, and unusual account "
             "velocity, and to freeze/act on mule accounts under due process."},
    {"doc_id": "FEMA-LRS", "title": "Cross-border transactions under LRS",
     "citation": "FEMA 1999; RBI Master Direction on LRS 2015 (as amended)",
     "keywords": ["international", "foreign", "lrs", "fema", "cross-border",
                  "remittance"],
     "text": "Cross-border remittances by residents are regulated under FEMA "
             "and routed through the Liberalised Remittance Scheme and other "
             "permitted channels. Transactions inconsistent with declared "
             "purpose, or split to evade limits, attract FEMA review."},
    {"doc_id": "NPCI-UPI", "title": "UPI transaction limits",
     "citation": "NPCI UPI procedural guidelines; RBI digital payments framework",
     "keywords": ["upi", "limit", "100000", "1 lakh", "npci", "channel"],
     "text": "Standard per-transaction UPI limit is Rs 1 lakh unless a "
             "regulated exception category applies. Amounts above the channel "
             "limit indicate channel anomaly requiring verification of the "
             "underlying authorisation."},
    {"doc_id": "RBI-TAKEOVER", "title": "Account takeover / compromised devices",
     "citation": "RBI circular on cyber security framework for banks (2016); "
                 "customer protection circular (2024)",
     "keywords": ["account takeover", "sim change", "device", "otp", "impossible "
                  "travel", "vpn", "untrusted", "compromise"],
     "text": "Where a transaction follows a SIM change, new/untrusted device, "
             "or other compromise indicators, banks must assess account "
             "takeover, apply customer-protection liability norms, and act "
             "under the zero-liability provisions for third-party fraud."},
    {"doc_id": "RBI-ESCAL", "title": "Escalation and internal governance",
     "citation": "RBI Master Direction on KYC 2016 - reporting/escalation",
     "keywords": ["escalation", "senior", "restricted information", "approval",
                  "governance", "incomplete"],
     "text": "In-house detection, escalation to appropriate internal authority "
             "and decision-making on STR filing must follow board-approved "
             "policy. Cases with incomplete evidence must be escalated rather "
             "than closed."}
]

_WORD = re.compile(r"[a-z0-9]+")


def _terms(text: str) -> Counter:
    return Counter(_WORD.findall(text.lower()))


def _score(doc: dict, query_terms: Counter) -> float:
    score = 0.0
    blob = _terms(doc["title"] + " " + doc["text"])
    for t, n in query_terms.items():
        score += blob.get(t, 0) * n
    for kw in doc["keywords"]:
        if kw in query_terms:
            score += 5 + query_terms[kw]          # curated keyword boost
    return score


def retrieve(context: str, top_k: int = 3) -> list[dict]:
    """Return top_k corpus snippets relevant to the free-text/structured
    context (typologies, findings, verdicts)."""
    q = _terms(context)
    ranked = sorted(((_score(d, q), d) for d in CORPUS), key=lambda x: -x[0])
    return [{"doc_id": d["doc_id"], "title": d["title"], "citation": d["citation"],
             "text": d["text"], "relevance": round(s, 2)}
            for s, d in ranked[:top_k] if s > 0]
