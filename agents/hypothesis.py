"""The three hypothesis agents (Checkpoint 4).

Each agent receives ONLY the masked (PII-sanitized) evidence JSON produced by
the Evidence Builder + PII Sanitizer. Agents are pure functions of
(client, evidence) so tests can inject a fake client.
"""
from __future__ import annotations

import json

from agents.llm_client import GroqClient, parse_llm_json
from agents.prompts import CONTRADICTION_SYSTEM, LEGITIMATE_SYSTEM, SCAMMER_SYSTEM


def _evidence_json(masked_evidence: dict) -> str:
    return json.dumps(masked_evidence, default=str)


async def scammer_agent(masked_evidence: dict,
                        client: GroqClient | None = None) -> dict:
    client = client or GroqClient()
    reply = await client.chat(SCAMMER_SYSTEM, _evidence_json(masked_evidence))
    return parse_llm_json(reply)


async def legitimate_agent(masked_evidence: dict,
                           client: GroqClient | None = None) -> dict:
    client = client or GroqClient()
    reply = await client.chat(LEGITIMATE_SYSTEM, _evidence_json(masked_evidence))
    return parse_llm_json(reply)


async def contradiction_agent(masked_evidence: dict, scammer: dict,
                              legitimate: dict,
                              client: GroqClient | None = None) -> dict:
    """Runs only AFTER both hypothesis agents have returned (MVP requirement)."""
    client = client or GroqClient()
    user = json.dumps({
        "evidence": masked_evidence,
        "scammer_hypothesis_report": scammer,
        "legitimate_hypothesis_report": legitimate,
    }, default=str)
    reply = await client.chat(CONTRADICTION_SYSTEM, user)
    return parse_llm_json(reply)
