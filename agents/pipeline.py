"""Investigation pipeline orchestration (Checkpoint 4, MVP requirement).

Flow on "Start Investigation":
  1. Evidence Builder collects the case evidence (raw).
  2. PII Sanitizer MASKS it (consistent per-case aliases; one sanitizer
     instance per case so the alias map doubles as the demask key).
  3. Scammer + Legitimate agents run IN PARALLEL on the masked package.
  4. Only when BOTH responses have arrived are they passed, with the masked
     evidence, to the Contradiction Agent.
  5. All three responses are DEMASKED (aliases -> raw ids) and the result is
     stored for the frontend (mockdata/investigations/<case_id>.json).
"""
from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime

from agents.hypothesis import contradiction_agent, legitimate_agent, scammer_agent
from agents.llm_client import GroqClient
from evidence.builder import EvidenceBuilder
from evidence.sanitizer import PIISanitizer

INVESTIGATIONS_DIR = os.path.join("mockdata", "investigations")


def _demask(obj, alias_to_raw: dict[str, str]):
    """Reverse the per-case alias map inside agent responses (text-safe)."""
    if not alias_to_raw:
        return obj
    pattern = re.compile(
        "|".join(re.escape(a) for a in sorted(alias_to_raw, key=len, reverse=True)))

    def sub(s: str) -> str:
        return pattern.sub(lambda m: alias_to_raw[m.group(0)], s)

    if isinstance(obj, dict):
        return {k: _demask(v, alias_to_raw) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_demask(x, alias_to_raw) for x in obj]
    if isinstance(obj, str):
        return sub(obj)
    return obj


async def run_investigation(case: dict, alerts: list[dict], role: str,
                            builder: EvidenceBuilder,
                            client: GroqClient | None = None,
                            out_dir: str | None = None) -> dict:
    """Full mask -> parallel hypotheses -> contradiction -> demask pipeline."""
    started = datetime.now().replace(microsecond=0).isoformat(sep=" ")
    client = client or GroqClient()

    # 1-2. build raw evidence, then mask it for the LLM boundary
    raw = builder.build(case, alerts)
    sanitizer = PIISanitizer()
    masked = sanitizer.mask_package(raw, role)
    alias_to_raw = {alias: rid for rid, alias in sanitizer.aliases.items()}

    # 3. hypothesis agents in parallel (MVP: both responses awaited together)
    t0 = asyncio.get_event_loop().time()
    scammer, legitimate = await asyncio.gather(
        scammer_agent(masked, client),
        legitimate_agent(masked, client),
    )
    parallel_s = round(asyncio.get_event_loop().time() - t0, 2)

    # 4. contradiction agent gets both responses + masked evidence
    t1 = asyncio.get_event_loop().time()
    contradiction = await contradiction_agent(masked, scammer, legitimate, client)
    contradiction_s = round(asyncio.get_event_loop().time() - t1, 2)

    # 5. demask all three responses before anything leaves the boundary
    result = {
        "case_id": case["case_id"],
        "role": role,
        "status": "COMPLETED",
        "started_at": started,
        "completed_at": datetime.now().replace(microsecond=0).isoformat(sep=" "),
        "timing_seconds": {"parallel_hypotheses": parallel_s,
                           "contradiction": contradiction_s},
        "agents": {
            "scammer_hypothesis": _demask(scammer, alias_to_raw),
            "legitimate_hypothesis": _demask(legitimate, alias_to_raw),
            "contradiction": _demask(contradiction, alias_to_raw),
        },
        "evidence_masked": masked,
    }

    out_dir = out_dir or INVESTIGATIONS_DIR
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{case['case_id']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=1, default=str)
    result["result_path"] = path
    return result
