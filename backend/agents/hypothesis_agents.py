"""
Hypothesis Agents
=================

Runs the three LLM-based investigation hypotheses:

1. Scammer Hypothesis Agent
2. Legitimate Hypothesis Agent
3. Contradiction Agent

LLM provider:
    Gemini Flash 3.6

Important architecture rules:
- The JSON contract is unchanged.
- Only sanitized evidence is sent to the LLM.
- The agents must never invent evidence.
- Typology distinctions remain explicit.
- PII demasking is NOT performed here.
"""

from __future__ import annotations

import json
from typing import Any

from agents.gemini_client import GeminiClient


# ---------------------------------------------------------------------------
# SYSTEM PROMPTS
# ---------------------------------------------------------------------------

SYSTEM_COMMON = (
    "You are an analyst on an Indian banking fraud investigation system. "
    "Use only facts contained in the evidence package. Never invent evidence. "
    "Distinguish fund-flow typologies (smurfing, reverse_smurfing) from "
    "account compromise (account_swap); a compromised account is not "
    "automatically a money mule."
)

TWO_HYP_SYSTEM = SYSTEM_COMMON + (
    " Output JSON: "
    "{\"hypothesis\": str, "
    "\"typology_assessment\": str, "
    "\"supporting_points\": [str], "
    "\"contradicting_points\": [str], "
    "\"confidence\": float}."
)

CONTRA_SYSTEM = SYSTEM_COMMON + (
    " Compare the scammer hypothesis with the legitimate hypothesis and "
    "decide which the evidence better supports. Output JSON: "
    "{\"verdict\": \"scammer|legitimate|insufficient_evidence\", "
    "\"confidence\": float, "
    "\"supporting_evidence\": [str], "
    "\"contradictions\": [str], "
    "\"missing_evidence\": [str], "
    "\"remaining_uncertainty\": str}."
)


# ---------------------------------------------------------------------------
# EVIDENCE DIGEST
# ---------------------------------------------------------------------------

def _evidence_digest(evidence: dict[str, Any]) -> str:
    """
    Build the restricted evidence package sent to Gemini.

    The LLM must only receive investigation evidence that has already passed
    through the backend's sanitization / PII boundary.

    This function does NOT demask PII.
    """

    if not isinstance(evidence, dict):
        return "{}"

    # Keep the evidence package deliberately constrained.
    #
    # These fields correspond to the existing evidence contract. Additional
    # fields are allowed if present, but the digest prevents unnecessarily
    # large payloads from being sent to the model.
    allowed_keys = (
        "case_id",
        "account_id",
        "primary_trigger",
        "typology",
        "alert",
        "alerts",
        "case",
        "transactions",
        "transaction_evidence",
        "network",
        "network_evidence",
        "device",
        "device_evidence",
        "geo",
        "geo_evidence",
        "beneficiary",
        "beneficiary_evidence",
        "derived_signals",
        "regulatory",
        "regulatory_findings",
        "completeness",
        "completeness_score",
    )

    digest: dict[str, Any] = {}

    for key in allowed_keys:
        if key in evidence:
            digest[key] = evidence[key]

    # Preserve the existing behavior of falling back to the complete
    # evidence package when none of the expected keys are present.
    if not digest:
        digest = evidence

    # Defensive size limit. The existing architecture intentionally limits
    # the evidence digest before it reaches the LLM.
    serialized = json.dumps(
        digest,
        ensure_ascii=False,
        default=str,
        separators=(",", ":"),
    )

    return serialized[:6000]


# ---------------------------------------------------------------------------
# HYPOTHESIS AGENT
# ---------------------------------------------------------------------------

class HypothesisAgents:
    """
    Three-agent LLM investigation layer.

    The class retains the existing public interface so callers such as
    main.py do not need architectural changes.
    """

    def __init__(self, client: GeminiClient | None = None) -> None:
        self.client = client or GeminiClient()

    # -----------------------------------------------------------------------
    # Scammer Hypothesis
    # -----------------------------------------------------------------------

    def scammer(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """
        Determine whether the evidence supports a scammer/fraud hypothesis.

        Returns the existing JSON contract:
        {
            "hypothesis": str,
            "typology_assessment": str,
            "supporting_points": [str],
            "contradicting_points": [str],
            "confidence": float
        }
        """

        digest = _evidence_digest(evidence)

        prompt = (
            "Evaluate the evidence from the perspective of a scammer/fraud "
            "hypothesis.\n\n"
            "Determine whether the observed activity is consistent with "
            "fraudulent behavior. Assess the applicable typology using only "
            "the supplied evidence.\n\n"
            "Do not assume that an alert means fraud. Identify both "
            "supporting and contradicting evidence.\n\n"
            "EVIDENCE PACKAGE:\n"
            f"{digest}"
        )

        result = self.client.complete(
            TWO_HYP_SYSTEM,
            prompt,
        )

        return self._normalize_two_hypothesis_result(result)

    # -----------------------------------------------------------------------
    # Legitimate Hypothesis
    # -----------------------------------------------------------------------

    def legitimate(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """
        Determine whether the evidence supports a legitimate explanation.

        Returns the same JSON contract as the scammer hypothesis.
        """

        digest = _evidence_digest(evidence)

        prompt = (
            "Evaluate the evidence from the perspective of a legitimate "
            "customer/activity hypothesis.\n\n"
            "Determine whether the observed activity could reasonably have "
            "a legitimate explanation. Assess the applicable typology using "
            "only the supplied evidence.\n\n"
            "Do not assume that unusual activity is automatically fraudulent. "
            "Identify both supporting and contradicting evidence.\n\n"
            "EVIDENCE PACKAGE:\n"
            f"{digest}"
        )

        result = self.client.complete(
            TWO_HYP_SYSTEM,
            prompt,
        )

        return self._normalize_two_hypothesis_result(result)

    # -----------------------------------------------------------------------
    # Contradiction Agent
    # -----------------------------------------------------------------------

    def contradiction(
        self,
        scammer_hypothesis: dict[str, Any],
        legitimate_hypothesis: dict[str, Any],
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Compare the scammer and legitimate hypotheses.

        Returns the existing contradiction-agent JSON contract.
        """

        digest = _evidence_digest(evidence)

        comparison = {
            "scammer_hypothesis": scammer_hypothesis,
            "legitimate_hypothesis": legitimate_hypothesis,
            "evidence": digest,
        }

        prompt = (
            "Compare the scammer hypothesis against the legitimate "
            "hypothesis.\n\n"
            "Determine which hypothesis is better supported by the evidence. "
            "Do not resolve uncertainty by inventing facts. If the evidence "
            "does not sufficiently distinguish the hypotheses, return "
            "\"insufficient_evidence\".\n\n"
            "HYPOTHESIS COMPARISON:\n"
            f"{json.dumps(comparison, ensure_ascii=False, default=str)[:10000]}"
        )

        result = self.client.complete(
            CONTRA_SYSTEM,
            prompt,
        )

        return self._normalize_contradiction_result(result)

    # -----------------------------------------------------------------------
    # Combined execution
    # -----------------------------------------------------------------------

    def run_all(self, evidence: dict[str, Any]) -> dict[str, Any]:
        """
        Execute all three hypothesis agents.

        Existing callers can continue using the same structure:
        {
            "scammer": {...},
            "legitimate": {...},
            "contradiction": {...}
        }
        """

        scammer_result = self.scammer(evidence)
        legitimate_result = self.legitimate(evidence)

        contradiction_result = self.contradiction(
            scammer_result,
            legitimate_result,
            evidence,
        )

        return {
            "scammer": scammer_result,
            "legitimate": legitimate_result,
            "contradiction": contradiction_result,
        }

    # -----------------------------------------------------------------------
    # JSON normalization
    # -----------------------------------------------------------------------

    @staticmethod
    def _normalize_two_hypothesis_result(
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Preserve the exact existing two-hypothesis JSON contract.

        Gemini normally returns the required structure directly. This
        normalization exists only as a defensive boundary so downstream
        modules never receive missing keys.
        """

        if not isinstance(result, dict):
            result = {}

        confidence = result.get("confidence", 0.0)

        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0

        confidence = max(0.0, min(1.0, confidence))

        supporting_points = result.get("supporting_points", [])
        contradicting_points = result.get("contradicting_points", [])

        if not isinstance(supporting_points, list):
            supporting_points = [str(supporting_points)]

        if not isinstance(contradicting_points, list):
            contradicting_points = [str(contradicting_points)]

        return {
            "hypothesis": str(result.get("hypothesis", "")),
            "typology_assessment": str(
                result.get("typology_assessment", "")
            ),
            "supporting_points": [
                str(item) for item in supporting_points
            ],
            "contradicting_points": [
                str(item) for item in contradicting_points
            ],
            "confidence": confidence,
        }

    @staticmethod
    def _normalize_contradiction_result(
        result: dict[str, Any],
    ) -> dict[str, Any]:
        """
        Preserve the exact contradiction-agent JSON contract.
        """

        if not isinstance(result, dict):
            result = {}

        verdict = result.get(
            "verdict",
            "insufficient_evidence",
        )

        if verdict not in {
            "scammer",
            "legitimate",
            "insufficient_evidence",
        }:
            verdict = "insufficient_evidence"

        confidence = result.get("confidence", 0.0)

        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 0.0

        confidence = max(0.0, min(1.0, confidence))

        supporting_evidence = result.get(
            "supporting_evidence",
            [],
        )
        contradictions = result.get(
            "contradictions",
            [],
        )
        missing_evidence = result.get(
            "missing_evidence",
            [],
        )

        if not isinstance(supporting_evidence, list):
            supporting_evidence = [str(supporting_evidence)]

        if not isinstance(contradictions, list):
            contradictions = [str(contradictions)]

        if not isinstance(missing_evidence, list):
            missing_evidence = [str(missing_evidence)]

        return {
            "verdict": verdict,
            "confidence": confidence,
            "supporting_evidence": [
                str(item) for item in supporting_evidence
            ],
            "contradictions": [
                str(item) for item in contradictions
            ],
            "missing_evidence": [
                str(item) for item in missing_evidence
            ],
            "remaining_uncertainty": str(
                result.get("remaining_uncertainty", "")
            ),
        }


# ---------------------------------------------------------------------------
# BACKWARD-COMPATIBLE FUNCTION API
# ---------------------------------------------------------------------------

def run_all(
    evidence: dict[str, Any],
    client: GeminiClient | None = None,
) -> dict[str, Any]:
    """
    Backward-compatible module-level API.

    Existing main.py code can therefore continue to do:

        agents_out = run_agents(safe, GeminiClient())

    without changing the architecture.
    """

    agents = HypothesisAgents(client=client)

    return agents.run_all(evidence)