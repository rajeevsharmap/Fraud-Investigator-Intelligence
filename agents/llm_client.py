"""Isolated LLM provider layer (Architecture.md s24).

The investigation pipeline never talks to the provider directly - only this
client does, so the provider/model can be swapped without touching agents.
API key comes from the environment (GROQ_API_KEY via .env), never source code.
"""
from __future__ import annotations

import json
import os
import re

import httpx

GROQ_BASE_URL = "https://api.groq.com/openai/v1"
DEFAULT_MODEL = "llama-3.1-8b-instant"  # MVP: fastest working model first


class GroqClient:
    """Minimal async OpenAI-compatible chat client pointed at Groq."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self.api_key = api_key or os.environ.get("GROQ_API_KEY", "")
        self.model = model or os.environ.get("GROQ_MODEL", DEFAULT_MODEL)
        self.base_url = os.environ.get("GROQ_BASE_URL", GROQ_BASE_URL).rstrip("/")

    async def chat(self, system: str, user: str, temperature: float = 0.2) -> str:
        payload = {
            "model": self.model,
            "temperature": temperature,
            "response_format": {"type": "json_object"},
            "messages": [{"role": "system", "content": system},
                         {"role": "user", "content": user}],
        }
        headers = {"Authorization": f"Bearer {self.api_key}"}
        async with httpx.AsyncClient(timeout=90) as http:
            r = await http.post(f"{self.base_url}/chat/completions",
                                json=payload, headers=headers)
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]


def parse_llm_json(text: str) -> dict:
    """Robustly extract a JSON object from an LLM reply (handles fences/prose)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    fenced = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if fenced:
        return json.loads(fenced.group(1))
    loose = re.search(r"\{.*\}", text, re.DOTALL)
    if loose:
        return json.loads(loose.group(0))
    raise ValueError(f"LLM returned non-JSON response: {text[:200]}")
