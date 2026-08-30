"""Grok client (Architecture.md section 24).

Isolated provider boundary: the investigation pipeline never talks to the
LLM API directly. Key, endpoint and model come from environment (.env via
python-dotenv); the provider can be swapped (e.g. Groq's OpenAI-compatible
endpoint) without touching the pipeline. No offline fallback - a missing
key or API failure raises.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:                      # python-dotenv is optional at runtime
    pass

XAI_URL = os.environ.get("GROK_API_URL", "https://api.x.ai/v1/chat/completions")
MODEL = os.environ.get("GROK_MODEL", "grok-3-mini")
TIMEOUT = 90


class GrokClient:
    """Thin chat-completions client; raises when the API is unavailable."""

    def __init__(self):
        self.api_key = os.environ.get("GROK_API_KEY", "").strip()
        if not self.api_key:
            raise RuntimeError("GROK_API_KEY not configured")

    def complete(self, system: str, user: str) -> dict:
        """Return parsed JSON object from the model, or raise RuntimeError."""
        payload = json.dumps({
            "model": MODEL,
            "temperature": 0.2,
            "response_format": {"type": "json_object"},
            "messages": [
                {"role": "system",
                 "content": system + " Respond with a single valid JSON object only."},
                {"role": "user", "content": user},
            ],
        }).encode()
        req = urllib.request.Request(
            XAI_URL, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}",
                     "User-Agent": "TekmerionIntelligence/1.0",
                     "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = json.load(resp)
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"grok api http {e.code}: "
                               f"{e.read()[:200].decode('utf-8', 'ignore')}") from e
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RuntimeError(f"grok api unreachable: {e}") from e
        text = body["choices"][0]["message"]["content"].strip()
        if text.startswith("```"):               # strip markdown fences
            text = text.strip("`")[:-4].strip() if text.endswith("```") \
                else text.strip("`")
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"grok returned invalid JSON: {text[:200]}") from e
