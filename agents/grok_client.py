"""Grok client (Architecture.md section 24).

Isolated provider boundary: the investigation pipeline never talks to the
LLM API directly. Key comes from environment (GROK_API_KEY via .env).
When no key is configured the client reports offline mode and the agents
use a deterministic fallback so the architecture runs end-to-end as an MVP.
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

XAI_URL = "https://api.x.ai/v1/chat/completions"
MODEL = os.environ.get("GROK_MODEL", "grok-3-mini")
TIMEOUT = 45


class GrokClient:
    """Thin chat-completions client; usable = False -> offline fallback."""

    def __init__(self):
        self.api_key = os.environ.get("GROK_API_KEY", "").strip()
        self.usable = bool(self.api_key)

    def complete(self, system: str, user: str) -> dict:
        """Return parsed JSON object from the model, or raise RuntimeError."""
        if not self.usable:
            raise RuntimeError("GROK_API_KEY not configured (offline mode)")
        payload = json.dumps({
            "model": MODEL,
            "temperature": 0.2,
            "messages": [
                {"role": "system",
                 "content": system + " Respond with a single valid JSON object only."},
                {"role": "user", "content": user},
            ],
        }).encode()
        req = urllib.request.Request(
            XAI_URL, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self.api_key}"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = json.load(resp)
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise RuntimeError(f"grok api unreachable: {e}") from e
        text = body["choices"][0]["message"]["content"]
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"grok returned invalid JSON: {text[:200]}") from e
