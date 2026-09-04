"""Gemini 3.6 Flash LLM provider boundary.

The investigation pipeline communicates with Gemini only through this client.
Provider configuration comes from environment variables.

The client performs bounded retries for transient rate-limit responses and
returns a parsed JSON object while preserving the existing agent contracts.
"""

from __future__ import annotations

import json
import os
import time

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from google import genai
from google.genai import types


MODEL = os.environ.get(
    "GEMINI_MODEL",
    "gemini-3.6-flash",
)

TIMEOUT = 90

MAX_RETRIES = 2
DEFAULT_RETRY_SECONDS = 5
MAX_RETRY_SECONDS = 30


class GeminiClient:
    """Thin Gemini API client returning parsed JSON."""

    def __init__(self):
        self.api_key = os.environ.get("GEMINI_API_KEY", "").strip()

        if not self.api_key:
            raise RuntimeError("GEMINI_API_KEY not configured")

        self.client = genai.Client(api_key=self.api_key)

    @staticmethod
    def _retry_delay(error: Exception) -> float:
        """Return a bounded retry delay."""

        retry_after = getattr(error, "headers", {}).get("Retry-After")

        if retry_after:
            try:
                return min(
                    max(float(retry_after), 0),
                    MAX_RETRY_SECONDS,
                )
            except (ValueError, TypeError):
                pass

        return DEFAULT_RETRY_SECONDS

    def complete(self, system: str, user: str) -> dict:
        """Call Gemini and return a parsed JSON object."""

        prompt = (
            system
            + "\n\nIMPORTANT OUTPUT REQUIREMENT:\n"
            "Return exactly one valid JSON object. "
            "Do not use Markdown fences. "
            "Do not add commentary before or after the JSON."
            "\n\nUSER INPUT:\n"
            + user
        )

        last_error: Exception | None = None

        for attempt in range(MAX_RETRIES + 1):
            try:
                response = self.client.models.generate_content(
                    model=MODEL,
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        temperature=0.2,
                        response_mime_type="application/json",
                    ),
                )

                text = (response.text or "").strip()

                if not text:
                    raise RuntimeError(
                        "Gemini returned an empty response"
                    )

                break

            except Exception as e:
                last_error = e

                # Retry transient/rate-limit failures.
                error_text = str(e).lower()

                transient = any(
                    marker in error_text
                    for marker in (
                        "429",
                        "rate limit",
                        "resource exhausted",
                        "temporarily unavailable",
                        "503",
                        "deadline exceeded",
                        "timeout",
                    )
                )

                if not transient or attempt >= MAX_RETRIES:
                    raise RuntimeError(
                        f"Gemini API request failed: {e}"
                    ) from e

                delay = self._retry_delay(e)

                print(
                    f"Gemini API transient error. "
                    f"Retrying in {delay:.1f}s "
                    f"(attempt {attempt + 1}/{MAX_RETRIES})"
                )

                time.sleep(delay)

        else:
            raise RuntimeError(
                f"Gemini API request failed: {last_error}"
            )

        # Defensive cleanup in case a provider response still contains fences.
        if text.startswith("```"):
            text = text[3:].strip()

            if text.startswith("json"):
                text = text[4:].strip()

            if text.endswith("```"):
                text = text[:-3].strip()

        try:
            result = json.loads(text)
        except json.JSONDecodeError as e:
            raise RuntimeError(
                f"Gemini returned invalid JSON: {text[:1000]}"
            ) from e

        if not isinstance(result, dict):
            raise RuntimeError(
                "Gemini returned valid JSON but it was not an object"
            )

        return result