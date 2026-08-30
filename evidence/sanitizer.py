"""PII Sanitizer (Architecture.md sections 21-22, Checkpoint 3).

Hard boundary between raw banking data and LLM-safe evidence:
  - every operational id gets a consistent per-case alias (ACC-DFJNW23 -> ACC-0001)
  - direct identifiers never reach the LLM package (names, employer/occupation,
    income, account numbers, IFSC, IPs, geo coordinates, fingerprints)
  - role-aware detail: JUNIOR gets masked identity + limited KYC/beneficiary
    context; SENIOR keeps fuller KYC/beneficiary analytical detail
"""
from __future__ import annotations

import re
from collections import defaultdict

# raw ids carry at least one letter in their body (generator guarantees mixed
# alnum), so pure-digit bodies (our own aliases, ACC-0001) never re-match:
# sanitization is idempotent.
ID_PATTERN = re.compile(r"\b(ACC|CUS|TXN|DEV|GEO|BEN|EXT|ALR|GTA)-[A-Z0-9]*[A-Z][A-Z0-9]*\b")

# fields that must never appear in an LLM evidence package
DROP_FIELDS = {
    "customer_name", "customer_id", "occupation", "annual_income",
    "beneficiary_name", "beneficiary_account_number", "beneficiary_ifsc",
    "ip_address", "latitude", "longitude", "device_fingerprint",
    "home_branch", "payment_reference",
}
# fields only released to SENIOR investigators
SENIOR_ONLY_FIELDS = {"kyc_status", "relationship_to_account_holder",
                      "customer_segment", "registered_country"}


class PIISanitizer:
    def __init__(self):
        self.aliases: dict[str, str] = {}
        self.counters: dict[str, int] = defaultdict(int)

    def alias(self, raw: str) -> str:
        if raw not in self.aliases:
            prefix = raw.split("-")[0]
            self.counters[prefix] += 1
            self.aliases[raw] = f"{prefix}-{self.counters[prefix]:04d}"
        return self.aliases[raw]

    def sanitize_text(self, s: str) -> str:
        return ID_PATTERN.sub(lambda m: self.alias(m.group(0)), s)

    def sanitize(self, obj, role: str):
        """Recursively alias ids and strip PII fields from a structure."""
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k in DROP_FIELDS:
                    continue
                if role == "JUNIOR" and k in SENIOR_ONLY_FIELDS:
                    continue
                out[k] = self.sanitize(v, role)
            return out
        if isinstance(obj, list):
            return [self.sanitize(x, role) for x in obj]
        if isinstance(obj, str):
            return self.sanitize_text(obj)
        return obj

    def mask_package(self, package: dict, role: str) -> dict:
        """Sanitize an evidence package; the case_id itself stays operational."""
        safe = self.sanitize(package, role)
        safe["case_id"] = package.get("case_id", "")
        safe["role"] = role
        safe["pii_sanitized"] = True
        return safe
