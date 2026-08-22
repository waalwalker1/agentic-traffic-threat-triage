"""Defensive safety boundary validator ensuring zero live-site scanning or external offensive tooling."""

import re
from urllib.parse import urlparse


class DefensiveSafetyBoundary:
    """Enforces P0 defensive-only invariant across inputs, ingest, and evaluation."""

    ALLOWLISTED_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "testserver"}

    OFFENSIVE_KEYWORD_PATTERNS = [
        r"\bcaptcha_bypass\b",
        r"\banti_bot_evasion\b",
        r"\bcf_clearance\b",
        r"\bdatadome_bypass\b",
        r"\bcredential_stuffing\b",
        r"\bpassword_spray\b",
        r"\bexploit_payload\b",
        r"\bport_scan\b",
    ]

    @classmethod
    def validate_target_url(cls, url: str) -> None:
        """Validates that a URL is not an unauthorized external target."""
        if not url:
            return

        parsed = urlparse(url)
        hostname = parsed.hostname

        if hostname and hostname.lower() not in cls.ALLOWLISTED_HOSTS:
            raise PermissionError(
                f"DEFENSIVE SAFETY INVARIANT VIOLATION: External network target '{hostname}' is prohibited. "
                "The platform executes strictly against local synthetic fixtures or repository services."
            )

    @classmethod
    def audit_code_safety(cls, text: str) -> list[str]:
        """Audits text or scripts for offensive bot evasion or exploit keywords."""
        findings = []
        for pattern in cls.OFFENSIVE_KEYWORD_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                findings.append(f"Prohibited offensive capability pattern detected: {pattern}")
        return findings
