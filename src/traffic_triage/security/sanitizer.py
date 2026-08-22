"""Telemetry sanitization and instruction boundary defense."""

import html
import unicodedata

MAX_HEADER_LENGTH = 512
MAX_ROUTE_LENGTH = 256
MAX_UA_LENGTH = 512


def sanitize_telemetry_string(raw_text: str | None, max_length: int = MAX_HEADER_LENGTH) -> str:
    """Sanitizes untrusted telemetry strings to prevent prompt injection and control character abuse."""
    if raw_text is None:
        return ""

    # Normalize Unicode to NFKC
    normalized = unicodedata.normalize("NFKC", str(raw_text))

    # Strip dangerous bidirectional control characters and ASCII control chars (except standard whitespace)
    cleaned = "".join(
        ch
        for ch in normalized
        if unicodedata.category(ch) not in ("Cc", "Cf") or ch in (" ", "\t", "\n")
    )

    # Escape HTML/XML entities so injected tags cannot break out of <curated_evidence> XML boundaries
    escaped = html.escape(cleaned, quote=True)

    # Truncate to maximum permitted length
    if len(escaped) > max_length:
        escaped = escaped[:max_length] + " [TRUNCATED]"

    return escaped.strip()


def wrap_untrusted_data(label: str, content: str) -> str:
    """Wraps untrusted forensic data in explicit, un-executable XML boundary tags."""
    clean_content = sanitize_telemetry_string(content)
    return f'<{label} is_untrusted="true">{clean_content}</{label}>'
