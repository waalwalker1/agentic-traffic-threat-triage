"""Canonical TrafficEvent schema."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class TrafficEvent(BaseModel):
    """Represents a single atomic HTTP/API/MCP traffic observation."""

    event_id: str = Field(..., description="Unique event identifier")
    schema_version: str = Field(default="1.0.0", description="Schema contract version")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="UTC timestamp of event observation",
    )
    session_id: str = Field(..., description="Correlated session identifier")
    source_id_hash: str = Field(..., description="Pseudonymous SHA-256 hash of source entity")
    request_method: str = Field(..., description="HTTP/RPC verb (GET, POST, MCP_CALL, etc.)")
    route_template: str = Field(..., description="Normalized endpoint route path")
    status_code: int = Field(default=200, description="HTTP or RPC response status code")
    response_bytes: int = Field(default=0, ge=0, description="Response payload length in bytes")
    latency_ms: float = Field(default=0.0, ge=0.0, description="Roundtrip latency in milliseconds")
    user_agent: str = Field(default="", description="Observed User-Agent header")
    accept_language: str | None = Field(
        default=None, description="Accept-Language header if present"
    )
    header_names: list[str] = Field(
        default_factory=list, description="List of present header names"
    )
    content_type: str | None = Field(default=None, description="Observed Content-Type header")
    has_auth_context: bool = Field(
        default=False, description="Whether authenticated credentials were provided"
    )
    identity_claim: str | None = Field(
        default=None, description="Claimed identity string/actor name"
    )
    identity_proof_type: str | None = Field(
        default=None, description="Type of identity proof (none, ed25519_signature, web_bot_auth)"
    )
    identity_proof_value: str | None = Field(
        default=None, description="Raw signature or proof token"
    )
    identity_proof_valid: bool | None = Field(
        default=None, description="Cryptographic verification result"
    )
    actor_hint: str | None = Field(
        default=None, description="Contextual category hint (e.g. human, crawler, agent)"
    )
    mcp_method: str | None = Field(default=None, description="MCP method if MCP RPC event")
    mcp_tool_category: str | None = Field(
        default=None, description="Sanitized category of MCP tool"
    )
    synthetic_scenario_id: str | None = Field(
        default=None, description="Benchmark scenario reference"
    )
    synthetic_ground_truth: str | None = Field(
        default=None, description="Benchmark ground truth label"
    )

    @field_validator("timestamp", mode="before")
    @classmethod
    def ensure_tz(cls, v: Any) -> Any:
        if isinstance(v, str):
            dt = datetime.fromisoformat(v)
            return dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        if isinstance(v, datetime) and v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v
