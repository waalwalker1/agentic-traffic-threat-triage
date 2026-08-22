"""Canonical EvidenceItem and CuratedEvidenceBundle schemas."""

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


class EvidenceItem(BaseModel):
    """Immutable atomic evidence unit derived deterministically from telemetry."""

    evidence_id: str = Field(..., description="Unique evidence reference (e.g. E-VOL-001)")
    session_id: str = Field(..., description="Associated session ID")
    kind: str = Field(
        ...,
        description="Category of evidence: volumetric, temporal, behavioral, identity, mcp, security, model_anomaly",
    )
    source_event_ids: list[str] = Field(
        default_factory=list, description="List of specific event IDs that ground this evidence"
    )
    feature_name: str = Field(..., description="Feature name or rule trigger key")
    observed_value: Any = Field(..., description="Measured numeric or categorical value")
    expected_range_or_context: str = Field(
        ..., description="Baseline context or threshold description"
    )
    severity_hint: Literal["low", "medium", "high", "critical", "informational"] = Field(
        default="informational", description="Heuristic severity indication"
    )
    human_readable_explanation: str = Field(..., description="Verifiable factual explanation")
    provenance: str = Field(
        default="rule_engine_v1", description="Algorithm or component that emitted evidence"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Evidence generation timestamp",
    )


class CuratedEvidenceBundle(BaseModel):
    """Sanitized, bounded evidence package provided to analyst AI agents."""

    session_id: str
    risk_score: float
    risk_band: str
    detector_scores: dict[str, float]
    model_versions: dict[str, str]
    evidence_items: list[EvidenceItem]
    sanitized_event_excerpts: list[dict[str, Any]] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
