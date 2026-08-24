"""Canonical TrafficSession schema."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from src.traffic_triage.schemas.events import TrafficEvent


class TrafficSession(BaseModel):
    """Aggregated session containing ordered traffic events and temporal context."""

    session_id: str = Field(..., description="Unique session identifier")
    start_time: datetime = Field(..., description="Timestamp of first event in session")
    end_time: datetime = Field(..., description="Timestamp of last event in session")
    event_count: int = Field(default=1, ge=1, description="Total number of events in session")
    duration_seconds: float = Field(default=0.0, ge=0.0, description="Session span in seconds")
    route_count: int = Field(default=1, ge=1, description="Count of unique routes accessed")
    actor_claims: list[str] = Field(
        default_factory=list, description="Distinct identity claims in session"
    )
    identity_evidence_summary: dict[str, Any] = Field(
        default_factory=dict, description="Aggregated identity verification state"
    )
    mcp_activity_summary: dict[str, Any] = Field(
        default_factory=dict, description="Aggregated MCP sequence counts and methods"
    )
    feature_vector_ref: str | None = Field(
        default=None, description="Reference key for computed feature vector"
    )
    events: list[TrafficEvent] = Field(
        default_factory=list, description="Chronological list of session events"
    )
