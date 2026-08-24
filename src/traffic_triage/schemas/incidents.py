"""Canonical IncidentBrief and triage workflow schemas."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field

from src.traffic_triage.schemas.detection import RiskBand


class DispositionStatus(StrEnum):
    BENIGN = "BENIGN"
    SUSPICIOUS_MONITOR = "SUSPICIOUS_MONITOR"
    CONFIRMED_ABUSE = "CONFIRMED_ABUSE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ESCALATED = "ESCALATED"


class AnalystDisposition(BaseModel):
    """Human analyst decision and review notes."""

    disposition: DispositionStatus
    analyst_id: str = Field(default="analyst_1")
    notes: str = Field(default="")
    applied_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class IntentHypothesis(BaseModel):
    """Evidence-grounded hypothesis regarding actor intent."""

    hypothesis: str = Field(..., description="Clear concise description of hypothesized intent")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence estimate (0.0-1.0)")
    supporting_evidence_ids: list[str] = Field(
        default_factory=list,
        description="List of existing deterministic evidence IDs supporting hypothesis",
    )
    contradicting_evidence_ids: list[str] = Field(
        default_factory=list, description="List of evidence IDs that challenge this hypothesis"
    )
    reasoning: str = Field(..., description="Logical explanation linking evidence to intent")


class NumericAssertion(BaseModel):
    """A specific numerical claim made in a brief that must match deterministic evidence."""

    metric_name: str = Field(..., description="Name of feature or evidence metric (e.g. requests_per_second)")
    claimed_value: float = Field(..., description="Claimed numeric value")
    tolerance: float = Field(default=0.05, description="Relative or absolute matching tolerance")
    verified_against_evidence_id: str | None = Field(default=None, description="Matched EvidenceItem ID")
    is_verified: bool = Field(default=False, description="Whether assertion matched deterministic observation")


class GroundedFinding(BaseModel):
    """An explicit factual claim strictly grounded in one or more deterministic EvidenceItems."""

    finding: str = Field(..., description="Factual discovery text")
    evidence_ids: list[str] = Field(
        default_factory=list, description="Mandatory citations to deterministic evidence items"
    )
    numeric_assertions: list[NumericAssertion] = Field(
        default_factory=list, description="Validated numerical statements"
    )
    is_factual: bool = Field(default=True, description="True for factual assertions requiring evidence")


class CriticReview(BaseModel):
    """Audit verdict from the Evidence Critic agent."""

    approved: bool = Field(
        ..., description="Whether the brief satisfies evidence grounding invariants"
    )
    rejected_reasons: list[str] = Field(default_factory=list, description="Reasons if rejected")
    invalid_evidence_ids: list[str] = Field(
        default_factory=list, description="Non-existent cited evidence IDs"
    )
    score_mutation_detected: bool = Field(
        default=False, description="Whether LLM attempted to mutate risk score"
    )
    unsupported_claim_detected: bool = Field(
        default=False, description="Whether factual claims lack supporting evidence IDs"
    )
    numeric_mismatch_detected: bool = Field(
        default=False, description="Whether numerical assertions disagree with evidence"
    )
    prompt_injection_flags: list[str] = Field(
        default_factory=list, description="Detected injection leakages"
    )


class IncidentBrief(BaseModel):
    """Final evidence-grounded SOC triage brief synthesized by the multi-agent crew."""

    incident_id: str = Field(..., description="Unique incident identifier")
    session_ids: list[str] = Field(..., description="Associated session IDs")
    risk_score: float = Field(
        ..., ge=0.0, le=1.0, description="Deterministic policy risk score (supervisor protected)"
    )
    risk_band: RiskBand = Field(..., description="Discrete risk category")
    identity_assessment: str = Field(..., description="Assessment of actor identity confidence")
    intent_hypotheses: list[IntentHypothesis] = Field(
        ..., description="Competing intent hypotheses"
    )
    mcp_activity_assessment: str | None = Field(
        default=None, description="Contextual MCP analysis if applicable"
    )
    grounded_findings: list[GroundedFinding] = Field(
        default_factory=list, description="Factual findings with strict evidence citations"
    )
    key_findings: list[str] = Field(
        default_factory=list, description="Bullet list of key factual discoveries (string view)"
    )
    evidence_citations: list[str] = Field(
        ..., description="Comprehensive list of cited EvidenceItem IDs"
    )
    alternative_explanations: list[str] = Field(
        ..., description="Alternative benign or edge-case interpretations"
    )
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall triage confidence")
    recommended_analyst_actions: list[str] = Field(
        ..., description="Actionable follow-up steps for SOC analyst"
    )
    known_limitations: list[str] = Field(..., description="Model, data, or context limitations")
    agent_trace_id: str = Field(..., description="Execution correlation trace ID")
    critic_review: CriticReview | None = Field(
        default=None, description="Evidence critic audit record"
    )
    analyst_disposition: AnalystDisposition | None = Field(
        default=None, description="Human analyst disposition"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
