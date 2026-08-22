"""Intermediate structured schema contracts for multi-agent triage crew roles."""

from pydantic import BaseModel, Field

from src.traffic_triage.schemas.incidents import IntentHypothesis


class IdentityAgentOutput(BaseModel):
    identity_assessment: str = Field(
        ..., description="Evaluation of claimed vs verified actor identity"
    )
    identity_confidence: float = Field(..., ge=0.0, le=1.0)
    cited_evidence_ids: list[str] = Field(default_factory=list)
    ambiguities: list[str] = Field(default_factory=list)


class IntentAgentOutput(BaseModel):
    intent_hypotheses: list[IntentHypothesis] = Field(
        ..., description="Competing hypotheses regarding actor intent"
    )
    primary_hypothesis_name: str = Field(...)
    behavioral_summary: str = Field(...)
    cited_evidence_ids: list[str] = Field(default_factory=list)


class MCPAgentOutput(BaseModel):
    mcp_assessment: str = Field(..., description="Contextual evaluation of MCP protocol activity")
    conformance_status: str = Field(
        ..., description="NOMINAL, PROTOCOL_DEVIATION, SUSPICIOUS_PROBE, NOT_APPLICABLE"
    )
    cited_evidence_ids: list[str] = Field(default_factory=list)


class SynthesisAgentOutput(BaseModel):
    key_findings: list[str] = Field(..., description="Key factual findings grounded in evidence")
    primary_hypothesis: IntentHypothesis = Field(...)
    alternative_explanations: list[str] = Field(default_factory=list)
    recommended_analyst_actions: list[str] = Field(default_factory=list)
    overall_confidence: float = Field(..., ge=0.0, le=1.0)
    all_cited_evidence_ids: list[str] = Field(default_factory=list)


class CriticAgentOutput(BaseModel):
    approved: bool = Field(
        ..., description="True if evidence citations and score invariants are valid"
    )
    rejected_reasons: list[str] = Field(default_factory=list)
    invalid_evidence_ids: list[str] = Field(default_factory=list)
    score_mutation_detected: bool = Field(default=False)
    injection_leakage_detected: bool = Field(default=False)
