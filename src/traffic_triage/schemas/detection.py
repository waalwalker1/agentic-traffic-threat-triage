"""Canonical DetectionResult and RiskBand schemas."""

from datetime import UTC, datetime
from enum import StrEnum

from pydantic import BaseModel, Field


class RiskBand(StrEnum):
    """Discrete calibrated risk categories."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DetectionResult(BaseModel):
    """Multi-model detection scores and deterministic calibrated risk fusion."""

    session_id: str = Field(..., description="Target session identifier")
    rules_score: float = Field(..., ge=0.0, le=1.0, description="Deterministic rules score")
    supervised_score: float = Field(
        ..., ge=0.0, le=1.0, description="Supervised ML model probability"
    )
    anomaly_score: float = Field(
        ..., ge=0.0, le=1.0, description="Unsupervised anomaly detector score"
    )
    pytorch_score: float = Field(..., ge=0.0, le=1.0, description="PyTorch neural model score")

    # Distinct probability vs policy separation
    raw_model_score: float = Field(
        default=0.0, ge=0.0, le=1.0, description="Raw model ensemble score before calibration"
    )
    calibrated_model_probability: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Platt calibrated threat probability from model ensemble",
    )
    policy_risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Deterministic operational policy risk score with rule overrides",
    )
    calibrated_risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Operational risk score (retained for backward compatibility, mirrors policy_risk_score)",
    )
    risk_band: RiskBand = Field(..., description="Assigned discrete risk band")
    policy_override_codes: list[str] = Field(
        default_factory=list, description="Deterministic policy overrides applied"
    )
    model_versions: dict[str, str] = Field(
        default_factory=dict, description="Versions of models used"
    )
    feature_schema_version: str = Field(default="1.0.0", description="Feature schema version")
    reason_codes: list[str] = Field(
        default_factory=list, description="Deterministic reason codes triggered"
    )
    evidence_ids: list[str] = Field(
        default_factory=list, description="Referenced deterministic evidence IDs"
    )
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
