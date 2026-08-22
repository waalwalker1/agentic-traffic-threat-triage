"""Canonical Evaluation metrics schema."""

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, Field


class EvaluationSummary(BaseModel):
    """Comprehensive metrics summary for detection, agent groundedness, and security evals."""

    eval_id: str
    dataset_version: str
    dataset_hash: str
    scenario_count: int
    session_count: int
    detection_metrics: dict[str, Any] = Field(default_factory=dict)
    hard_negative_metrics: dict[str, Any] = Field(default_factory=dict)
    calibration_metrics: dict[str, Any] = Field(default_factory=dict)
    agent_groundedness_metrics: dict[str, Any] = Field(default_factory=dict)
    prompt_injection_metrics: dict[str, Any] = Field(default_factory=dict)
    ablation_metrics: dict[str, Any] = Field(default_factory=dict)
    runtime_metrics: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
