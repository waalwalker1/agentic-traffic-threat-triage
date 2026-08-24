"""Deterministic RiskPolicy and multi-signal risk fusion engine."""

from dataclasses import dataclass
from datetime import UTC, datetime

from src.traffic_triage.features.extractor import SessionFeatureVector
from src.traffic_triage.schemas.detection import DetectionResult, RiskBand

POLICY_VERSION = "2026.1.0"


@dataclass
class PolicyWeights:
    rules: float = 0.25
    supervised: float = 0.30
    unsupervised: float = 0.15
    pytorch: float = 0.15
    identity_uncertainty: float = 0.15


@dataclass
class PolicyThresholds:
    critical: float = 0.80
    high: float = 0.60
    medium: float = 0.35


class RiskPolicy:
    """Combines rule, supervised, anomaly, PyTorch, and identity signals into deterministic policy risk."""

    def __init__(
        self,
        version: str = POLICY_VERSION,
        weights: PolicyWeights | None = None,
        thresholds: PolicyThresholds | None = None,
    ) -> None:
        self.version = version
        self.weights = weights or PolicyWeights()
        self.thresholds = thresholds or PolicyThresholds()

    def fuse_scores(
        self,
        session_id: str,
        fv: SessionFeatureVector,
        rules_score: float,
        supervised_score: float,
        anomaly_score: float,
        pytorch_score: float,
        reason_codes: list[str],
        evidence_ids: list[str],
        model_versions: dict[str, str] | None = None,
        calibrated_probability: float | None = None,
    ) -> DetectionResult:
        f = fv.features
        id_conf = f.get("identity_confidence", 0.5)
        id_mismatch = f.get("identity_claim_proof_match", 1.0) == 0.0
        id_invalid = (
            f.get("identity_proof_present", 0.0) == 1.0
            and f.get("identity_proof_valid", 0.0) == 0.0
        )
        rps = f.get("requests_per_second", 0.0)
        auth_fail = f.get("auth_failure_ratio", 0.0)
        is_verified = f.get("identity_proof_valid", 0.0) == 1.0

        # Continuous model ensemble score
        raw_model = float(
            self.weights.supervised * supervised_score
            + self.weights.unsupervised * anomaly_score
            + self.weights.pytorch * pytorch_score
        )
        raw_model = float(min(max(raw_model, 0.0), 1.0))
        calibrated_prob = calibrated_probability if calibrated_probability is not None else raw_model

        # Base operational fusion
        base_risk = (
            self.weights.supervised * supervised_score
            + self.weights.rules * rules_score
            + self.weights.unsupervised * anomaly_score
            + self.weights.pytorch * pytorch_score
            + self.weights.identity_uncertainty * (1.0 - id_conf)
        )

        final_policy_risk = base_risk
        override_codes: list[str] = []

        # Deterministic hard-rule overrides
        if id_invalid or id_mismatch:
            final_policy_risk = max(final_policy_risk, 0.85)
            override_codes.append("RISK_OVERRIDE_IDENTITY_MISMATCH")

        if auth_fail >= 0.50:
            final_policy_risk = max(final_policy_risk, 0.80)
            override_codes.append("RISK_OVERRIDE_CREDENTIAL_ABUSE")

        if rps >= 30.0:
            final_policy_risk = max(final_policy_risk, 0.75)
            override_codes.append("RISK_OVERRIDE_BURST_VOLUME")

        # Benign cryptographic verification discount if behavioral signals are clean
        if is_verified and rules_score < 0.20 and rps < 10.0 and auth_fail == 0.0:
            final_policy_risk = min(final_policy_risk, 0.20)
            override_codes.append("RISK_DISCOUNT_VERIFIED_BENIGN")

        final_policy_score = float(round(min(1.0, max(0.0, final_policy_risk)), 4))

        # Assign discrete RiskBand
        if final_policy_score >= self.thresholds.critical:
            band = RiskBand.CRITICAL
        elif final_policy_score >= self.thresholds.high:
            band = RiskBand.HIGH
        elif final_policy_score >= self.thresholds.medium:
            band = RiskBand.MEDIUM
        else:
            band = RiskBand.LOW

        all_reasons = sorted(list(set(reason_codes + override_codes)))

        return DetectionResult(
            session_id=session_id,
            rules_score=round(rules_score, 4),
            supervised_score=round(supervised_score, 4),
            anomaly_score=round(anomaly_score, 4),
            pytorch_score=round(pytorch_score, 4),
            raw_model_score=round(raw_model, 4),
            calibrated_model_probability=round(calibrated_prob, 4),
            policy_risk_score=final_policy_score,
            calibrated_risk_score=final_policy_score,
            risk_band=band,
            policy_override_codes=override_codes,
            model_versions=model_versions or {"policy": self.version},
            feature_schema_version=fv.feature_schema_version,
            reason_codes=all_reasons,
            evidence_ids=evidence_ids,
            evaluated_at=datetime.now(UTC),
        )
