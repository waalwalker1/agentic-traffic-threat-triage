"""Deterministic RiskPolicy and multi-signal risk fusion engine."""

from datetime import UTC, datetime

from src.traffic_triage.features.extractor import SessionFeatureVector
from src.traffic_triage.schemas.detection import DetectionResult, RiskBand

POLICY_VERSION = "2026.1.0"


class RiskPolicy:
    """Combines rule, supervised, anomaly, PyTorch, and identity signals into deterministic risk."""

    def __init__(self, version: str = POLICY_VERSION) -> None:
        self.version = version

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

        # Base weighted fusion
        base_risk = (
            0.30 * supervised_score
            + 0.25 * rules_score
            + 0.15 * anomaly_score
            + 0.15 * pytorch_score
            + 0.15 * (1.0 - id_conf)
        )

        final_risk = base_risk

        # Deterministic hard-rule overrides
        if id_invalid or id_mismatch:
            final_risk = max(final_risk, 0.85)
            if "RISK_OVERRIDE_IDENTITY_MISMATCH" not in reason_codes:
                reason_codes.append("RISK_OVERRIDE_IDENTITY_MISMATCH")

        if auth_fail >= 0.50:
            final_risk = max(final_risk, 0.80)
            if "RISK_OVERRIDE_CREDENTIAL_ABUSE" not in reason_codes:
                reason_codes.append("RISK_OVERRIDE_CREDENTIAL_ABUSE")

        if rps >= 30.0:
            final_risk = max(final_risk, 0.75)
            if "RISK_OVERRIDE_BURST_VOLUME" not in reason_codes:
                reason_codes.append("RISK_OVERRIDE_BURST_VOLUME")

        # Benign cryptographic verification discount if behavioral signals are clean
        if is_verified and rules_score < 0.20 and rps < 10.0 and auth_fail == 0.0:
            final_risk = min(final_risk, 0.20)
            if "RISK_DISCOUNT_VERIFIED_BENIGN" not in reason_codes:
                reason_codes.append("RISK_DISCOUNT_VERIFIED_BENIGN")

        calibrated_risk = float(round(min(1.0, max(0.0, final_risk)), 4))

        # Assign discrete RiskBand
        if calibrated_risk >= 0.80:
            band = RiskBand.CRITICAL
        elif calibrated_risk >= 0.60:
            band = RiskBand.HIGH
        elif calibrated_risk >= 0.35:
            band = RiskBand.MEDIUM
        else:
            band = RiskBand.LOW

        return DetectionResult(
            session_id=session_id,
            rules_score=round(rules_score, 4),
            supervised_score=round(supervised_score, 4),
            anomaly_score=round(anomaly_score, 4),
            pytorch_score=round(pytorch_score, 4),
            calibrated_risk_score=calibrated_risk,
            risk_band=band,
            model_versions=model_versions or {"policy": self.version},
            feature_schema_version=fv.feature_schema_version,
            reason_codes=reason_codes,
            evidence_ids=evidence_ids,
            evaluated_at=datetime.now(UTC),
        )
