from src.traffic_triage.features.extractor import SessionFeatureVector
from src.traffic_triage.risk.fusion import RiskPolicy
from src.traffic_triage.schemas.detection import RiskBand


def test_risk_policy_fusion_and_bands():
    policy = RiskPolicy()

    # Clean low risk
    fv_clean = SessionFeatureVector(
        session_id="s_clean",
        features={
            "identity_confidence": 0.95,
            "identity_proof_valid": 1.0,
            "requests_per_second": 1.0,
            "auth_failure_ratio": 0.0,
        },
    )
    res_clean = policy.fuse_scores(
        session_id="s_clean",
        fv=fv_clean,
        rules_score=0.05,
        supervised_score=0.05,
        anomaly_score=0.1,
        pytorch_score=0.05,
        reason_codes=[],
        evidence_ids=[],
    )
    assert res_clean.risk_band == RiskBand.LOW
    assert res_clean.calibrated_risk_score <= 0.20

    # High risk with identity mismatch
    fv_mismatch = SessionFeatureVector(
        session_id="s_mismatch",
        features={
            "identity_confidence": 0.2,
            "identity_claim_proof_match": 0.0,
            "identity_proof_present": 1.0,
            "identity_proof_valid": 0.0,
            "requests_per_second": 5.0,
            "auth_failure_ratio": 0.0,
        },
    )
    res_mismatch = policy.fuse_scores(
        session_id="s_mismatch",
        fv=fv_mismatch,
        rules_score=0.5,
        supervised_score=0.6,
        anomaly_score=0.5,
        pytorch_score=0.5,
        reason_codes=[],
        evidence_ids=["E-ID-001"],
    )
    assert res_mismatch.risk_band in (RiskBand.HIGH, RiskBand.CRITICAL)
    assert res_mismatch.calibrated_risk_score >= 0.80
    assert "RISK_OVERRIDE_IDENTITY_MISMATCH" in res_mismatch.reason_codes
