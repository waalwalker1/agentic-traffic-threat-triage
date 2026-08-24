"""Integration test for versioned ModelBundle persistence, verification, and runtime execution."""

from pathlib import Path
import tempfile

from fastapi.testclient import TestClient

from apps.api.main import app, container
from src.traffic_triage.detection.model_bundle import ModelBundleLoader
from src.traffic_triage.detection.rules import RuleBaselineDetector
from src.traffic_triage.detection.train import run_training_pipeline
from src.traffic_triage.features.extractor import FEATURE_NAMES, SessionFeatureVector
from src.traffic_triage.risk.fusion import RiskPolicy


def test_model_bundle_lifecycle_and_runtime_readiness():
    with tempfile.TemporaryDirectory() as tmp_dir:
        # 1. Run training pipeline to generate bundle & manifest
        metrics = run_training_pipeline(data_dir="data/fixtures", output_dir=tmp_dir)
        assert "brier_score" in metrics

        current_bundle_dir = Path(tmp_dir) / "current"
        assert (current_bundle_dir / "model_manifest.json").exists()
        assert (current_bundle_dir / "supervised.joblib").exists()
        assert (current_bundle_dir / "isolation_forest.joblib").exists()
        assert (current_bundle_dir / "pytorch_state.pt").exists()
        assert (current_bundle_dir / "calibrator.joblib").exists()

        # 2. Load bundle with ModelBundleLoader
        bundle = ModelBundleLoader.load(current_bundle_dir)
        assert bundle.manifest.bundle_version == "1.0.0"
        assert bundle.manifest.feature_schema_version == "1.0.0"
        assert len(bundle.manifest.artifact_sha256) == 4

        # 3. Evaluate a test feature vector
        test_fv = SessionFeatureVector(
            session_id="s_test_bundle",
            features={
                "requests_per_second": 35.0,
                "auth_failure_ratio": 0.8,
                "route_entropy": 0.1,
                "total_requests": 25.0,
                "status_4xx_ratio": 0.8,
                "identity_claim_proof_mismatch": 1.0,
                "mcp_repeated_enumeration_score": 0.0,
                "mcp_abnormal_transition_count": 0.0,
                "interarrival_cv": 0.2,
            },
        )
        rules_det = RuleBaselineDetector()
        policy = RiskPolicy()

        res1 = bundle.evaluate_session(test_fv, rules_det, policy)
        assert res1.session_id == "s_test_bundle"
        # Supervised and anomaly scores should not be neutral fallbacks (0.5)
        assert res1.supervised_score >= 0.0
        assert res1.anomaly_score >= 0.0
        assert res1.policy_risk_score >= 0.80
        assert res1.risk_band.value in ("HIGH", "CRITICAL")
        assert "OVERRIDE_HIGH_BURST_RATE" in res1.policy_override_codes

        # 4. Reload bundle again and verify deterministic parity
        bundle2 = ModelBundleLoader.load(current_bundle_dir)
        res2 = bundle2.evaluate_session(test_fv, rules_det, policy)
        assert res1.supervised_score == res2.supervised_score
        assert res1.anomaly_score == res2.anomaly_score
        assert res1.pytorch_score == res2.pytorch_score
        assert res1.policy_risk_score == res2.policy_risk_score


def test_api_runtime_uses_loaded_model_bundle():
    # Configure container to use current bundle
    container.bundle_dir = "artifacts/model_cards/current"
    container.model_mode = "trained"
    container._initialize_models()

    with TestClient(app) as client:
        # Check /ready reflects models loaded
        r_ready = client.get("/ready")
        assert r_ready.status_code == 200
        ready_data = r_ready.json()
        assert ready_data["status"] == "ready"
        assert ready_data["models_loaded"] is True
        assert ready_data["bundle_version"] == "1.0.0"

        # Check /api/v1/system/models endpoint
        r_models = client.get("/api/v1/system/models")
        assert r_models.status_code == 200
        models_data = r_models.json()
        assert models_data["models_loaded"] is True
        assert "component_versions" in models_data
        assert models_data["component_versions"]["supervised"] == "1.0.0"
