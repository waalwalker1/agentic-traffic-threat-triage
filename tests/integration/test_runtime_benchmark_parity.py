"""Integration test asserting exact numeric parity between evaluation pipeline and API runtime."""

import pytest
from fastapi.testclient import TestClient

from apps.api.main import app, container
from src.traffic_triage.detection.model_bundle import ModelBundleLoader
from src.traffic_triage.detection.rules import RuleBaselineDetector
from src.traffic_triage.detection.train import load_parquet_events
from src.traffic_triage.features.extractor import FeatureExtractor
from src.traffic_triage.risk.fusion import RiskPolicy


def test_runtime_benchmark_parity_on_held_out_session():
    # 1. Load trained bundle in standalone evaluation mode
    bundle = ModelBundleLoader.load("artifacts/model_cards/current")
    rules_det = RuleBaselineDetector()
    policy = RiskPolicy()

    # 2. Get first session from fixtures
    events = load_parquet_events("data/fixtures/traffic_dataset.parquet")
    test_session_id = events[0].session_id
    session_events = [e for e in events if e.session_id == test_session_id]

    extractor = FeatureExtractor()
    fv = extractor.extract_features(session_events, test_session_id)

    # Standalone evaluation pipeline output
    eval_result = bundle.evaluate_session(fv, rules_det, policy)

    # 3. Fast-API runtime output
    container.bundle_dir = "artifacts/model_cards/current"
    container.model_mode = "trained"
    container._initialize_models()

    with TestClient(app) as client:
        r = client.post(f"/api/v1/sessions/{test_session_id}/detect")
        assert r.status_code == 200
        api_result = r.json()

        # 4. Assert strict parity across all components
        assert api_result["session_id"] == eval_result.session_id
        assert api_result["supervised_score"] == pytest.approx(
            eval_result.supervised_score, abs=1e-4
        )
        assert api_result["anomaly_score"] == pytest.approx(eval_result.anomaly_score, abs=1e-4)
        assert api_result["pytorch_score"] == pytest.approx(eval_result.pytorch_score, abs=1e-4)
        assert api_result["raw_model_score"] == pytest.approx(eval_result.raw_model_score, abs=1e-4)
        assert api_result["calibrated_model_probability"] == pytest.approx(
            eval_result.calibrated_model_probability, abs=1e-4
        )
        assert api_result["policy_risk_score"] == pytest.approx(
            eval_result.policy_risk_score, abs=1e-4
        )
        assert api_result["risk_band"] == eval_result.risk_band.value
        assert set(api_result["reason_codes"]) == set(eval_result.reason_codes)
