import numpy as np

from src.traffic_triage.detection.calibration import ScoreCalibrator
from src.traffic_triage.detection.pytorch_model import PyTorchThreatDetector
from src.traffic_triage.detection.rules import RuleBaselineDetector
from src.traffic_triage.detection.supervised import SupervisedThreatClassifier
from src.traffic_triage.detection.unsupervised import UnsupervisedAnomalyDetector
from src.traffic_triage.features.extractor import FEATURE_NAMES, SessionFeatureVector


def test_rule_baseline_detection():
    detector = RuleBaselineDetector()

    # Benign session features
    benign_fv = SessionFeatureVector(
        session_id="s_benign",
        features={
            "requests_per_second": 1.2,
            "auth_failure_ratio": 0.0,
            "identity_claim_proof_match": 1.0,
        },
    )
    benign_res = detector.evaluate(benign_fv)
    assert benign_res.score < 0.3
    assert "BENIGN_BEHAVIORAL_PROFILE" in benign_res.reason_codes

    # Hostile burst session features
    burst_fv = SessionFeatureVector(
        session_id="s_burst",
        features={"requests_per_second": 45.0, "auth_failure_ratio": 0.0},
    )
    burst_res = detector.evaluate(burst_fv)
    assert burst_res.score >= 0.4
    assert "HIGH_FREQUENCY_BURST_RATE" in burst_res.reason_codes


def test_supervised_and_unsupervised_lifecycle():
    X_train = np.random.randn(20, len(FEATURE_NAMES)).astype(np.float32)
    y_train = np.random.choice([0, 1], size=20)

    # Unsupervised
    iso = UnsupervisedAnomalyDetector()
    iso.fit(X_train)
    score_iso = iso.predict_score(
        SessionFeatureVector(session_id="s1", features=dict.fromkeys(FEATURE_NAMES, 0.0))
    )
    assert 0.0 <= score_iso <= 1.0

    # Supervised
    clf = SupervisedThreatClassifier()
    clf.fit(X_train, y_train)
    score_clf = clf.predict_proba(
        SessionFeatureVector(session_id="s1", features=dict.fromkeys(FEATURE_NAMES, 0.0))
    )
    assert 0.0 <= score_clf <= 1.0


def test_pytorch_detector_lifecycle():
    X_train = np.random.randn(20, len(FEATURE_NAMES)).astype(np.float32)
    y_train = np.random.choice([0, 1], size=20).astype(np.float32)

    pyt = PyTorchThreatDetector(input_dim=len(FEATURE_NAMES))
    metrics = pyt.train_model(X_train, y_train, epochs=5)
    assert "final_loss" in metrics

    score = pyt.predict_score(
        SessionFeatureVector(session_id="s1", features=dict.fromkeys(FEATURE_NAMES, 0.0))
    )
    assert 0.0 <= score <= 1.0


def test_score_calibrator():
    calib = ScoreCalibrator()
    raw = np.array([0.1, 0.2, 0.8, 0.9])
    labels = np.array([0, 0, 1, 1])
    calib.fit(raw, labels)

    cal_val = calib.calibrate(0.85)
    assert 0.0 <= cal_val <= 1.0

    metrics = ScoreCalibrator.compute_metrics(labels, raw, n_bins=2)
    assert metrics.brier_score >= 0.0


def test_model_bundle_calibration_execution():
    from src.traffic_triage.detection.model_bundle import ModelBundle, ModelManifest
    from src.traffic_triage.risk.fusion import RiskPolicy

    X_train = np.random.randn(20, len(FEATURE_NAMES)).astype(np.float32)
    y_train = np.random.choice([0, 1], size=20)

    iso = UnsupervisedAnomalyDetector()
    iso.fit(X_train)

    clf = SupervisedThreatClassifier()
    clf.fit(X_train, y_train)

    pyt = PyTorchThreatDetector(input_dim=len(FEATURE_NAMES))
    pyt.train_model(X_train, y_train.astype(np.float32), epochs=5)

    calib = ScoreCalibrator()
    calib.fit(np.array([0.1, 0.2, 0.8, 0.9]), np.array([0, 0, 1, 1]))

    manifest = ModelManifest(
        bundle_version="1.0.0",
        feature_schema_version="1.0.0",
        risk_policy_version="2026.1.0",
        trained_at="2026-08-24T00:00:00Z",
        dataset_sha256="test_sha",
        artifact_sha256={},
        supervised_model_version="1.0.0",
        anomaly_model_version="1.0.0",
        pytorch_model_version="1.0.0",
        calibrator_version="1.0.0",
    )

    bundle = ModelBundle(
        supervised=clf,
        anomaly=iso,
        pytorch=pyt,
        calibrator=calib,
        manifest=manifest,
    )

    fv = SessionFeatureVector(
        session_id="test_calib_s1", features=dict.fromkeys(FEATURE_NAMES, 0.0)
    )
    rules_det = RuleBaselineDetector()
    policy = RiskPolicy()

    det_res = bundle.evaluate_session(fv, rules_det, policy)
    expected_calibrated = bundle.calibrator.calibrate(det_res.raw_model_score)

    assert abs(det_res.calibrated_model_probability - expected_calibrated) < 1e-4
