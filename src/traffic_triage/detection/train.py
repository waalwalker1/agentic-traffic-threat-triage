"""Reproducible training and model evaluation pipeline."""

import argparse
import json
from pathlib import Path
from typing import Any, cast

import joblib
import numpy as np
import pyarrow.parquet as pq

from src.traffic_triage.detection.calibration import ScoreCalibrator
from src.traffic_triage.detection.pytorch_model import PyTorchThreatDetector
from src.traffic_triage.detection.supervised import SupervisedThreatClassifier
from src.traffic_triage.detection.unsupervised import UnsupervisedAnomalyDetector
from src.traffic_triage.features.extractor import FeatureExtractor, SessionFeatureVector
from src.traffic_triage.schemas.events import TrafficEvent
from src.traffic_triage.telemetry.sessionizer import TelemetrySessionizer


def load_parquet_events(parquet_path: str) -> list[TrafficEvent]:
    table = pq.read_table(parquet_path)
    pydict = table.to_pydict()
    events: list[TrafficEvent] = []
    n = len(pydict["event_id"])
    for i in range(n):
        events.append(
            TrafficEvent(
                event_id=pydict["event_id"][i],
                schema_version=pydict["schema_version"][i],
                timestamp=pydict["timestamp"][i],
                session_id=pydict["session_id"][i],
                source_id_hash=pydict["source_id_hash"][i],
                request_method=pydict["request_method"][i],
                route_template=pydict["route_template"][i],
                status_code=pydict["status_code"][i],
                response_bytes=pydict["response_bytes"][i],
                latency_ms=pydict["latency_ms"][i],
                user_agent=pydict["user_agent"][i] or "",
                accept_language=pydict["accept_language"][i],
                header_names=json.loads(pydict["header_names"][i])
                if pydict["header_names"][i]
                else [],
                content_type=pydict["content_type"][i],
                has_auth_context=bool(pydict["has_auth_context"][i]),
                identity_claim=pydict["identity_claim"][i],
                identity_proof_type=pydict["identity_proof_type"][i],
                identity_proof_value=pydict["identity_proof_value"][i],
                identity_proof_valid=pydict["identity_proof_valid"][i],
                actor_hint=pydict["actor_hint"][i],
                mcp_method=pydict["mcp_method"][i],
                mcp_tool_category=pydict["mcp_tool_category"][i],
                synthetic_scenario_id=pydict["synthetic_scenario_id"][i],
                synthetic_ground_truth=pydict["synthetic_ground_truth"][i],
            )
        )
    return events


def run_training_pipeline(data_dir: str, output_dir: str) -> dict[str, Any]:
    data_path = Path(data_dir)
    parquet_path = data_path / "traffic_dataset.parquet"
    splits_path = data_path / "splits.json"

    if not parquet_path.exists() or not splits_path.exists():
        raise FileNotFoundError(f"Missing dataset fixtures in {data_dir}. Run 'make data' first.")

    events = load_parquet_events(str(parquet_path))
    with open(splits_path) as f:
        splits = json.load(f)

    sessionizer = TelemetrySessionizer()
    sessions = sessionizer.sessionize(events)
    extractor = FeatureExtractor()

    # Map session_id -> (feature_vector, ground_truth_label)
    session_data: dict[str, tuple[SessionFeatureVector, int]] = {}
    for s in sessions:
        fv = extractor.extract_features(s.events, s.session_id)
        # 1 for threat/suspicious, 0 for benign
        is_threat = (
            1 if any(e.synthetic_ground_truth in ("threat", "suspicious") for e in s.events) else 0
        )
        session_data[s.session_id] = (fv, is_threat)

    # Prepare Train / Val / Test arrays
    train_ids = splits["train"]
    val_ids = splits["validation"]
    test_ids = splits["test"]

    X_train = np.array(
        [session_data[sid][0].to_array() for sid in train_ids if sid in session_data]
    )
    y_train = np.array([session_data[sid][1] for sid in train_ids if sid in session_data])

    X_val = np.array([session_data[sid][0].to_array() for sid in val_ids if sid in session_data])
    y_val = np.array([session_data[sid][1] for sid in val_ids if sid in session_data])

    X_test = np.array([session_data[sid][0].to_array() for sid in test_ids if sid in session_data])

    print(
        f"Training set: {X_train.shape[0]} samples, Validation: {X_val.shape[0]}, Test: {X_test.shape[0]}"
    )

    # 1. Unsupervised Anomaly Detector
    anomaly_detector = UnsupervisedAnomalyDetector()
    anomaly_detector.fit(X_train)

    # 2. Supervised Threat Classifier
    supervised_clf = SupervisedThreatClassifier()
    supervised_clf.fit(X_train, y_train)

    # 3. PyTorch Threat Detector
    pytorch_detector = PyTorchThreatDetector(input_dim=X_train.shape[1])
    pyt_metrics = pytorch_detector.train_model(X_train, y_train, epochs=30)

    # 4. Score Calibrator on Validation set
    val_raw_scores = np.array(
        [supervised_clf.predict_proba(session_data[sid][0]) for sid in val_ids]
    )
    calibrator = ScoreCalibrator()
    calibrator.fit(val_raw_scores, y_val)
    val_calibrated = np.array([calibrator.calibrate(s) for s in val_raw_scores])
    calib_metrics = ScoreCalibrator.compute_metrics(y_val, val_calibrated)

    # Save artifacts
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    artifacts = {
        "anomaly_detector": anomaly_detector,
        "supervised_classifier": supervised_clf,
        "pytorch_detector": pytorch_detector,
        "calibrator": calibrator,
        "validation_metrics": {
            "brier_score": calib_metrics.brier_score,
            "expected_calibration_error": calib_metrics.expected_calibration_error,
            "pytorch_training_loss": pyt_metrics["final_loss"],
        },
    }

    joblib.dump(artifacts, out_path / "trained_models.joblib")

    # Generate MODEL_CARD.md
    model_card = f"""# Model Card: Traffic Threat Detection Baseline Ensemble

## Model Summary
- **Ensemble Components**:
  1. Rule Baseline (`RuleBaselineDetector_v1.0.0`)
  2. Unsupervised Anomaly Detector (`IsolationForest` on session feature matrix)
  3. Supervised Threat Classifier (`HistGradientBoostingClassifier` with StandardScaler)
  4. Neural Network (`PyTorchThreatDetector` 2-layer MLP with BatchNorm & Dropout)
  5. Probability Calibrator (`PlattSigmoidCalibrator`)
  6. Deterministic Policy (`RiskPolicy_v2026.1.0`)

## Training & Validation Setup
- **Dataset**: Synthetic Traffic Corpus v1.0.0 ({len(events)} events, 150 sessions across 30 scenario families)
- **Splits**: Group-aware split by session instance (Train: {len(train_ids)} sessions, Val: {len(val_ids)} sessions, Test: {len(test_ids)} sessions)
- **Validation Brier Score**: {calib_metrics.brier_score:.4f}
- **Validation ECE**: {calib_metrics.expected_calibration_error:.4f}
- **PyTorch Training Final Loss**: {pyt_metrics["final_loss"]:.4f}

## Quantitative Performance (Held-out Validation)
- Calibration Brier Score: {calib_metrics.brier_score:.4f}
- Expected Calibration Error: {calib_metrics.expected_calibration_error:.4f}

## Limitations & Non-Goals
- Evaluated solely on synthetic scenario fixtures.
- Does not represent real-world fraud or bot distributions.
- Models provide input to the deterministic risk supervisor; generative agents cannot overwrite scores.
"""
    with open("docs/MODEL_CARD.md", "w") as f:
        f.write(model_card)

    print("Model training complete. Artifacts saved.")
    return cast(dict[str, Any], artifacts["validation_metrics"])


def main() -> None:
    parser = argparse.ArgumentParser(description="Train detection models")
    parser.add_argument("--data-dir", type=str, default="data/fixtures")
    parser.add_argument("--output-dir", type=str, default="artifacts/model_cards")
    args = parser.parse_args()

    run_training_pipeline(args.data_dir, args.output_dir)


if __name__ == "__main__":
    main()
