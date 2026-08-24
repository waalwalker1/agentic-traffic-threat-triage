"""Reproducible training and model evaluation pipeline."""

import argparse
from datetime import UTC, datetime
import json
from pathlib import Path
import sys
from typing import Any, cast

import joblib
import numpy as np
import pyarrow.parquet as pq
import torch

from src.traffic_triage.detection.calibration import ScoreCalibrator
from src.traffic_triage.detection.model_bundle import ModelManifest, compute_file_sha256
from src.traffic_triage.detection.pytorch_model import PyTorchThreatDetector
from src.traffic_triage.detection.supervised import SupervisedThreatClassifier
from src.traffic_triage.detection.unsupervised import UnsupervisedAnomalyDetector
from src.traffic_triage.features.extractor import FeatureExtractor, SessionFeatureVector
from src.traffic_triage.risk.fusion import RiskPolicy
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
    print("[1/6] Loading parquet dataset...", flush=True)
    data_path = Path(data_dir)
    parquet_path = data_path / "traffic_dataset.parquet"
    splits_path = data_path / "splits.json"

    if not parquet_path.exists() or not splits_path.exists():
        raise FileNotFoundError(f"Missing dataset fixtures in {data_dir}. Run 'make data' first.")

    dataset_sha256 = compute_file_sha256(parquet_path)
    events = load_parquet_events(str(parquet_path))
    with open(splits_path) as f:
        splits = json.load(f)

    print(f"[2/6] Sessionizing {len(events)} events...", flush=True)
    sessionizer = TelemetrySessionizer()
    sessions = sessionizer.sessionize(events)
    extractor = FeatureExtractor()

    print(f"[3/6] Extracting features across {len(sessions)} sessions...", flush=True)
    session_data: dict[str, tuple[SessionFeatureVector, int]] = {}
    for s in sessions:
        fv = extractor.extract_features(s.events, s.session_id)
        is_threat = (
            1 if any(e.synthetic_ground_truth in ("threat", "suspicious") for e in s.events) else 0
        )
        session_data[s.session_id] = (fv, is_threat)

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
        f"  Training set: {X_train.shape[0]} samples, Validation: {X_val.shape[0]}, Test: {X_test.shape[0]}",
        flush=True,
    )

    print("[4/6] Fitting detector baselines (Anomaly, Supervised, PyTorch)...", flush=True)
    anomaly_detector = UnsupervisedAnomalyDetector()
    anomaly_detector.fit(X_train)

    supervised_clf = SupervisedThreatClassifier()
    supervised_clf.fit(X_train, y_train)

    pytorch_detector = PyTorchThreatDetector(input_dim=X_train.shape[1])
    pyt_metrics = pytorch_detector.train_model(X_train, y_train, epochs=25)

    print("[5/6] Fitting Platt score calibrator on validation raw scores...", flush=True)
    policy = RiskPolicy()
    val_raw_scores = np.array(
        [
            float(
                policy.weights.supervised * supervised_clf.predict_proba(session_data[sid][0])
                + policy.weights.unsupervised * anomaly_detector.predict_score(session_data[sid][0])
                + policy.weights.pytorch * pytorch_detector.predict_score(session_data[sid][0])
            )
            for sid in val_ids
        ]
    )
    calibrator = ScoreCalibrator()
    calibrator.fit(val_raw_scores, y_val)
    val_calibrated = np.array([calibrator.calibrate(s) for s in val_raw_scores])
    calib_metrics = ScoreCalibrator.compute_metrics(y_val, val_calibrated)

    print("[6/6] Writing ModelBundle artifacts & manifest...", flush=True)
    current_bundle_dir = Path(output_dir) / "current"
    current_bundle_dir.mkdir(parents=True, exist_ok=True)

    joblib.dump(supervised_clf, current_bundle_dir / "supervised.joblib")
    joblib.dump(anomaly_detector, current_bundle_dir / "isolation_forest.joblib")
    joblib.dump(calibrator, current_bundle_dir / "calibrator.joblib")

    torch.save(
        {
            "model_state_dict": pytorch_detector.model.state_dict(),
            "mean": torch.tensor(pytorch_detector.mean, dtype=torch.float32),
            "std": torch.tensor(pytorch_detector.std, dtype=torch.float32),
        },
        current_bundle_dir / "pytorch_state.pt",
    )

    artifact_hashes = {
        "supervised.joblib": compute_file_sha256(current_bundle_dir / "supervised.joblib"),
        "isolation_forest.joblib": compute_file_sha256(current_bundle_dir / "isolation_forest.joblib"),
        "calibrator.joblib": compute_file_sha256(current_bundle_dir / "calibrator.joblib"),
        "pytorch_state.pt": compute_file_sha256(current_bundle_dir / "pytorch_state.pt"),
    }

    manifest = ModelManifest(
        bundle_version="1.0.0",
        feature_schema_version="1.0.0",
        risk_policy_version=policy.version,
        trained_at=datetime.now(UTC).isoformat(),
        dataset_sha256=dataset_sha256,
        artifact_sha256=artifact_hashes,
        supervised_model_version="1.0.0",
        anomaly_model_version="1.0.0",
        pytorch_model_version="1.0.0",
        calibrator_version="1.0.0",
        calibration_metrics={
            "brier_score": round(calib_metrics.brier_score, 4),
            "expected_calibration_error": round(calib_metrics.expected_calibration_error, 4),
        },
    )

    with open(current_bundle_dir / "model_manifest.json", "w") as f:
        json.dump(manifest.model_dump(mode="json"), f, indent=2)

    print(f"ModelBundle successfully saved to: {current_bundle_dir}", flush=True)
    print(f"  Brier Score: {calib_metrics.brier_score:.4f}, ECE: {calib_metrics.expected_calibration_error:.4f}", flush=True)

    return {
        "dataset_sha256": dataset_sha256,
        "bundle_dir": str(current_bundle_dir),
        "brier_score": calib_metrics.brier_score,
        "ece": calib_metrics.expected_calibration_error,
        "pytorch_loss": pyt_metrics["final_loss"],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Train baseline models and calibration")
    parser.add_argument("--data-dir", type=str, default="data/fixtures")
    parser.add_argument("--output-dir", type=str, default="artifacts/model_cards")
    args = parser.parse_args()

    run_training_pipeline(args.data_dir, args.output_dir)


if __name__ == "__main__":
    main()
