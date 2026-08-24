"""ModelBundle container and safe cryptographic artifact loader."""

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import torch
from pydantic import BaseModel, Field

from src.traffic_triage.detection.calibration import ScoreCalibrator
from src.traffic_triage.detection.pytorch_model import PyTorchThreatDetector
from src.traffic_triage.detection.rules import RuleBaselineDetector
from src.traffic_triage.detection.supervised import SupervisedThreatClassifier
from src.traffic_triage.detection.unsupervised import UnsupervisedAnomalyDetector
from src.traffic_triage.features.extractor import FEATURE_NAMES, SessionFeatureVector
from src.traffic_triage.risk.fusion import RiskPolicy
from src.traffic_triage.schemas.detection import DetectionResult


def compute_file_sha256(file_path: Path | str) -> str:
    """Compute SHA-256 digest of a binary or text file."""
    sha = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha.update(chunk)
    return sha.hexdigest()


class ModelManifest(BaseModel):
    """Immutable metadata manifest for trained detector artifacts."""

    bundle_version: str = "1.0.0"
    feature_schema_version: str = "1.0.0"
    risk_policy_version: str = "2026.1.0"
    trained_at: str
    dataset_sha256: str
    artifact_sha256: dict[str, str]
    supervised_model_version: str = "1.0.0"
    anomaly_model_version: str = "1.0.0"
    pytorch_model_version: str = "1.0.0"
    calibrator_version: str = "1.0.0"
    calibration_metrics: dict[str, float] = Field(default_factory=dict)


class ModelBundleError(Exception):
    """Base exception for model bundle loading and verification failures."""


class ModelBundleNotFoundError(ModelBundleError):
    """Raised when bundle directory or manifest is missing."""


class ModelBundleSchemaMismatchError(ModelBundleError):
    """Raised when bundle feature schema or version does not match runtime."""


class ModelBundleCorruptError(ModelBundleError):
    """Raised when artifact SHA-256 hashes do not match manifest."""


@dataclass
class ModelBundle:
    """Encapsulates all verified detection model artifacts for runtime evaluation."""

    supervised: SupervisedThreatClassifier
    anomaly: UnsupervisedAnomalyDetector
    pytorch: PyTorchThreatDetector
    calibrator: ScoreCalibrator
    manifest: ModelManifest

    def evaluate_session(
        self,
        fv: SessionFeatureVector,
        rules_detector: RuleBaselineDetector,
        risk_policy: RiskPolicy,
    ) -> DetectionResult:
        """Execute deterministic multi-model inference and fuse into DetectionResult."""
        # 1. Deterministic rules evaluation
        rules_res = rules_detector.evaluate(fv)

        # 2. Individual model inferences
        supervised_prob = self.supervised.predict_proba(fv)
        anomaly_score = self.anomaly.predict_score(fv)
        pytorch_score = self.pytorch.predict_score(fv)

        # 3. Fuse scores via calibrated risk policy
        det_result = risk_policy.fuse_scores(
            session_id=fv.session_id,
            fv=fv,
            rules_score=rules_res.score,
            supervised_score=supervised_prob,
            anomaly_score=anomaly_score,
            pytorch_score=pytorch_score,
            reason_codes=rules_res.reason_codes,
            evidence_ids=[],
        )

        return det_result


class ModelBundleLoader:
    """Verifies SHA-256 digests and loads versioned ModelBundle artifacts."""

    REQUIRED_ARTIFACTS = [
        "supervised.joblib",
        "isolation_forest.joblib",
        "pytorch_state.pt",
        "calibrator.joblib",
    ]

    @classmethod
    def load(cls, bundle_dir: str | Path) -> ModelBundle:
        path = Path(bundle_dir)
        if not path.exists():
            raise ModelBundleNotFoundError(f"Model bundle directory not found: {path}")

        manifest_path = path / "model_manifest.json"
        if not manifest_path.exists():
            raise ModelBundleNotFoundError(f"Model manifest not found at: {manifest_path}")

        try:
            with open(manifest_path, encoding="utf-8") as f:
                manifest_data = json.load(f)
            manifest = ModelManifest.model_validate(manifest_data)
        except Exception as err:
            raise ModelBundleCorruptError(f"Failed to parse manifest: {err}") from err

        # Verify feature schema version
        if manifest.feature_schema_version != "1.0.0":
            raise ModelBundleSchemaMismatchError(
                f"Schema mismatch: bundle has {manifest.feature_schema_version}, expected 1.0.0"
            )

        # Verify cryptographic SHA-256 hashes for all required artifacts
        for artifact_name in cls.REQUIRED_ARTIFACTS:
            art_file = path / artifact_name
            if not art_file.exists():
                raise ModelBundleNotFoundError(f"Missing bundle artifact: {art_file}")

            expected_hash = manifest.artifact_sha256.get(artifact_name)
            if not expected_hash:
                raise ModelBundleCorruptError(
                    f"Manifest missing expected SHA-256 for: {artifact_name}"
                )

            actual_hash = compute_file_sha256(art_file)
            if actual_hash != expected_hash:
                raise ModelBundleCorruptError(
                    f"SHA-256 mismatch for {artifact_name}: expected {expected_hash}, got {actual_hash}"
                )

        # Load artifacts
        supervised = joblib.load(path / "supervised.joblib")
        anomaly = joblib.load(path / "isolation_forest.joblib")
        calibrator = joblib.load(path / "calibrator.joblib")

        # Reconstruct PyTorch model
        pt_data = torch.load(path / "pytorch_state.pt", map_location="cpu", weights_only=True)
        pytorch_model = PyTorchThreatDetector(input_dim=len(FEATURE_NAMES))
        pytorch_model.model.load_state_dict(pt_data["model_state_dict"])
        mean_data = pt_data["mean"]
        std_data = pt_data["std"]
        pytorch_model.mean = (
            mean_data.numpy()
            if isinstance(mean_data, torch.Tensor)
            else np.array(mean_data, dtype=np.float32)
        )
        pytorch_model.std = (
            std_data.numpy()
            if isinstance(std_data, torch.Tensor)
            else np.array(std_data, dtype=np.float32)
        )
        pytorch_model.is_trained = True

        return ModelBundle(
            supervised=supervised,
            anomaly=anomaly,
            pytorch=pytorch_model,
            calibrator=calibrator,
            manifest=manifest,
        )
