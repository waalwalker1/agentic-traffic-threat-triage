"""Unsupervised anomaly detection baseline using Isolation Forest."""

import numpy as np
from sklearn.ensemble import IsolationForest

from src.traffic_triage.features.extractor import SessionFeatureVector


class UnsupervisedAnomalyDetector:
    """Isolation Forest based anomaly detector for high-dimensional session features."""

    def __init__(self, contamination: float = 0.25, random_state: int = 42) -> None:
        self.model = IsolationForest(
            n_estimators=100,
            contamination=contamination,
            random_state=random_state,
        )
        self.is_fitted = False

    def fit(self, X: np.ndarray) -> "UnsupervisedAnomalyDetector":
        self.model.fit(X)
        self.is_fitted = True
        return self

    def predict_score(self, fv: SessionFeatureVector) -> float:
        if not self.is_fitted:
            return 0.5

        x = fv.to_array().reshape(1, -1)
        # Decision function: lower values mean more anomalous.
        raw_score = self.model.decision_function(x)[0]
        # Normalize decision function (typically in range [-0.3, 0.3]) to [0.0, 1.0]
        # where 1.0 is highly anomalous and 0.0 is normal.
        norm_score = 1.0 / (1.0 + np.exp(raw_score * 8.0))
        return float(np.clip(norm_score, 0.0, 1.0))
