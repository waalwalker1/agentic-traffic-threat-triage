"""Supervised gradient-boosted classification baseline for session threat probability."""

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.preprocessing import StandardScaler

from src.traffic_triage.features.extractor import SessionFeatureVector


class SupervisedThreatClassifier:
    """Supervised tree-based classifier predicting threat probability."""

    def __init__(self, random_state: int = 42) -> None:
        self.model = HistGradientBoostingClassifier(
            max_iter=50,
            learning_rate=0.1,
            max_depth=5,
            early_stopping=False,
            random_state=random_state,
        )
        self.scaler = StandardScaler()
        self.is_fitted = False

    def fit(self, X: np.ndarray, y: np.ndarray) -> "SupervisedThreatClassifier":
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled, y)
        self.is_fitted = True
        return self

    def predict_proba(self, fv: SessionFeatureVector) -> float:
        if not self.is_fitted:
            return 0.5

        x = fv.to_array().reshape(1, -1)
        x_scaled = self.scaler.transform(x)
        probs = self.model.predict_proba(x_scaled)[0]
        # Probability of threat class (class 1)
        threat_prob = probs[1] if len(probs) > 1 else probs[0]
        return float(np.clip(threat_prob, 0.0, 1.0))
