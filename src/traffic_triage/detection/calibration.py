"""Calibration analytics and probability scaling for threat detection scores."""

from typing import NamedTuple

import numpy as np
from sklearn.calibration import calibration_curve
from sklearn.linear_model import LogisticRegression


class CalibrationMetrics(NamedTuple):
    brier_score: float
    expected_calibration_error: float
    prob_true: list[float]
    prob_pred: list[float]


class ScoreCalibrator:
    """Calibrates raw detector scores using Platt scaling / sigmoid fitting."""

    def __init__(self) -> None:
        self.calibrator = LogisticRegression(C=1.0, solver="lbfgs")
        self.is_fitted = False

    def fit(self, raw_scores: np.ndarray, labels: np.ndarray) -> "ScoreCalibrator":
        X = raw_scores.reshape(-1, 1)
        self.calibrator.fit(X, labels)
        self.is_fitted = True
        return self

    def calibrate(self, raw_score: float) -> float:
        if not self.is_fitted:
            return raw_score
        x = np.array([[raw_score]])
        prob = self.calibrator.predict_proba(x)[0][1]
        return float(np.clip(prob, 0.0, 1.0))

    @staticmethod
    def compute_metrics(
        y_true: np.ndarray,
        y_prob: np.ndarray,
        n_bins: int = 10,
    ) -> CalibrationMetrics:
        """Compute Brier Score, ECE, and reliability curve bins."""
        brier = float(np.mean((y_prob - y_true) ** 2))

        prob_true, prob_pred = calibration_curve(y_true, y_prob, n_bins=n_bins, strategy="uniform")

        # Compute Expected Calibration Error (ECE)
        bin_edges = np.linspace(0.0, 1.0, n_bins + 1)
        ece = 0.0
        n_samples = len(y_true)

        for i in range(n_bins):
            bin_mask = (y_prob >= bin_edges[i]) & (y_prob < bin_edges[i + 1])
            bin_count = np.sum(bin_mask)
            if bin_count > 0:
                bin_acc = np.mean(y_true[bin_mask])
                bin_conf = np.mean(y_prob[bin_mask])
                ece += (bin_count / n_samples) * abs(bin_acc - bin_conf)

        return CalibrationMetrics(
            brier_score=round(brier, 4),
            expected_calibration_error=round(float(ece), 4),
            prob_true=[round(float(x), 4) for x in prob_true],
            prob_pred=[round(float(x), 4) for x in prob_pred],
        )
