# Model Card: Traffic Threat Detection Baseline Ensemble

## Model Summary
- **Ensemble Components**:
  1. Rule Baseline (`RuleBaselineDetector_v1.0.0`)
  2. Unsupervised Anomaly Detector (`IsolationForest` on session feature matrix)
  3. Supervised Threat Classifier (`HistGradientBoostingClassifier` with StandardScaler)
  4. Neural Network (`PyTorchThreatDetector` 2-layer MLP with BatchNorm & Dropout)
  5. Probability Calibrator (`PlattSigmoidCalibrator`)
  6. Deterministic Policy (`RiskPolicy_v2026.1.0`)

## Training & Validation Setup
- **Dataset**: Synthetic Traffic Corpus v1.0.0 (2412 events, 150 sessions across 30 scenario families)
- **Splits**: Group-aware split by session instance (Train: 90 sessions, Val: 30 sessions, Test: 30 sessions)
- **Validation Brier Score**: 0.0964
- **Validation ECE**: 0.2061
- **PyTorch Training Final Loss**: 0.0840

## Quantitative Performance (Held-out Validation)
- Calibration Brier Score: 0.0964
- Expected Calibration Error: 0.2061

## Limitations & Non-Goals
- Evaluated solely on synthetic scenario fixtures.
- Does not represent real-world fraud or bot distributions.
- Models provide input to the deterministic risk supervisor; generative agents cannot overwrite scores.
