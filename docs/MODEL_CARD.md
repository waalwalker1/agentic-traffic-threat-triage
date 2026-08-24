# Model Card: Traffic Threat Detection Baseline Ensemble

## Model Summary
- **Ensemble Components**:
  1. Rule Baseline (`RuleBaselineDetector_v1.0.0`)
  2. Unsupervised Anomaly Detector (`IsolationForest` on 32-feature session matrix)
  3. Supervised Threat Classifier (`HistGradientBoostingClassifier` with StandardScaler)
  4. Neural Network (`PyTorchThreatDetector` 2-layer MLP with LayerNorm & Dropout)
  5. Probability Calibrator (`ScoreCalibrator` via Platt Sigmoid Scaling)
  6. Deterministic Policy (`RiskPolicy_v2026.1.0` with hard rule overrides)

## Training & Validation Setup
- **Dataset**: Synthetic Traffic Corpus v1.0.0 (3,623 events, 150 sessions across 30 scenario families)
- **Dataset SHA-256**: `523f9d8d813dd49f05c73543bc83afe8ef9f494a47d1a9110ee2a27e0116cbdb`
- **Trained At**: `2026-08-24T10:24:50.778076+00:00`
- **Splits**: Group-aware split by session instance (Train: 90 sessions, Val: 30 sessions, Test: 30 sessions)
- **PyTorch Architecture**: Input (32 dims) -> Linear(64) -> LayerNorm(64) -> ReLU() -> Dropout(0.2) -> Linear(32) -> LayerNorm(32) -> ReLU() -> Dropout(0.2) -> Linear(1) -> Sigmoid()

## Quantitative Performance (Held-out Validation & Test)
- **Calibration Brier Score**: 0.1676
- **Expected Calibration Error (ECE)**: 0.3184
- **Calibration Target**: Continuous ensemble probability is calibrated before deterministic operational policy overrides.

## Operational Policy Fusion vs Raw Neural F1 Rationale
- The PyTorch neural baseline achieves high unconstrained raw F1 on pattern recognition tasks.
- However, operational SOC environments demand deterministic security guarantees and strict interpretability.
- The fused `RiskPolicy` incorporates deterministic hard-rule overrides:
  - `RISK_OVERRIDE_IDENTITY_MISMATCH` (Forces min risk 0.85 on cryptographic key forgery)
  - `RISK_OVERRIDE_CREDENTIAL_ABUSE` (Forces min risk 0.80 on authentication failure bursts >= 50%)
  - `RISK_OVERRIDE_BURST_VOLUME` (Forces min risk 0.75 on volumetric floods >= 30 rps)
  - `RISK_DISCOUNT_VERIFIED_BENIGN` (Reduces risk <= 0.20 when verified cryptographically and behavior is nominal)
- These hard guarantees prioritize containment and false-negative prevention on high-severity attacks over unconstrained mathematical F1 optimization.

## Limitations & Non-Goals
- Evaluated solely on synthetic scenario fixtures.
- Does not represent real-world fraud or bot distributions.
- Models provide input to the deterministic risk supervisor; generative agents cannot overwrite numeric scores.
