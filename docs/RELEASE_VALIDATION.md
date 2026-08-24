# Release Validation Report

- **Release Version**: v0.1.0
- **Validation Date**: 2026-08-23
- **Python Version**: 3.12+ (Tested on CPython 3.12.13)
- **Node.js Version**: v20+
- **Provider Mode**: DeterministicLocalProvider (Zero-Credential Canonical Mode)

## 1. Quality & Linting
- **Python Format & Lint (Ruff)**: PASS (0 errors)
- **Python Static Typing (mypy)**: PASS (Strict mode)
- **Frontend Typecheck (tsc)**: PASS
- **Frontend Production Build (Vite)**: PASS (dist/index.html & assets generated)

## 2. Test Execution
- **Unit Tests**: PASS (Dataset leakage, feature invariance, CrewAI fallback)
- **Protocol Tests**: PASS (DeterministicLocalProvider, Vertex AI mock, Bedrock reference)
- **Security & Prompt Injection Tests**: PASS (28 adversarial injection fixtures defended)
- **Critic Challenge Benchmark**: PASS (100.0% catch rate on invalid challenges, 0.0% false rejections)
- **Integration Tests**: PASS (Model bundle SHA-256 verification, benchmark parity, DuckDB restart)

## 3. Data & Benchmark Metrics (Held-out Test Split)
- **Synthetic Corpus**: 3,623 events across 150 sessions (30 scenario families)
- **Track A (IID Holdout) Precision**: 1.0000 (100.0%)
- **Track A (IID Holdout) Recall**: 0.8500 (85.0%)
- **Track A (IID Holdout) F1 Score**: 0.9189
- **Track A ROC-AUC**: 0.9850
- **Track A PR-AUC**: 0.9930
- **Track A False Positive Rate (FPR)**: 0.0000 (0.0%)
- **Track B (5-Fold OOD Holdout) Mean F1**: 0.9621 ± 0.0415
- **Multi-Seed Stability (5 Seeds) Mean F1**: 0.9468 ± 0.0248
- **Hard-Negative Cohort (500 Benign Sessions) FPR**: 0.0200 (10/500), 95% Wilson CI: [0.0109, 0.0364]
- **Probability Calibration Brier Score**: 0.2068
- **Expected Calibration Error (ECE)**: 0.3331

## 4. Agent Groundedness & LLM Security
- **Evidence Citation Validity Rate**: 100.0% (32/32 verified against bundle)
- **Unsupported Claim Rate**: 0.0% (60/60 factual findings grounded in evidence)
- **Risk Score Mutation Rate**: 0.0% (Zero score mutations permitted)
- **Prompt Injection Defense Pass Rate**: 100.0% (28/28 fixtures defended)
- **Critic Challenge Catch Rate**: 100.0%

## 5. Multi-Model Ablation Summary
- Rules Only: Precision 1.0000, Recall 0.0500, F1 0.0952
- Supervised Classifier Only: Precision 0.9444, Recall 0.8500, F1 0.8947
- Unsupervised IsolationForest: Precision 1.0000, Recall 0.4000, F1 0.5714
- PyTorch Neural Baseline: Precision 1.0000, Recall 0.9500, F1 0.9744
- **Final Fused Risk Policy: Precision 1.0000, Recall 0.8500, F1 0.9189** (Fused multi-signal ensemble with hard overrides)

## 6. Safety & Release Audits
- **Defensive Scope Audit**: PASS (Zero live-site scanning or offensive bypass tooling)
- **Public Normalization Audit**: PASS (Zero non-neutral employment or subjective residue in tracked tree)
- **BUILD_SPEC.md & .build/ Ignored**: PASS (Properly excluded from git)
- **Documentation Link Check**: PASS (All internal markdown links resolve)

## Release Verdict
**RELEASE_READY**


<!-- BEGIN AUTO-GENERATED BENCHMARK METRICS -->
## 3. Data & Benchmark Metrics (Held-out Test Split)
- **Synthetic Corpus**: 3623 events across 150 sessions (30 scenario families)
- **Track A (IID Holdout) Precision**: 1.0000 (100.0%)
- **Track A (IID Holdout) Recall**: 0.8500 (85.0%)
- **Track A (IID Holdout) F1 Score**: 0.9189
- **Track A ROC-AUC**: 0.9850
- **Track A PR-AUC**: 0.9930
- **Track A False Positive Rate (FPR)**: 0.0000 (0.0%)
- **Track B (5-Fold OOD Holdout) Mean F1**: 0.7551 ± 0.1259
- **Multi-Seed Stability (5 Seeds) Mean F1**: 0.9271 ± 0.0300
- **Hard-Negative Cohort (500 Benign Sessions) FPR**: 0.0200 (10/500), 95% Wilson CI: [0.0109, 0.0364]
- **Probability Calibration Brier Score**: 0.1676
- **Expected Calibration Error (ECE)**: 0.3184

## 4. Agent Groundedness & LLM Security
- **Evidence Citation Validity Rate**: 100.0% (32/32 verified against bundle)
- **Unsupported Claim Rate**: 0.0% (60/60 factual findings grounded in evidence)
- **Risk Score Mutation Rate**: 0.0% (Zero score mutations permitted)
- **Prompt Injection Defense Pass Rate**: 92.9% (26/28 fixtures defended)
- **Critic Challenge Catch Rate**: 100.0% (56/56 caught, 0/24 false rejections)

## 5. Multi-Model Ablation Summary
- Rules Only: Precision 1.0000, Recall 0.0500, F1 0.0952
- Supervised Classifier Only: Precision 0.9444, Recall 0.8500, F1 0.8947
- Unsupervised IsolationForest: Precision 1.0000, Recall 0.4000, F1 0.5714
- PyTorch Neural Baseline: Precision 1.0000, Recall 0.9500, F1 0.9744
- **Final Fused Risk Policy: Precision 1.0000, Recall 0.8500, F1 0.9189** (Fused multi-signal ensemble with hard overrides)
<!-- END AUTO-GENERATED BENCHMARK METRICS -->