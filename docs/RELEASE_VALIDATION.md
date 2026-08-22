# Release Validation Report

- **Release Version**: v0.1.0
- **Validation Date**: 2026-08-22
- **Python Version**: 3.13.7 (Target: 3.12+)
- **Node.js Version**: v20.20.1 (Target: 20+)
- **Provider Mode**: DeterministicLocalProvider (Zero-Credential Canonical Mode)

## 1. Quality & Linting
- **Python Format & Lint (Ruff)**: PASS (0 errors)
- **Python Static Typing (mypy)**: PASS (Strict mode)
- **Frontend Typecheck (tsc)**: PASS
- **Frontend Production Build (Vite)**: PASS (dist/index.html & assets generated)

## 2. Test Execution
- **Unit & Protocol Tests**: 21/21 PASS
- **Security & Prompt Injection Tests**: 7/7 PASS (28 adversarial fixtures)
- **Integration Tests**: 3/3 PASS
- **E2E Verification**: PASS

## 3. Data & Benchmark Metrics (Held-out Test Split)
- **Synthetic Corpus**: 2,412 events across 150 sessions (30 scenario families)
- **Detection Precision**: 1.0000 (100.0%)
- **Detection Recall**: 0.9000 (90.0%)
- **Detection F1 Score**: 0.9474
- **ROC-AUC**: 0.9750
- **PR-AUC**: 0.9887
- **False Positive Rate (FPR)**: 0.0000 (0.0% across all benign hard negatives)
- **Brier Calibration Score**: 0.1144
- **Expected Calibration Error (ECE)**: 0.2598

## 4. Agent Groundedness & LLM Security
- **Evidence Citation Validity Rate**: 100.0% (30/30 verified)
- **Unsupported Claim Rate**: 0.0%
- **Risk Score Mutation Rate**: 0.0% (Zero mutations permitted)
- **Prompt Injection Defense Pass Rate**: 100.0% (28/28 fixtures defended)

## 5. Multi-Model Ablation Summary
- Rules Only F1: 0.0952
- Supervised Only F1: 0.9231
- Unsupervised IsolationForest F1: 0.2069
- PyTorch Neural Baseline F1: 0.9000
- **Final Fused Risk Policy F1: 0.9474** (Best ensemble performance)

## 6. Runtime & Security Audits
- **Defensive Scope Audit**: PASS (Zero live-site scanning or offensive bypass tooling)
- **Public Normalization Audit**: PASS (Zero non-neutral employment or subjective residue in tracked tree)
- **BUILD_SPEC.md & .build/ Ignored**: PASS (Properly excluded from git)

## Release Verdict
**RELEASE_READY**
