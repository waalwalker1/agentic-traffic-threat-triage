# Evaluation Methodology

## Benchmark Protocol
- **Dataset**: Seeded 30-scenario synthetic corpus (2,412 events, 150 sessions).
- **Split Strategy**: Group-aware split by session instance:
  - 60% Train (90 sessions)
  - 20% Validation (30 sessions, used for calibration)
  - 20% Held-Out Test (30 sessions, used strictly for final evaluation)
- **Metrics Tracked**: Precision, Recall, F1, ROC-AUC, PR-AUC, False Positive Rate (FPR), Brier Calibration Score, ECE, Citation Validity Rate, Prompt Injection Defense Rate.
