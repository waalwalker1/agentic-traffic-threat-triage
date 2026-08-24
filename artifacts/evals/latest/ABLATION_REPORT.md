# Architectural Component & Feature Ablations Report

| Configuration | Precision | Recall | F1 Score | Notes |
|---|---|---|---|---|
| A. Rules Only | 1.0000 | 0.0500 | 0.0952 | Deterministic threshold baselines |
| B. Supervised Only | 0.9444 | 0.8500 | 0.8947 | HistGradientBoosting |
| C. Anomaly Only | 1.0000 | 0.4000 | 0.5714 | Isolation Forest |
| D. PyTorch Only | 1.0000 | 0.9500 | 0.9744 | 2-layer neural MLP |
| **G. Full Risk Policy Fusion** | **1.0000** | **0.8500** | **0.9189** | **Operational policy with deterministic security overrides** |

### Identity & Protocol Ablations
- **Identity Feature Ablation** (on Identity Scenario Cohort):
  - With Identity Features: F1 = 0.8889, Recall = 0.8000
  - Without Identity Features: F1 = 0.8889, Recall = 1.0000
- **MCP Feature Ablation** (on MCP Protocol Cohort):
  - With MCP Features: F1 = 0.9744, Recall = 0.9500
  - Without MCP Features: F1 = 0.9189, Recall = 0.8500
