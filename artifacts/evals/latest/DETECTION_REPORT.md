# Detection & Calibration Benchmark Report

## Headline Metrics (Held-out Test Split)
- **Precision**: 1.0000
- **Recall**: 0.9000
- **F1 Score**: 0.9474
- **ROC-AUC**: 0.9750
- **PR-AUC**: 0.9887
- **False Positive Rate**: 0.0000
- **Brier Score**: 0.1144
- **Expected Calibration Error (ECE)**: 0.2635

## Confusion Matrix
| Metric | Count |
|---|---|
| True Negatives (TN) | 10 |
| False Positives (FP) | 0 |
| False Negatives (FN) | 2 |
| True Positives (TP) | 18 |

## Hard-Negative Cohort Analysis
{
  "human_browsing": {
    "session_count": 1,
    "mean_risk_score": 0.2415,
    "false_positives": 0,
    "fpr": 0.0
  },
  "mobile_app_api": {
    "session_count": 1,
    "mean_risk_score": 0.2404,
    "false_positives": 0,
    "fpr": 0.0
  },
  "search_crawler": {
    "session_count": 1,
    "mean_risk_score": 0.1726,
    "false_positives": 0,
    "fpr": 0.0
  },
  "verified_ai_fetcher": {
    "session_count": 1,
    "mean_risk_score": 0.1108,
    "false_positives": 0,
    "fpr": 0.0
  },
  "mcp_discovery_benign": {
    "session_count": 1,
    "mean_risk_score": 0.2395,
    "false_positives": 0,
    "fpr": 0.0
  },
  "mcp_tool_use_benign": {
    "session_count": 1,
    "mean_risk_score": 0.4354,
    "false_positives": 0,
    "fpr": 0.0
  }
}
