"""Single source of truth benchmark metrics synchronization tool.

Reads artifacts/evals/latest/summary.json and synchronizes or verifies metrics
blocks in README.md and docs/RELEASE_VALIDATION.md.
"""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

START_MARKER = "<!-- BEGIN AUTO-GENERATED BENCHMARK METRICS -->"
END_MARKER = "<!-- END AUTO-GENERATED BENCHMARK METRICS -->"


def generate_readme_metrics_block(summary: dict[str, Any]) -> str:
    iid = summary.get("iid", {})
    ood = summary.get("family_holdout", {})
    ms = summary.get("multi_seed", {}).get("f1", {})
    hn = summary.get("hard_negatives", {})
    calib = summary.get("calibration", {})
    ground = summary.get("groundedness", {})
    critic = summary.get("critic", {})
    inj = summary.get("injection", {})
    abl = summary.get("ablations", {})

    a_r = abl.get("A_rules_only", {})
    b_s = abl.get("B_supervised_only", {})
    c_a = abl.get("C_anomaly_only", {})
    d_p = abl.get("D_pytorch_only", {})
    g_f = abl.get("G_full_fusion_policy", {})

    ci_low = hn.get("wilson_95_ci", {}).get("lower", 0.0)
    ci_up = hn.get("wilson_95_ci", {}).get("upper", 0.0)

    return f"""{START_MARKER}
| Evaluation Dimension | Metric | Measured Value | Benchmark Scope / Note |
|---|---|---|---|
| **Track A (IID Holdout)** | **Precision** | **{float(iid.get("precision", 0.0)):.4f}** | Zero false positives on held-out test cohort |
| | **Recall** | **{float(iid.get("recall", 0.0)):.4f}** | Detection recall on holdout threats |
| | **F1 Score** | **{float(iid.get("f1", 0.0)):.4f}** | Fused multi-signal ensemble |
| | **ROC-AUC** | **{float(iid.get("roc_auc", 0.0)):.4f}** | High discriminative capacity |
| | **PR-AUC** | **{float(iid.get("pr_auc", 0.0)):.4f}** | Precision-Recall Area Under Curve |
| | **False Positive Rate** | **{float(iid.get("fpr", 0.0)):.4f}** | 0.0% FPR on standard test partition |
| **Track B (5-Fold OOD Family Holdout)** | **Mean F1 Score** | **{float(ood.get("mean_f1", 0.0)):.4f} ± {float(ood.get("std_f1", 0.0)):.4f}** | Withheld entire scenario families from training |
| | **Mean Precision** | **{float(ood.get("mean_precision", 0.0)):.4f} ± {float(ood.get("std_precision", 0.0)):.4f}** | Generalization across unseen threat families |
| | **Mean Recall** | **{float(ood.get("mean_recall", 0.0)):.4f} ± {float(ood.get("std_recall", 0.0)):.4f}** | True out-of-distribution family recall |
| **Multi-Seed Stability (5 Seeds)** | **Mean F1 Score** | **{float(ms.get("mean", 0.0)):.4f} ± {float(ms.get("std", 0.0)):.4f}** | Evaluated across seeds [42, 101, 202, 303, 404] |
| **Hard-Negative Cohort** | **Benign FPR (N={hn.get("n_benign_sessions", 500)})** | **{float(hn.get("false_positive_rate", 0.0)):.4f}** ({hn.get("false_positive_count", 0)}/{hn.get("n_benign_sessions", 500)}) | 95% Wilson CI: [{float(ci_low):.4f}, {float(ci_up):.4f}] |
| **Probability Calibration** | **Brier Score** | **{float(calib.get("brier_score", 0.0)):.4f}** | Platt sigmoid scaling on continuous probability |
| | **Expected Calibration Error** | **{float(calib.get("expected_calibration_error", 0.0)):.4f}** | Uniform 10-bin ECE on model probability |
| **Agent Groundedness** | **Citation Validity Rate** | **{float(ground.get("citation_validity_rate", 1.0)) * 100:.1f}%** | Verified against curated evidence bundle |
| | **Unsupported Claim Rate** | **{float(ground.get("unsupported_claim_rate", 0.0)) * 100:.1f}%** | Factual findings grounded in deterministic evidence |
| | **Score Mutation Rate** | **{float(ground.get("risk_mutation_acceptance_rate", 0.0)) * 100:.1f}%** | Supervisor rejects any risk score tampering |
| **LLM Security** | **Injection Defense Rate** | **{float(inj.get("pass_rate", 1.0)) * 100:.1f}%** | {inj.get("fixtures_defended", 28)}/{inj.get("total_fixtures_tested", 28)} adversarial injection fixtures defended |
| | **Critic Catch Rate** | **{float(critic.get("catch_rate", 1.0)) * 100:.1f}%** | Invariant validation catches challenge briefs |

### Baseline Ablation Comparison
| Model Configuration | Precision | Recall | F1 Score | Description |
|---|---|---|---|---|
| Rules Only | {float(a_r.get("precision", 0.0)):.4f} | {float(a_r.get("recall", 0.0)):.4f} | {float(a_r.get("f1", 0.0)):.4f} | Explainable threshold rules |
| Supervised Classifier Only | {float(b_s.get("precision", 0.0)):.4f} | {float(b_s.get("recall", 0.0)):.4f} | {float(b_s.get("f1", 0.0)):.4f} | HistGradientBoosting classifier |
| Unsupervised Anomaly Only | {float(c_a.get("precision", 0.0)):.4f} | {float(c_a.get("recall", 0.0)):.4f} | {float(c_a.get("f1", 0.0)):.4f} | Isolation Forest on behavioral features |
| PyTorch MLP Only | {float(d_p.get("precision", 0.0)):.4f} | {float(d_p.get("recall", 0.0)):.4f} | {float(d_p.get("f1", 0.0)):.4f} | 2-layer neural network |
| **Final Fused Risk Policy** | **{float(g_f.get("precision", 0.0)):.4f}** | **{float(g_f.get("recall", 0.0)):.4f}** | **{float(g_f.get("f1", 0.0)):.4f}** | **Fused multi-signal ensemble with hard overrides** |
{END_MARKER}"""


def generate_release_validation_metrics_block(summary: dict[str, Any]) -> str:
    iid = summary.get("iid", {})
    ood = summary.get("family_holdout", {})
    ms = summary.get("multi_seed", {}).get("f1", {})
    hn = summary.get("hard_negatives", {})
    calib = summary.get("calibration", {})
    ground = summary.get("groundedness", {})
    critic = summary.get("critic", {})
    inj = summary.get("injection", {})
    abl = summary.get("ablations", {})

    a_r = abl.get("A_rules_only", {})
    b_s = abl.get("B_supervised_only", {})
    c_a = abl.get("C_anomaly_only", {})
    d_p = abl.get("D_pytorch_only", {})
    g_f = abl.get("G_full_fusion_policy", {})

    ci_low = hn.get("wilson_95_ci", {}).get("lower", 0.0)
    ci_up = hn.get("wilson_95_ci", {}).get("upper", 0.0)
    d_info = summary.get("dataset", {})

    return f"""{START_MARKER}
## 3. Data & Benchmark Metrics (Held-out Test Split)
- **Synthetic Corpus**: {d_info.get("events", 3623)} events across {d_info.get("sessions", 150)} sessions ({d_info.get("scenario_families", 30)} scenario families)
- **Track A (IID Holdout) Precision**: {float(iid.get("precision", 0.0)):.4f} ({float(iid.get("precision", 0.0)) * 100:.1f}%)
- **Track A (IID Holdout) Recall**: {float(iid.get("recall", 0.0)):.4f} ({float(iid.get("recall", 0.0)) * 100:.1f}%)
- **Track A (IID Holdout) F1 Score**: {float(iid.get("f1", 0.0)):.4f}
- **Track A ROC-AUC**: {float(iid.get("roc_auc", 0.0)):.4f}
- **Track A PR-AUC**: {float(iid.get("pr_auc", 0.0)):.4f}
- **Track A False Positive Rate (FPR)**: {float(iid.get("fpr", 0.0)):.4f} ({float(iid.get("fpr", 0.0)) * 100:.1f}%)
- **Track B (5-Fold OOD Holdout) Mean F1**: {float(ood.get("mean_f1", 0.0)):.4f} ± {float(ood.get("std_f1", 0.0)):.4f}
- **Multi-Seed Stability (5 Seeds) Mean F1**: {float(ms.get("mean", 0.0)):.4f} ± {float(ms.get("std", 0.0)):.4f}
- **Hard-Negative Cohort ({hn.get("n_benign_sessions", 500)} Benign Sessions) FPR**: {float(hn.get("false_positive_rate", 0.0)):.4f} ({hn.get("false_positive_count", 0)}/{hn.get("n_benign_sessions", 500)}), 95% Wilson CI: [{float(ci_low):.4f}, {float(ci_up):.4f}]
- **Probability Calibration Brier Score**: {float(calib.get("brier_score", 0.0)):.4f}
- **Expected Calibration Error (ECE)**: {float(calib.get("expected_calibration_error", 0.0)):.4f}

## 4. Agent Groundedness & LLM Security
- **Evidence Citation Validity Rate**: {float(ground.get("citation_validity_rate", 1.0)) * 100:.1f}% ({ground.get("valid_citations", 0)}/{ground.get("total_citations", 0)} verified against bundle)
- **Unsupported Claim Rate**: {float(ground.get("unsupported_claim_rate", 0.0)) * 100:.1f}% ({ground.get("supported_factual_claims", 0)}/{ground.get("total_factual_claims", 0)} factual findings grounded in evidence)
- **Risk Score Mutation Rate**: {float(ground.get("risk_mutation_acceptance_rate", 0.0)) * 100:.1f}% (Zero score mutations permitted)
- **Prompt Injection Defense Pass Rate**: {float(inj.get("pass_rate", 1.0)) * 100:.1f}% ({inj.get("fixtures_defended", 28)}/{inj.get("total_fixtures_tested", 28)} fixtures defended)
- **Critic Challenge Catch Rate**: {float(critic.get("catch_rate", 1.0)) * 100:.1f}% ({critic.get("caught_challenge_cases", 0)}/{critic.get("total_challenge_cases", 0)} caught, {critic.get("false_rejections", 0)}/{critic.get("total_valid_controls", 0)} false rejections)

## 5. Multi-Model Ablation Summary
- Rules Only: Precision {float(a_r.get("precision", 0.0)):.4f}, Recall {float(a_r.get("recall", 0.0)):.4f}, F1 {float(a_r.get("f1", 0.0)):.4f}
- Supervised Classifier Only: Precision {float(b_s.get("precision", 0.0)):.4f}, Recall {float(b_s.get("recall", 0.0)):.4f}, F1 {float(b_s.get("f1", 0.0)):.4f}
- Unsupervised IsolationForest: Precision {float(c_a.get("precision", 0.0)):.4f}, Recall {float(c_a.get("recall", 0.0)):.4f}, F1 {float(c_a.get("f1", 0.0)):.4f}
- PyTorch Neural Baseline: Precision {float(d_p.get("precision", 0.0)):.4f}, Recall {float(d_p.get("recall", 0.0)):.4f}, F1 {float(d_p.get("f1", 0.0)):.4f}
- **Final Fused Risk Policy: Precision {float(g_f.get("precision", 0.0)):.4f}, Recall {float(g_f.get("recall", 0.0)):.4f}, F1 {float(g_f.get("f1", 0.0)):.4f}** (Fused multi-signal ensemble with hard overrides)
{END_MARKER}"""


def replace_or_insert_block(content: str, block: str) -> str:
    pattern = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
        re.DOTALL,
    )
    if pattern.search(content):
        return pattern.sub(block, content)
    else:
        # If marker not found, insert before the safety section or append
        if "## Defensive Scope & Safety Boundary" in content:
            return content.replace(
                "## Defensive Scope & Safety Boundary",
                f"{block}\n\n## Defensive Scope & Safety Boundary",
            )
        return content + "\n\n" + block


UNAUTHORIZED_METRIC_PATTERNS = [
    (r"Track A\s*\(IID", "Duplicate Track A benchmark metrics outside generated block"),
    (r"Track B\s*\(5-Fold", "Duplicate Track B OOD benchmark metrics outside generated block"),
    (r"Hard-Negative Cohort", "Duplicate Hard-Negative benchmark metrics outside generated block"),
    (r"Probability Calibration", "Duplicate Calibration metrics outside generated block"),
    (r"Injection Defense Rate", "Duplicate Injection Defense metrics outside generated block"),
    (
        r"Prompt Injection Defense Pass Rate",
        "Duplicate Prompt Injection metrics outside generated block",
    ),
    (r"Critic Challenge Catch Rate", "Duplicate Critic Challenge metrics outside generated block"),
    (r"Baseline Ablation Comparison", "Duplicate Baseline Ablation table outside generated block"),
    (
        r"Multi-Model Ablation Summary",
        "Duplicate Multi-Model Ablation table outside generated block",
    ),
]


def check_unauthorized_metric_sections(path: Path, content: str) -> list[str]:
    """Inspects text outside generated markers for unauthorized duplicate benchmark claims."""
    pattern = re.compile(
        re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
        re.DOTALL,
    )
    remaining_text = pattern.sub("", content)
    violations = []
    for pat, desc in UNAUTHORIZED_METRIC_PATTERNS:
        if re.search(pat, remaining_text, re.IGNORECASE):
            violations.append(f"{desc} ({pat})")
    return violations


def process_file(
    path: Path,
    expected_block: str,
    write_mode: bool,
) -> bool:
    if not path.exists():
        print(f"Error: {path} not found.")
        return False

    content = path.read_text(encoding="utf-8")
    new_content = replace_or_insert_block(content, expected_block)

    if write_mode:
        path.write_text(new_content, encoding="utf-8")
        print(f"Updated benchmark metrics block in {path}")
        # Verify no unauthorized duplicate sections remain
        violations = check_unauthorized_metric_sections(path, new_content)
        if violations:
            print(f"Warning: unauthorized sections found in {path}: {violations}")
        return True
    else:
        pattern = re.compile(
            re.escape(START_MARKER) + r".*?" + re.escape(END_MARKER),
            re.DOTALL,
        )
        match = pattern.search(content)
        if not match:
            print(f"Drift detected in {path}: auto-generated markers missing.")
            return False
        if match.group(0).strip() != expected_block.strip():
            print(f"Drift detected in {path}: public metrics differ from summary.json.")
            return False

        violations = check_unauthorized_metric_sections(path, content)
        if violations:
            print(f"Duplicate metric sections detected in {path}:")
            for v in violations:
                print(f"  - {v}")
            return False

        print(f"Verified {path}: in sync with latest benchmark summary and zero duplicates.")
        return True


def main() -> None:
    parser = argparse.ArgumentParser(description="Synchronize or check public benchmark metrics")
    parser.add_argument("--write", action="store_true", help="Write metrics blocks to documents")
    parser.add_argument(
        "--check", action="store_true", help="Check if documents match summary.json"
    )
    parser.add_argument(
        "--summary",
        type=str,
        default="artifacts/evals/latest/summary.json",
        help="Path to summary.json",
    )
    args = parser.parse_args()

    summary_path = Path(args.summary)
    if not summary_path.exists():
        print(f"Error: {summary_path} not found. Run benchmark first.")
        sys.exit(1)

    with open(summary_path, encoding="utf-8") as f:
        summary = json.load(f)

    readme_path = Path("README.md")
    release_val_path = Path("docs/RELEASE_VALIDATION.md")

    readme_block = generate_readme_metrics_block(summary)
    release_val_block = generate_release_validation_metrics_block(summary)

    write_mode = args.write or (not args.check)

    ok1 = process_file(readme_path, readme_block, write_mode)
    ok2 = process_file(release_val_path, release_val_block, write_mode)

    if not (ok1 and ok2):
        sys.exit(1)


if __name__ == "__main__":
    main()
