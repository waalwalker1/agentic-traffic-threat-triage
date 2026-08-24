"""Synchronizes headline benchmark results from artifacts/evals/latest/summary.json into public documentation."""

import json
from pathlib import Path
import sys


def sync_metrics() -> None:
    summary_path = Path("artifacts/evals/latest/summary.json")
    if not summary_path.exists():
        print(f"Error: {summary_path} not found. Run benchmark suite first.")
        sys.exit(1)

    with open(summary_path) as f:
        summary = json.load(f)

    iid = summary.get("iid", {})
    ood = summary.get("family_holdout", {})
    hn = summary.get("hard_negatives", {})
    ground = summary.get("groundedness", {})
    critic = summary.get("critic", {})
    inj = summary.get("injection", {})

    print(f"Loaded benchmark summary (Version: {summary.get('benchmark_version')})")
    print(f"IID Precision: {iid.get('precision')} | Recall: {iid.get('recall')} | F1: {iid.get('f1')}")
    print(f"OOD 5-Fold F1: {ood.get('mean_f1')} ± {ood.get('std_f1')}")
    print(f"Hard-Negative FPR: {hn.get('false_positive_rate')} (95% CI: [{hn.get('wilson_95_ci', {}).get('lower')}, {hn.get('wilson_95_ci', {}).get('upper')}])")
    print(f"Citation Validity: {ground.get('citation_validity_rate') * 100:.1f}%")
    print(f"Critic Challenge Catch Rate: {critic.get('catch_rate') * 100:.1f}%")
    print(f"Injection Defense Pass Rate: {inj.get('pass_rate') * 100:.1f}%")


if __name__ == "__main__":
    sync_metrics()
