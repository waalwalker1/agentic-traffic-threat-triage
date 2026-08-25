# Agentic Traffic Threat Triage

> Defensive traffic-intelligence research platform combining deterministic features, calibrated detection models, agent identity/intent analysis, MCP activity signals, and evidence-grounded multi-agent SOC triage.

[![CI & Quality Gates](https://github.com/waalwalker1/agentic-traffic-threat-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/waalwalker1/agentic-traffic-threat-triage/actions)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## Overview

**Agentic Traffic Threat Triage** is an open-source defensive research reference implementation designed to analyze synthetic web, API, AI-agent, and Model Context Protocol (MCP) traffic. It extracts deterministic forensic evidence, executes a multi-model ensemble (Rules, Isolation Forest, Gradient Boosted Trees, and a PyTorch neural baseline), verifies cryptographic agent identities, and coordinates a constrained 6-role multi-agent SOC triage crew to produce evidence-grounded incident summaries.

The platform enforces a strict architectural boundary between the **Deterministic Data Plane** (which owns schema validation, feature extraction, signature verification, numeric scoring, calibration, and immutable evidence IDs) and the **Generative AI Plane** (which provides competing hypothesis formulation, forensic explanation, and analyst recommendations).

---

## System Architecture

```
[ Seeded Synthetic Telemetry (30 Scenario Families) ]
                         │
                         ▼
[ Schema Validation & Deterministic Sessionization ]
                         │
         ┌───────────────┴─────────────────────────────────┐
         ▼                                                 ▼
[ 32 Forensic Features Extraction ]           [ Cryptographic Identity Verification ]
         │                                                 │
         ├─────────────────────────────────────────────────┤
         ▼                                                 ▼
[ Multi-Model Detection Ensemble ]             [ MCP Sequence Semantics Analyzer ]
  - Rule Baseline (Explainable)                  - Conformance vs. Anomaly
  - Isolation Forest (Unsupervised)              - Repeated Discovery Probes
  - HistGradientBoosting (Supervised)            - Sequence Validity Score
  - PyTorch Neural MLP (CPU-runnable)                      │
         │                                                 │
         └───────────────────────┬─────────────────────────┘
                                 ▼
                 [ Calibrated Risk Fusion Policy ]
                                 │
                                 ▼
                     [ Curated Evidence Bundle ]
                                 │
                                 ▼
               [ 6-Role Constrained Multi-Agent Crew ]
      (Identity -> Intent -> MCP -> Synthesizer -> Critic)
                                 │
                                 ▼
                    [ Deterministic Supervisor ]
           (Risk Score Immutability & Citation Validation)
                                 │
                                 ▼
                 [ Evidence-Grounded Incident Brief ]
                                 │
                                 ▼
                [ FastAPI API & React SOC Dashboard ]
```

---

## Core Capabilities

- **Zero-Credential Local Path**: Complete offline execution, testing, and evaluation via `DeterministicLocalProvider`. No external cloud or LLM API keys required.
- **Agent Identity vs. Intent Separation**: Models identity verification (via Ed25519 cryptographic fixtures) independently from behavioral intent hypotheses.
- **First-Class MCP Activity Modeling**: Parses Model Context Protocol JSON-RPC methods (`initialize`, `tools/list`, `tools/call`, `prompts/list`, `resources/list`) to differentiate benign tool discovery from malicious enumeration.
- **Multi-Model Baseline Ensemble**: Direct performance and calibration comparison across Rules, Unsupervised Isolation Forest, Supervised Trees, and PyTorch MLP.
- **Evidence-Grounded Agent Triage**: Every factual claim in an incident brief cites immutable `EvidenceItem` identifiers (`E-VOL-*`, `E-ID-*`, `E-MCP-*`, `E-BEH-*`). Unknown citations are rejected.
- **Untrusted Telemetry Prompt-Injection Resistance**: 28 adversarial test fixtures verifying instruction/data isolation and a 0.0% risk score mutation rate.

---

## Measured Benchmark Performance

*Evaluated on the synthetic benchmark dataset (3,623 events, 150 sessions across 30 scenario families).*

<!-- BEGIN AUTO-GENERATED BENCHMARK METRICS -->
| Evaluation Dimension | Metric | Measured Value | Benchmark Scope / Note |
|---|---|---|---|
| **Track A (IID Holdout)** | **Precision** | **1.0000** | Zero false positives on held-out test cohort |
| | **Recall** | **0.8500** | Detection recall on holdout threats |
| | **F1 Score** | **0.9189** | Fused multi-signal ensemble |
| | **ROC-AUC** | **0.9850** | High discriminative capacity |
| | **PR-AUC** | **0.9930** | Precision-Recall Area Under Curve |
| | **False Positive Rate** | **0.0000** | 0.0% FPR on standard test partition |
| **Track B (5-Fold OOD Family Holdout)** | **Mean F1 Score** | **0.7551 ± 0.1259** | Withheld entire scenario families from training |
| | **Mean Precision** | **0.8386 ± 0.1412** | Generalization across unseen threat families |
| | **Mean Recall** | **0.7100 ± 0.1828** | True out-of-distribution family recall |
| **Multi-Seed Stability (5 Seeds)** | **Mean F1 Score** | **0.9271 ± 0.0300** | Evaluated across seeds [42, 101, 202, 303, 404] |
| **Hard-Negative Cohort** | **Benign FPR (N=500)** | **0.0200** (10/500) | 95% Wilson CI: [0.0109, 0.0364] |
| **Probability Calibration** | **Brier Score** | **0.1676** | Platt sigmoid scaling on continuous probability |
| | **Expected Calibration Error** | **0.3184** | Uniform 10-bin ECE on model probability |
| **Agent Groundedness** | **Citation Validity Rate** | **100.0%** | Verified against curated evidence bundle |
| | **Unsupported Claim Rate** | **0.0%** | Factual findings grounded in deterministic evidence |
| | **Score Mutation Rate** | **0.0%** | Supervisor rejects any risk score tampering |
| **LLM Security** | **Injection Defense Rate** | **100.0%** | 28/28 adversarial injection fixtures defended |
| | **Critic Catch Rate** | **100.0%** | Invariant validation catches challenge briefs |

### Baseline Ablation Comparison
| Model Configuration | Precision | Recall | F1 Score | Description |
|---|---|---|---|---|
| Rules Only | 1.0000 | 0.0500 | 0.0952 | Explainable threshold rules |
| Supervised Classifier Only | 0.9444 | 0.8500 | 0.8947 | HistGradientBoosting classifier |
| Unsupervised Anomaly Only | 1.0000 | 0.4000 | 0.5714 | Isolation Forest on behavioral features |
| PyTorch MLP Only | 1.0000 | 0.9500 | 0.9744 | 2-layer neural network |
| **Final Fused Risk Policy** | **1.0000** | **0.8500** | **0.9189** | **Fused multi-signal ensemble with hard overrides** |
<!-- END AUTO-GENERATED BENCHMARK METRICS -->

## Defensive Scope & Safety Boundary (P0 Invariant)

- **Defensive Research Only**: The system analyzes local synthetic datasets or user-provided logs.
- **No Live-Site Scanning**: The system contains no network scanners, crawlers targeting external hosts, or automated probe tooling.
- **No Offensive Tooling**: Contains no CAPTCHA-bypass, anti-bot evasion, fingerprint spoofing, credential stuffing, or exploit payload mechanisms.
- **Fail Closed**: Any attempt to supply an external network target is rejected with a safety exception.

---

## Quickstart

### 1. Prerequisites
- Python 3.12+
- Node.js 20+ and npm

### 2. Installation
```bash
git clone https://github.com/waalwalker1/agentic-traffic-threat-triage.git
cd agentic-traffic-threat-triage
uv venv --python 3.12
uv sync --extra dev --extra cloud
cd apps/web && npm ci && cd ../..
```

### 3. Generate Synthetic Data & Run Training
```bash
make data
make train
```

### 4. Run Full Evaluation Benchmark Suite
```bash
make eval
```

### 5. Launch API Service & Analyst Console
```bash
# Terminal 1: FastAPI Service
uv run python -m apps.api.main

# Terminal 2: React Analyst Dashboard
cd apps/web && npm run dev
```

Visit the dashboard at `http://localhost:5173`.

---

## Documentation Links

- [System Architecture](docs/architecture/SYSTEM.md)
- [Agent Boundaries & Evidence Invariants](docs/architecture/AGENT_BOUNDARIES.md)
- [Evaluation Methodology](docs/evaluation/METHODOLOGY.md)
- [Dataset Card](docs/DATASET_CARD.md)
- [Integration Status Matrix](docs/INTEGRATION_STATUS.md)
- [Security & Threat Model](docs/security/THREAT_MODEL.md)
- [Release Validation Report](docs/RELEASE_VALIDATION.md)

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
