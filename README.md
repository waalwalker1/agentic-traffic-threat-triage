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

*Evaluated on the held-out test split of the 30-scenario synthetic benchmark dataset (2,412 events, 150 sessions).*

| Evaluation Dimension | Metric | Measured Value | Benchmark Scope / Note |
|---|---|---|---|
| **Detection Quality** | **Precision** | **1.0000** | Zero false positives on benign test cohort |
| | **Recall** | **0.9000** | High recall on anomalous & scraping patterns |
| | **F1 Score** | **0.9474** | Best ensemble performance |
| | **ROC-AUC** | **0.9750** | High discriminative capacity |
| | **PR-AUC** | **0.9887** | Precision-Recall Area Under Curve |
| | **False Positive Rate** | **0.0000** | 0.0% FPR across all benign hard-negatives |
| **Probability Calibration** | **Brier Score** | **0.1144** | Calibrated via Platt sigmoid scaling |
| | **Expected Calibration Error** | **0.2598** | Uniform 10-bin ECE |
| **Agent Groundedness** | **Citation Validity Rate** | **100.0%** | All 30/30 citations verified against bundle |
| | **Unsupported Claim Rate** | **0.0%** | Enforced by deterministic supervisor |
| | **Score Mutation Rate** | **0.0%** | Supervisor rejects any risk score tampering |
| **LLM Security** | **Injection Defense Rate** | **100.0%** | 28/28 adversarial injection fixtures defended |

### Baseline Ablation Comparison
| Model Configuration | F1 Score | Brier Score | Description |
|---|---|---|---|
| Rules Only | 0.0952 | 0.4222 | Explainable threshold rules |
| Unsupervised Anomaly Only | 0.2069 | 0.3987 | Isolation Forest on behavioral features |
| Supervised Classifier Only | 0.9231 | 0.0576 | HistGradientBoosting classifier |
| PyTorch MLP Only | 0.9000 | 0.0724 | 2-layer neural network |
| **Final Fused Risk Policy** | **0.9474** | **0.1144** | **Fused multi-signal ensemble with hard overrides** |

> [!NOTE]
> Evaluation results reported here are measured on the repository's synthetic benchmark dataset and should not be interpreted as real-world fraud-detection performance.

---

## Defensive Scope & Safety Boundary (P0 Invariant)

- **Defensive Research Only**: The system analyzes local synthetic datasets or user-provided logs.
- **No Live-Site Scanning**: The system contains no network scanners, crawlers targeting external hosts, or automated probe tooling.
- **No Offensive Tooling**: Contains no CAPTCHA-bypass, anti-bot evasion, fingerprint spoofing, credential stuffing, or exploit payload mechanisms.
- **Fail Closed**: Any attempt to supply an external network target is rejected with a safety exception.

---

## Quickstart

### 1. Prerequisites
- Python 3.12+ (tested on Python 3.13)
- Node.js 20+ and npm
- `uv` package manager (`curl -LsSf https://astral.sh/uv/install.sh | sh`)

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/waalwalker1/agentic-traffic-threat-triage.git
cd agentic-traffic-threat-triage

# Install Python and Node dependencies
make setup
```

### 3. Generate Dataset & Train Baselines
```bash
# Generate deterministic 30-scenario synthetic corpus
make data

# Train detection models and calibration layer
make train
```

### 4. Run Offline CLI Triage Demo
```bash
make demo
```

### 5. Start API & Analyst Dashboard
```bash
# Start FastAPI backend (port 8000) and React dashboard (port 3000)
make dev
```
Open [http://localhost:3000](http://localhost:3000) in your browser.

---

## Testing & Quality Verification

```bash
# Run unit and protocol tests
make test

# Run backend integration tests
make test-integration

# Run adversarial prompt injection test suite
make red-team

# Run full evaluation benchmark
make eval

# Run linters and static type checking
make lint
make typecheck

# Execute complete release verification check
make release-check
```

---

## Repository Layout

```text
.
├── apps/
│   ├── api/                   # FastAPI backend service
│   └── web/                   # React 18 + TypeScript + Vite analyst dashboard
├── src/traffic_triage/
│   ├── schemas/               # Canonical versioned Pydantic contracts
│   ├── telemetry/             # Sessionization and stream aggregation
│   ├── features/              # Deterministic 32-feature extraction pipeline
│   ├── identity/              # Signed Ed25519 identity fixtures & trust model
│   ├── mcp_activity/          # Model Context Protocol sequence semantics analyzer
│   ├── detection/             # Multi-model baselines (Rules, IsolationForest, HGB, PyTorch)
│   ├── risk/                  # Deterministic calibrated RiskPolicy fusion
│   ├── evidence/              # CuratedEvidenceBundle & EvidenceItem builder
│   ├── agents/                # 6-role multi-agent SOC crew & DeterministicSupervisor
│   ├── llm/                   # Provider abstractions (DeterministicLocal, Vertex AI, Bedrock)
│   ├── persistence/           # DuckDB analytical repository
│   ├── observability/         # OpenTelemetry tracing & Prometheus metrics
│   └── security/              # Telemetry sanitizer, validator & defensive boundary
├── tools/
│   └── synthetic_traffic/     # Seeded 30-scenario synthetic traffic generator
├── data/
│   ├── fixtures/              # Parquet dataset fixtures and group-aware split manifest
│   └── samples/               # Compact sample events JSON
├── evals/
│   └── runners/               # Benchmark evaluation runner & metrics generator
├── artifacts/
│   ├── evals/latest/          # Benchmark reports (Detection, Groundedness, Injection, Ablations)
│   └── model_cards/           # Serialized trained model weights & metadata
├── docs/                      # Comprehensive technical architecture & security documentation
├── tests/
│   ├── unit/                  # Unit tests for schemas, features, models, and identity
│   ├── integration/           # FastAPI service integration tests
│   ├── security/              # 28 prompt-injection and defensive boundary tests
│   └── e2e/                   # End-to-end workflow verification tests
├── pyproject.toml             # Python build configuration & dependencies
├── package.json               # Frontend Node package configuration
├── Makefile                   # Canonical developer command interface
├── docker-compose.yml         # Containerized local runtime deployment
├── LICENSE                    # MIT License
├── SECURITY.md                # Security policy & vulnerability reporting
└── CONTRIBUTING.md            # Contribution guidelines
```

---

## Known Limitations

1. **Synthetic Telemetry Baseline**: The models and agents are evaluated on structured synthetic scenario distributions. Real-world internet traffic exhibits higher variance, browser quirks, and dynamic network conditions.
2. **Deterministic Local Mode**: By default, the system runs with `DeterministicLocalProvider` to enable zero-credential local evaluation. Optional cloud adapters (Vertex AI, AWS Bedrock) require external credentials.
3. **Defensive Research Scope**: This platform is designed for research, triage acceleration, and forensic investigation; it does not replace automated real-time edge blocking appliances.

---

## License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.
