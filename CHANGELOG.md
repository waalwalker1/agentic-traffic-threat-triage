# Changelog

All notable changes to the Agentic Traffic Threat Triage project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-22

### Added
- **Canonical Pydantic Schemas**: Versioned contracts for `TrafficEvent`, `TrafficSession`, `EvidenceItem`, `DetectionResult`, `IncidentBrief`, `IntentHypothesis`, `CriticReview`, `AnalystDisposition`, and `EvaluationSummary`.
- **Deterministic Synthetic Traffic Generator**: Seeded scenario generator producing 30 distinct scenario families spanning benign usage, identity ambiguity, web abuse patterns, MCP activity signals, and adversarial prompt-injection fixtures.
- **Group-Aware Splitting**: Zero session leakage splitting across train (60%), validation (20%), and test (20%) groups.
- **Deterministic Feature Layer**: 32 behavioral, identity, and MCP sequence features with provenance tracking.
- **Signed Agent Identity Fixture**: Ed25519 cryptographic keypair generation, signature creation, and registry verification fixtures.
- **MCP Activity Signal Modeling**: Sequence analyzer for Model Context Protocol lifecycle transitions (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `prompts/list`, `resources/list`).
- **Multi-Model Baseline Ensemble**:
  - Heuristic explainable Rule baseline (`RuleBaselineDetector`)
  - Unsupervised anomaly baseline (`IsolationForest`)
  - Supervised gradient-boosted classifier (`HistGradientBoostingClassifier`)
  - Compact neural baseline (`PyTorchThreatDetector` MLP)
  - Probability calibration engine (`PlattSigmoidCalibrator`)
  - Deterministic risk fusion policy (`RiskPolicy`)
- **6-Role Multi-Agent SOC Triage Crew**:
  - `Identity Analyst`
  - `Behavior & Intent Analyst`
  - `MCP Activity Analyst`
  - `Threat Hypothesis Synthesizer`
  - `Evidence Critic`
  - `SOC Brief Composer`
- **Deterministic Supervisor**: Enforces numeric risk score immutability, evidence citation verification, and critic rejection loops.
- **Zero-Credential Local Provider**: Offline `DeterministicLocalProvider` exercising identical typed structured schema generation protocols as cloud LLMs.
- **Optional Cloud Adapters**: Google Cloud Vertex AI and AWS Bedrock typed provider adapters with mockable contracts.
- **Untrusted Telemetry Sanitization & Prompt-Injection Hardening**: 28 adversarial test fixtures verifying instruction/data separation, XML boundary tagging, and 0% risk score mutation.
- **FastAPI Backend & DuckDB Analytical Store**: Versioned REST API with correlation tracing, OpenAPI documentation, and local DuckDB persistence.
- **React 18 + TypeScript Analyst Dashboard**: Interactive SOC interface for session timeline exploration, forensic evidence drill-down, incident hypothesis briefing, and human analyst disposition.
- **Reproducible Evaluation Science**: Full benchmark suite generating detection metrics (F1 0.9474, ROC-AUC 0.9750), hard-negative FPR analysis (0.0%), calibration reports, groundedness audits (100% valid citations), and ablation studies.
- **Containerization & CI**: Multi-stage Dockerfiles, Docker Compose, and GitHub Actions CI workflow covering linting, typechecking, unit/integration/security tests, and normalization audits.
