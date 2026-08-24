# Integration & Provider Status Classification

This document records the exact implementation and verification status of all external framework, model provider, and infrastructure adapters in the Agentic Traffic Threat Triage platform.

## Status Taxonomies
- **`IMPLEMENTED_AND_TESTED`**: Full end-to-end implementation with automated unit, integration, and benchmark tests running in CI without credentials.
- **`CONTRACT_TESTED`**: Typed interface contract implemented and verified using deterministic mocked fixtures and schema boundary tests.
- **`REFERENCE_ONLY`**: Static architectural template, reference implementation, or schema definition provided for deployment guidance without live end-to-end execution.
- **`NOT_EXECUTED`**: Optional live capability that was not executed in the zero-credential canonical test environment.

---

## Component Status Ledger

| Component / Adapter | Classification | Verification Evidence | Notes |
|---|---|---|---|
| **Deterministic Local Provider** | `IMPLEMENTED_AND_TESTED` | `tests/unit/`, `evals/runners/benchmark.py` | Canonical offline zero-credential provider powering all tests and benchmarks |
| **Native SOC Orchestrator** | `IMPLEMENTED_AND_TESTED` | `tests/unit/test_crewai_adapter.py`, `src/traffic_triage/agents/` | Production typed multi-agent orchestration pipeline |
| **CrewAI Orchestration Adapter** | `CONTRACT_TESTED` | `tests/unit/test_crewai_adapter.py` | Optional CrewAI role adapter with deterministic contract tests |
| **Google Cloud Vertex AI Adapter** | `CONTRACT_TESTED` | `tests/protocol/test_cloud_providers.py` | Typed structured JSON schema output contract tested via mocked `genai.Client` |
| **AWS Bedrock Provider** | `REFERENCE_ONLY` | `tests/protocol/test_cloud_providers.py` | Reference contract for AWS Bedrock Anthropic Claude model payload conversion |
| **GCP Cloud Run Terraform** | `REFERENCE_ONLY` | `infra/gcp/terraform/` | Reference infrastructure definitions for containerized deployment |
| **OpenTelemetry Instrumentation** | `IMPLEMENTED_AND_TESTED` | `src/traffic_triage/observability/` | FastAPI tracing and Prometheus metrics active in runtime service |
