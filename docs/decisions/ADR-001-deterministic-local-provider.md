# ADR-001: Deterministic Local Provider for Zero-Credential Evaluation

## Context
Running multi-agent SOC triage in production test suites and CI must not require external cloud API keys or incur unpredictable external LLM latency.

## Decision
Implement `DeterministicLocalProvider` fulfilling the `LLMProvider` protocol. It deterministically formats structured Pydantic outputs from curated forensic evidence.

## Consequences
- Guaranteed reproducible, offline CI and local demonstration.
- Cloud providers (Vertex AI, AWS Bedrock) implement the same interface and remain optional.
