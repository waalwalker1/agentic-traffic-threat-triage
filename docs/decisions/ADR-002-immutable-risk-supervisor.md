# ADR-002: Deterministic Supervisor & Risk Score Immutability

## Context
Generative AI models can suffer from hallucinations, numbers drift, or prompt injection attempts seeking to downgrade risk scores.

## Decision
The `DeterministicSupervisor` strictly enforces that numeric risk scores and discrete risk bands are calculated by the deterministic data plane and injected directly into the `IncidentBrief`. Generative agents are prohibited from mutating scores.

## Consequences
- 0.0% risk score mutation rate under adversarial prompt injection.
- Verifiable audit trails for SOC analysts.
