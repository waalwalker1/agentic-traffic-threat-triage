# Workspace Agent & Engineering Invariants

This document defines the architectural and engineering invariants for automated maintenance and development of the Agentic Traffic Threat Triage platform.

## 1. Defensive-Only Boundary (P0 Invariant)
- No scanning of public endpoints or unauthorized third-party services.
- No CAPTCHA-bypass, anti-bot evasion, fingerprint spoofing, credential stuffing, or exploit payload tooling.
- All testing, evaluation, and demonstration must execute against seeded synthetic data or repository-local services.
- System must fail closed when invalid or external targets are supplied.

## 2. Deterministic & AI Plane Separation
- **Data Plane (Deterministic)** owns: Schema validation, sessionization, raw feature extraction, cryptographic identity proof verification, numeric model scoring, calibration, immutable evidence IDs, and incident IDs.
- **AI Plane (Generative)** may: Interpret structured evidence, generate natural language briefings, propose competing hypotheses, and suggest analyst investigation steps.
- **AI Plane Invariant**: Generative agents may NEVER alter numeric risk scores, invent evidence IDs, modify raw events, or execute unauthorized external actions.

## 3. Evidence Grounding & Citation Rigor
- Every factual claim in an incident brief must cite one or more valid, deterministic `EvidenceItem` identifiers (e.g. `E-VOL-001`, `E-ID-001`).
- Unknown evidence citations must be rejected by the validation supervisor and critic agent.
- Telemetry headers, user agents, paths, and payloads are treated as untrusted data and strictly sanitized.

## 4. Zero-Credential Canonical Path
- The local execution path must operate completely offline without external cloud or LLM API keys using `DeterministicLocalProvider`.
- Optional cloud adapters (Vertex AI, AWS Bedrock) must be tested against typed contracts and mock interfaces.
