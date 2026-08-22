# Multi-Agent Boundaries & Role Taxonomy

The triage crew is composed of 6 constrained, specialized roles coordinated by a deterministic supervisor:

## 1. Identity Analyst
- **Input**: Curated identity evidence items (`E-ID-*`).
- **Function**: Evaluates claimed identity vs cryptographic proof status. Distinguishes unverified User-Agent assertions from cryptographic Ed25519 fixtures.
- **Output**: `IdentityAgentOutput` (assessment, confidence, cited evidence IDs, ambiguities).

## 2. Behavior & Intent Analyst
- **Input**: Behavioral, volumetric, and temporal evidence items (`E-VOL-*`, `E-BEH-*`) and detector scores.
- **Function**: Constructs competing hypotheses regarding actor intent (abusive vs benign explanation).
- **Output**: `IntentAgentOutput` (competing hypotheses, behavioral summary, cited evidence IDs).

## 3. MCP Activity Analyst
- **Input**: MCP sequence metrics and evidence items (`E-MCP-*`).
- **Function**: Contextualizes Model Context Protocol activity. Emphasizes that tool discovery is normal and isolates genuine anomalies (uninitialized calls, rapid enumeration).
- **Output**: `MCPAgentOutput` (assessment, conformance status, cited evidence IDs).

## 4. Threat Hypothesis Synthesizer
- **Input**: Curated bundle and outputs from Identity, Intent, and MCP analysts.
- **Function**: Integrates findings into key factual discoveries, primary hypothesis, alternative explanations, and recommended analyst actions.
- **Output**: `SynthesisAgentOutput` (findings, primary hypothesis, alternatives, recommendations, confidence).

## 5. Evidence Critic
- **Input**: Synthesized brief and original `CuratedEvidenceBundle`.
- **Function**: Adversarially audits the brief against grounding invariants:
  - Rejects if citations do not exist in bundle.
  - Rejects if numbers contradict forensic evidence.
  - Rejects if hostile injection instructions leaked.
- **Output**: `CriticAgentOutput` (approval verdict, rejection reasons, invalid IDs).

## 6. SOC Brief Composer (Supervisor Enforced)
- **Input**: Approved synthesis and deterministic `DetectionResult`.
- **Function**: Enforces numeric risk score immutability and citation formatting to emit final typed `IncidentBrief`.
