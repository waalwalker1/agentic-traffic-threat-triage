# System Architecture

## Architecture Overview
The Agentic Traffic Threat Triage platform is organized around a strict **Separation of Concerns between the Deterministic Data Plane and the Generative AI Plane**.

```
[ Synthetic / Ingested Telemetry ]
               │
               ▼
[ Schema Validation & Deterministic Sessionization ]
               │
       ┌───────┴────────────────────────┐
       ▼                                ▼
[ Behavioral Feature Extraction ]    [ Cryptographic Identity Verification ]
       │                                │
       ├────────────────────────────────┤
       ▼                                ▼
[ Multi-Model Detection Ensemble ]   [ MCP Sequence Semantics Analyzer ]
 (Rules, IsolationForest, HGB, MLP)
       │                                │
       └────────────────┬───────────────┘
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
 (Score Immutability & Citation Validation Audit)
                        │
                        ▼
           [ Incident Brief & Store ]
                        │
                        ▼
       [ FastAPI Backend & React Dashboard ]
```

## Plane Invariants
1. **Deterministic Data Plane**:
   - Schema validation and session aggregation.
   - All 32 forensic feature calculations and provenance.
   - Ed25519 cryptographic signature verification.
   - Model inference (Rule baseline, IsolationForest, HistGradientBoosting, PyTorch MLP).
   - Probability calibration (Platt scaling) and deterministic RiskPolicy score fusion.
   - Generation of immutable `EvidenceItem` identifiers (`E-VOL-*`, `E-ID-*`, `E-MCP-*`, `E-BEH-*`).

2. **Generative AI Plane**:
   - Interprets curated forensic evidence items within strict `<curated_evidence>` XML boundaries.
   - Proposes competing threat and benign hypotheses with logical explanations.
   - Suggests actionable next steps for human SOC analysts.
   - **Safety Invariant**: Agents cannot alter numeric risk scores, change risk bands, invent evidence IDs, or issue external network requests.
