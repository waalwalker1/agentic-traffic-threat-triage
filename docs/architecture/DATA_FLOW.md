# Data Flow Architecture

## Ingestion to Disposition Lifecycle

1. **Ingest Phase**:
   - Raw HTTP/API/MCP events ingested via `POST /api/v1/ingest` or Parquet batch load.
   - Validated against versioned `TrafficEvent` Pydantic schema.
   - Normalized and stored in DuckDB `events` table.

2. **Sessionization Phase**:
   - `TelemetrySessionizer` groups events by `session_id` and sorts chronologically.
   - Computes session span, event count, route counts, and actor claims.
   - Persisted to DuckDB `sessions` table.

3. **Forensic Feature & Signal Extraction**:
   - `FeatureExtractor` calculates 32 numeric features.
   - `IdentityEvaluator` checks claims against local Ed25519 registry.
   - `MCPSequenceAnalyzer` parses RPC methods and evaluates sequence validity.
   - Features saved to DuckDB `features` table.

4. **Multi-Model Scoring & Risk Fusion**:
   - `RuleBaselineDetector`, `UnsupervisedAnomalyDetector`, `SupervisedThreatClassifier`, and `PyTorchThreatDetector` evaluate feature vector.
   - `RiskPolicy` applies deterministic weighted fusion and hard rule overrides.
   - Emits `DetectionResult` saved to DuckDB `detection_results` table.

5. **Evidence Collection**:
   - `EvidenceCollector` maps significant forensic features and rule triggers into immutable `EvidenceItem` records with unique identifiers.
   - Bundles detection scores and evidence items into `CuratedEvidenceBundle`.

6. **Multi-Agent Triage Execution**:
   - `DeterministicSupervisor` orchestrates the 6 agent roles.
   - Agent outputs audited by `EvidenceCritic`.
   - Supervisor verifies citation validity and injects protected risk score into `IncidentBrief`.
   - Brief saved to DuckDB `incidents` table.

7. **Human Disposition & Continuous Learning**:
   - SOC analyst reviews brief on React dashboard and records disposition (`CONFIRMED_ABUSE`, `FALSE_POSITIVE`, `BENIGN`, `SUSPICIOUS_MONITOR`).
   - Disposition saved to DuckDB `incidents` table.
