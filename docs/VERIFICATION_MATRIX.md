# Verification & Traceability Matrix

| Requirement / Acceptance ID | Description | Implementation Path | Test Path | Status |
|---|---|---|---|---|
| A01 | Defensive safety: no external scanning/attack tooling | src/traffic_triage/security/boundary.py | tests/security/test_defensive_boundary.py | PASS |
| A02 | BUILD_SPEC.md & .build/ excluded from git | .gitignore | scripts/check_public_normalization.py | PASS |
| A03 | Seeded reproducible 30-scenario synthetic corpus | tools/synthetic_traffic/generator.py | tests/unit/test_synthetic_generator.py | PASS |
| A04 | Dataset card documentation | docs/DATASET_CARD.md | Inspection | PASS |
| A05 | Group-aware session splitting (no leakage) | tools/synthetic_traffic/generator.py | tests/unit/test_synthetic_generator.py | PASS |
| A06 | Deterministic 32-feature extraction & provenance | src/traffic_triage/features/extractor.py | tests/unit/test_features.py | PASS |
| A07 | Claimed vs verified identity distinction | src/traffic_triage/identity/trust.py | tests/unit/test_identity.py | PASS |
| A08 | Cryptographic Ed25519 identity fixture & verification | src/traffic_triage/identity/signature.py | tests/unit/test_identity.py | PASS |
| A09 | MCP method parsing & sequence semantics | src/traffic_triage/mcp_activity/analyzer.py | tests/unit/test_mcp_activity.py | PASS |
| A10 | Benign MCP discovery hard-negative remains low risk | src/traffic_triage/detection/rules.py | evals/runners/benchmark.py | PASS |
| A11 | Rule baseline evaluated | src/traffic_triage/detection/rules.py | tests/unit/test_models.py | PASS |
| A12 | Unsupervised IsolationForest anomaly detector | src/traffic_triage/detection/unsupervised.py | tests/unit/test_models.py | PASS |
| A13 | Supervised gradient-boosted classifier | src/traffic_triage/detection/supervised.py | tests/unit/test_models.py | PASS |
| A14 | PyTorch neural model baseline | src/traffic_triage/detection/pytorch_model.py | tests/unit/test_models.py | PASS |
| A15 | Probability calibration & Brier score evaluation | src/traffic_triage/detection/calibration.py | tests/unit/test_models.py | PASS |
| A16 | Deterministic risk score fusion & immutability | src/traffic_triage/risk/fusion.py | tests/unit/test_risk_fusion.py | PASS |
| A17 | Agent risk score mutation prevention | src/traffic_triage/security/validator.py | tests/security/test_prompt_injection.py | PASS |
| A18 | Evidence citation grounding | src/traffic_triage/agents/supervisor.py | evals/runners/benchmark.py | PASS |
| A19 | Unknown evidence citations rejected | src/traffic_triage/agents/supervisor.py | tests/security/test_prompt_injection.py | PASS |
| A20 | Evidence Critic audit loop | src/traffic_triage/agents/crew.py | tests/unit/test_schemas.py | PASS |
| A21 | 25+ prompt injection fixtures pass | tests/security/test_prompt_injection.py | pytest tests/security | PASS |
| A22 | Runtime agents lack network/attack tools | src/traffic_triage/agents/crew.py | Code Audit | PASS |
| A23 | Zero-credential local triage execution | src/traffic_triage/llm/providers/deterministic_local.py | scripts/run_demo.py | PASS |
| A24 | FastAPI REST contracts & error handling | apps/api/main.py | tests/integration/test_api.py | PASS |
| A25 | DuckDB persistence across sessions | src/traffic_triage/persistence/duckdb_store.py | tests/integration/test_api.py | PASS |
| A26 | React analyst dashboard with drill-down | apps/web/src/App.tsx | Build & Inspection | PASS |
| A27 | End-to-end integration flow | tests/e2e/test_api_e2e.py | python tests/e2e/test_api_e2e.py | PASS |
| A28 | Detection metrics & hard-negative FPR analysis | evals/runners/benchmark.py | make eval | PASS |
| A29 | Citation validity & unsupported claim rates | evals/runners/benchmark.py | make eval | PASS |
| A30 | Detection baseline ablation study | evals/runners/benchmark.py | make eval | PASS |
| A31 | Docker Compose stack configuration | docker-compose.yml | scripts/docker_smoke.py | PASS |
| A32 | Docker API & web smoke validation | scripts/docker_smoke.py | python scripts/docker_smoke.py | PASS |
| A33 | CI Python & Frontend quality gates | .github/workflows/ci.yml | Inspection | PASS |
| A34 | CI security audit & normalization checks | .github/workflows/ci.yml | Inspection | PASS |
| A35 | Public metrics map to reproducible artifacts | README.md | artifacts/evals/latest/summary.json | PASS |
| A36 | Neutral OSS limitations clearly stated | README.md | Inspection | PASS |
| A37 | Zero non-neutral employment or subjective residue | scripts/check_public_normalization.py | python scripts/check_public_normalization.py | PASS |
| A38 | Optional cloud adapters tested via typed mocks | src/traffic_triage/llm/providers/ | tests/unit/ | PASS |
| A39 | RELEASE_VALIDATION.md reflects current measured results | docs/RELEASE_VALIDATION.md | make release-check | PASS |
| A40 | Release auditor status | docs/RELEASE_VALIDATION.md | Inspection | PASS |
