# Dataset Card: Synthetic Traffic Threat Triage Corpus v1.0.0

## Dataset Summary
The Synthetic Traffic Threat Triage Corpus is a seeded, reproducible benchmark dataset of synthetic HTTP, API, AI-agent, and Model Context Protocol (MCP) traffic sessions. It is engineered specifically for evaluating defensive traffic-analysis algorithms, multi-model threat detection baselines, cryptographic agent identity verification, and multi-agent SOC triage briefing.

## Key Statistics
- **Total Events**: 2,412
- **Total Sessions**: 150 (5 sessions per scenario)
- **Scenario Families**: 30 distinct scenario types
- **Storage Format**: Apache Parquet (`data/fixtures/traffic_dataset.parquet`) & DuckDB
- **Splits**: Group-aware split by session instance (Train: 90 sessions / 60%, Validation: 30 sessions / 20%, Test: 30 sessions / 20%)

## Scenario Catalog (30 Families)
1. **Benign / Low-Risk**:
   - `human_browsing`: Nominal human web interaction with realistic interarrival delays and route transitions.
   - `mobile_app_api`: Authenticated mobile application API calls with JSON payloads.
   - `search_crawler`: Standard search engine indexing crawler traversing public documentation politely.
   - `verified_ai_fetcher`: Legitimate AI assistant fetcher with valid cryptographic signature proof.
   - `qa_automation`: Internal testing automated browser with fixed headers.
   - `monitoring_burst`: Bursty health-check probes on status endpoints.
   - `mcp_discovery_benign`: Conforming MCP protocol initialization and tool listing.
   - `mcp_tool_use_benign`: Normal cadence MCP tool calls following initialization.

2. **Identity / Trust Ambiguity**:
   - `claimed_ai_no_proof`: Actor claiming AI agent identity in User-Agent without cryptographic proof.
   - `cryptographic_verified_agent`: Agent verified against local Ed25519 public key registry.
   - `identity_mismatch`: Identity claim conflicting with signing key or failing cryptographic verification.
   - `rotating_claimed_identity`: Mid-session User-Agent / claim changes with benign request timing.
   - `verified_identity_behavior_shift`: Verified agent displaying sudden anomalous burst activity.

3. **Fraud & Abuse-Like Behavior**:
   - `catalog_scraping_high_volume`: High-frequency pagination through product endpoints (30+ rps).
   - `distributed_collection`: Distributed collection pattern targeting structured datasets.
   - `repetitive_login_failure`: High-rate authentication failures (401/403) resembling credential attacks.
   - `inventory_checkout_timing_abuse`: Rapid cart reservation and checkout loops.
   - `excessive_api_enumeration`: Sequential resource ID walking with elevated 404/403 rates.
   - `low_and_slow_scraping`: Periodic requests spaced just below rate limits across diverse routes.
   - `agentic_browser_abuse`: Repetitive agentic browser execution loops.

4. **MCP-Specific Activity Patterns**:
   - `mcp_normal_workflow`: Standard initialize -> notifications/initialized -> tools/list -> tools/call.
   - `mcp_discovery_only_abandoned`: Initialization followed by discovery calls with zero action.
   - `mcp_repeated_enumeration`: Rapid repeated discovery loops across tools, prompts, and resources.
   - `mcp_identity_shift`: Switching identity claims or signing keys mid-MCP lifecycle.
   - `mcp_abnormal_sequence`: Tool execution attempts prior to protocol initialization.

5. **Adversarial LLM-Security Fixtures**:
   - `injection_user_agent`: Hostile system override text embedded in User-Agent header.
   - `injection_custom_header`: Injected instructions in synthetic headers.
   - `injection_ignore_evidence`: Telemetry requesting the analyst to ignore findings.
   - `injection_fake_evidence_id`: Forged evidence IDs embedded in query parameters.
   - `injection_unicode_control`: Bidirectional override characters, control bytes, and XML tags.

## Leakage Prevention
- **Group-Aware Splitting**: Splitting is strictly performed at the session level. Events belonging to the same session never cross split boundaries.
- **Inference Separation**: Benchmark ground truth labels (`synthetic_ground_truth`) are stripped during feature extraction and are never provided to detection models or LLM agents.
