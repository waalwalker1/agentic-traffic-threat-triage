# Forensic Feature Catalog

The platform extracts 32 deterministic features across 3 categories with full mathematical definitions and provenance tracking.

## 1. Behavioral & Volumetric Features (16)
- `requests_per_second`: Total events divided by session duration in seconds.
- `interarrival_mean_ms`: Mean time interval between consecutive requests in milliseconds.
- `interarrival_cv`: Coefficient of variation (std / mean) of interarrival times. Measures timing regularity.
- `burstiness_index`: Normalized burst metric: `(std - mean) / (std + mean)`.
- `route_entropy`: Shannon entropy of accessed route distribution: `-SUM(p * log2(p))`.
- `unique_route_ratio`: Count of unique route templates divided by total events.
- `error_ratio`: Total error responses (4xx + 5xx) divided by total events.
- `status_4xx_ratio`: Ratio of 4xx client errors.
- `status_5xx_ratio`: Ratio of 5xx server errors.
- `auth_failure_ratio`: Ratio of 401/403 authentication and authorization failures.
- `response_byte_mean`: Mean response payload size in bytes.
- `response_byte_cv`: Coefficient of variation of response bytes.
- `session_duration_s`: Total elapsed time between first and last event.
- `repeated_route_ratio`: Proportion of requests accessing already-visited routes.
- `user_agent_stability_score`: 1.0 if User-Agent remains constant; penalized if multiple UAs appear.
- `header_count_mean`: Mean number of HTTP headers sent per request.

## 2. Agent Identity Features (6)
- `identity_claim_present`: Binary flag (1.0 if actor claimed an identity, 0.0 otherwise).
- `identity_proof_present`: Binary flag (1.0 if cryptographic proof token supplied).
- `identity_proof_valid`: Binary flag (1.0 if signature successfully verified against public key).
- `identity_claim_proof_match`: 1.0 if verified, 0.0 if mismatch or verification failure, 0.5 if unclaimed.
- `identity_changes_count`: Number of times claimed identity changed within session.
- `identity_confidence`: Calibrated confidence score (0.0 to 1.0) based on verification strength.

## 3. MCP Protocol Features (10)
- `mcp_event_ratio`: Proportion of session events executing MCP JSON-RPC methods.
- `mcp_initialize_count`: Count of `initialize` method calls.
- `mcp_tools_list_count`: Count of `tools/list` method calls.
- `mcp_prompts_list_count`: Count of `prompts/list` method calls.
- `mcp_resources_list_count`: Count of `resources/list` method calls.
- `mcp_tools_call_count`: Count of `tools/call` method executions.
- `mcp_discovery_to_action_ratio`: Ratio of discovery calls (tools/prompts/resources list) to tool calls.
- `mcp_repeated_enumeration_score`: Anomaly score (0.0 to 1.0) for rapid discovery loops with zero action.
- `mcp_unknown_method_count`: Count of unrecognized or non-standard MCP methods.
- `mcp_sequence_validity_score`: Conformance score (0.0 to 1.0) penalizing tool calls made prior to initialization.
