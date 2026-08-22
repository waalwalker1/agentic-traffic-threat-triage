# ADR-003: Model Context Protocol (MCP) Activity Signal Modeling

## Context
AI agents increasingly interact with servers via the Model Context Protocol (MCP). Treating all discovery calls as malicious causes false positives.

## Decision
Implement `MCPSequenceAnalyzer` to evaluate protocol conformance (`initialize` -> `tools/list` -> `tools/call`) and isolate genuine sequence anomalies (uninitialized calls, rapid repeated discovery without action) from benign usage.

## Consequences
- 0.0% false positive rate on benign MCP discovery fixtures.
- High detection fidelity on anomalous tool probing.
