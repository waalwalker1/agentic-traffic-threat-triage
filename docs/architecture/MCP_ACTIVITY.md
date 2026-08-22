# MCP Activity Signal Modeling

## Overview
Model Context Protocol (MCP) traffic represents an emerging category of AI-agent interactions with APIs and tools. Treating all MCP discovery as malicious causes severe false positive spikes; treating it as invisible creates blind spots for tool enumeration abuse.

## Supported Protocol Methods
- `initialize`: Client capabilities declaration and protocol handshake.
- `notifications/initialized`: Confirmation of successful client initialization.
- `tools/list`: Tool discovery endpoint.
- `tools/call`: Tool execution with arguments.
- `prompts/list`: Prompt template enumeration.
- `resources/list`: Resource inventory discovery.
- `resources/read`: Resource content retrieval.

## Deterministic Lifecycle Modeling
The `MCPSequenceAnalyzer` evaluates chronological transitions:
1. **NOMINAL**: Follows standard `initialize` -> `tools/list` -> `tools/call` cadence.
2. **DISCOVERY_ONLY**: Normal single discovery pass without subsequent action (conforming, benign).
3. **SUSPICIOUS_PROBE**: Repeated enumeration loops (`tools/list` multiple times in rapid bursts with zero subsequent action) or uninitialized execution (`tools/call` without prior handshake).
