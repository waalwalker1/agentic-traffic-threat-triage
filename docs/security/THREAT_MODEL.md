# Threat Model

## Threat Vectors Analyzed (Synthetic Scenarios)
1. **High-Frequency Catalog Scraping**: Automated scrapers extracting large-scale entity datasets.
2. **Credential Abuse & Account Takeover**: Repetitive credential trial attacks against authentication endpoints.
3. **Identity Spoofing**: Untrusted bots forging User-Agent headers to impersonate legitimate crawlers or AI agents.
4. **MCP Protocol Probing**: Uninitialized tool execution and repeated tool discovery enumeration.
5. **Prompt Injection via Telemetry**: Hostile instructions embedded in HTTP headers, paths, and User-Agents targeting LLM SOC copilot agents.
