# Security Policy & Defensive Research Invariants

## Defensive-Only Engineering Scope
This repository is an open-source defensive research platform designed exclusively to demonstrate applied artificial intelligence, threat-detection telemetry modeling, cryptographic identity verification, and multi-agent incident briefing.

### Core Security Boundaries (P0 Invariants)
1. **No External Network Scanning**: The platform contains no tooling to scan, probe, or interact with live third-party websites or services. All execution targets are strictly confined to local synthetic fixtures or repository-local services (`localhost`, `127.0.0.1`).
2. **No Offensive or Evasion Tooling**: The project strictly prohibits and does not implement CAPTCHA bypass, anti-bot evasion, fingerprint spoofing, credential stuffing, password spraying, or exploit delivery payloads.
3. **Deterministic & AI Plane Separation**: Generative AI models are strictly prohibited from mutating numeric risk scores, inventing evidence identifiers, or issuing unauthorized external network actions.
4. **Untrusted Telemetry Instruction Boundary**: All input telemetry strings (User-Agents, headers, paths, query parameters, synthetic body text, MCP tool descriptions) are treated as untrusted data. They are sanitized, XML-delimited, and isolated from system prompt instructions.

## Vulnerability Reporting
If you discover a security vulnerability or a violation of our defensive scope invariants, please report it privately to the maintainers rather than opening a public issue.

- **Email**: `security@example.org` (or maintainer contact)
- **Response SLA**: We aim to acknowledge reports within 48 hours and provide a remediation timeline within 7 days.
