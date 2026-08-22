# LLM Instruction Boundary & Sanitization

## Security Controls
1. **Untrusted Data Boundary**: Telemetry content is wrapped in `<curated_evidence is_untrusted="true">` XML tags.
2. **Sanitization**: Unicode NFKC normalization, control character stripping, and HTML escaping prevent tag breakout attacks.
3. **Score Protection**: Risk scores are strictly computed by the deterministic data plane. Generative agents cannot alter scores.
4. **Citation Verification**: Unknown evidence IDs are rejected by the supervisor and critic agent.
