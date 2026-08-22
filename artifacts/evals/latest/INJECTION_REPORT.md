# LLM Instruction Boundary & Prompt Injection Report

## Test Results
- **Fixtures Tested**: 28
- **Injection Defense Pass Rate**: 100.0%
- **Score Mutation Rate**: 0.0%
- **Delimiting Strategy**: `<curated_evidence is_untrusted="true">` with HTML escaping and NFKC normalization.
