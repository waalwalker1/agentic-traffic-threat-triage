---
name: test-first-contract
description: Defines typed contracts and negative tests before integrating shared behavior.
---

# Test First Contract

1. Freeze Pydantic/JSON contracts before parallel implementation.
2. For every positive path add at least one failure/edge path.
3. Shared interfaces require contract tests.
4. Do not change schemas silently; version or record an ADR.
