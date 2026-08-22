# Contributing to Agentic Traffic Threat Triage

Thank you for your interest in contributing to the Agentic Traffic Threat Triage research platform.

## Development Principles & Invariants
1. **Defensive-Only**: All additions must remain defensive. No live-site attack or evasion features will be merged.
2. **Evidence-Grounded**: Features, models, and agent behaviors must be backed by unit tests, deterministic evidence citations, and reproducible metrics.
3. **Zero-Credential Canonical Path**: Core test suites, evaluation runners, and CLI demos must run completely offline using `DeterministicLocalProvider`. Cloud adapters (Vertex AI, AWS Bedrock) must remain optional and testable with mock clients.
4. **Code Quality**: Pull requests must pass all formatting, linting, typing, unit, integration, and security checks.

## Development Workflow
```bash
# Set up development environment
make setup

# Run test suite
make test

# Run integration tests
make test-integration

# Run security prompt injection tests
make red-team

# Run linters and type checking
make lint
make typecheck

# Full release gating check
make release-check
```

## Pull Request Checklist
- [ ] Schema changes versioned and tested in `tests/unit/test_schemas.py`.
- [ ] New feature extractors include provenance descriptions in `docs/architecture/FEATURES.md`.
- [ ] Deterministic supervisor invariants are preserved.
- [ ] `make release-check` passes cleanly.
