# Identity Verification & Intent Reasoning

## The Identity vs. Intent Principle
1. **Identity is Claimed or Verified**: An actor's identity may be unverified (User-Agent string alone) or cryptographically verified (Ed25519 signature over canonical request payload).
2. **Verified Identity does not Guarantee Benign Intent**: A verified agent can misbehave or suffer configuration errors.
3. **Intent is Inferred from Combinations of Context and Behavior**: Intent is modeled as competing hypotheses with explicit confidence weighting.

## Signed-Agent Identity Fixtures
- Keypairs: Ed25519 asymmetric cryptography.
- Canonical signing string: `SOURCE=<hash>|ROUTE=<path>|TIME=<iso>`.
- Verification against local fixture registry (`IdentityRegistry`).
