---
name: crewai-orchestration
description: Implements CrewAI-based role orchestration with typed interfaces and a deterministic supervisor when current CrewAI is healthy.
---

# Crewai Orchestration

1. Verify current CrewAI API before implementation.
2. Crew roles cannot own numeric risk or evidence IDs.
3. Use structured outputs and bounded retries.
4. If CrewAI is unavailable, use typed fallback and document ADR rather than blocking release.
