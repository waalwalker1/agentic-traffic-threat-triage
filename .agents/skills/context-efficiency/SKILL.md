---
name: context-efficiency
description: Keeps multi-agent work compact through ownership boundaries, handoffs, summaries, and selective context retrieval.
---

# Context Efficiency

1. Delegate by file-tree ownership and explicit deliverable.
2. Subagents write concise handoffs instead of returning raw logs.
3. Orchestrator reads only relevant handoff, tests, and changed files.
4. Do not paste large datasets or generated logs into agent context.
