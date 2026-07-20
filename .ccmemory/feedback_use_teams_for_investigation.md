---
name: Use teams for multi-faceted investigations
description: When investigating a problem with multiple independent code paths to trace, use a team with parallel workers, not a single agent
type: feedback
---

Multi-faceted code investigations should use a team lead + parallel workers, not a single sequential agent.

**Why:** A single agent traces paths sequentially — DLM, then journal, then allocation, etc. A team traces all paths in parallel and finishes in a fraction of the time. User called this out explicitly: "I thought director mode would kick off a team... why aren't we being as efficient as possible?"

**How to apply:** When an investigation has 3+ independent threads (e.g., "trace the write path" involves DLM, journal, allocation, VFS entry, caching, locking), dispatch a team lead who spawns one worker per thread. The team lead synthesizes findings into a single report for the Director.
