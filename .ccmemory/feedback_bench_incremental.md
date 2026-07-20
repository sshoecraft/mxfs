---
name: Benchmarks are one-at-a-time with immediate reporting
description: Run ONE benchmark, report results, update bench.md/json, THEN run the next one
type: feedback
---

NEVER batch benchmarks. Run ONE test at a time:

1. Run the benchmark (e.g., 2-node fio suite)
2. Report the table to the user IMMEDIATELY
3. Update bench.md and bench.json
4. THEN run the next benchmark (e.g., 3-node)

**Why:** Batching 8+ tests and reporting at the end wastes hours if something is wrong. The user needs to see each result before deciding whether to continue. A straggler at 3 nodes might mean "stop and investigate" not "keep going to 4 nodes."

**How to apply:** Use separate workers per benchmark round, or structure a single worker to report back after each round before proceeding. The Director should receive each result, show the user, update docs, then dispatch the next round.
