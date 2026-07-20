---
name: Benchmark workflow - report incrementally and persist immediately
description: Report each benchmark result as it completes, update bench.md/json immediately, don't batch
type: feedback
---

When running multi-round benchmarks (e.g., 2-node, 3-node, 4-node):

1. Report each round's table to the user AS SOON AS it completes — don't wait for all rounds
2. Update bench.md AND bench.json after EACH round, not at the end
3. The user should see results incrementally, not in one giant dump

**Why:** Waiting until all rounds complete wastes the user's time. If a 3-node test shows a problem, the user might want to abort the 4-node test. Intermediate results inform decisions.

**How to apply:** Structure benchmark workers to report per-round, or use multiple workers (one per node count) that report independently. Update persistent files (bench.md, bench.json) after each round.

**Also needed:** A project-specific benchmark skill or document that standardizes the procedure (fio params, report format, storage verification, file updates). Currently this knowledge is scattered across worker prompts.
