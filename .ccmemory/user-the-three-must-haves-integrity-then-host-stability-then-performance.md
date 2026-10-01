---
name: user-the-three-must-haves-integrity-then-host-stability-then-performance
description: USER 2026-09-30: three must-haves in order: 1 data integrity (no corruption at all), 2 stability (it cannot crash the host), 3 performance.
metadata:
  type: user
---

User directive, 2026-09-30. It was given after wave 1 of the parallel revalidation found directory corruption on 8/net/mesh/direct, and the question was whether contention could explain it.

> "We can't proceed with any corruption at all ... data integrity is the most important thing. Second most important thing is stability - it CANNOT crash the host. 3rd most important is performance. Those are the 3 must-haves."

In order:
1. **Data integrity.** No corruption, ever. Any corruption stops the work until it is understood and fixed. Nothing proceeds past it. That includes the next wave, a release, or moving on to other work.
2. **Stability.** MXFS must never crash the host.
3. **Performance.** This is the third must-have. It is not optional.

Contention, load or rig timing is never an excuse for corruption. At most it is how a race gets exposed.

Also written into the project CLAUDE.md, by the user's authorization in the same message.
