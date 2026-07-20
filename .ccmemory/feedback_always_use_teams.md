---
name: Always use Agent Teams for multi-worker tasks
description: Use TeamCreate + team lead + TaskCreate for any task requiring 2+ workers, not bare Agent spawns
type: feedback
---

When dispatching 2+ workers, ALWAYS use the team infrastructure:
1. TeamCreate to create the team
2. TaskCreate for each work item
3. Spawn a team lead agent (general-purpose, with team_name param)
4. Team lead spawns workers, assigns tasks, coordinates, reports back

Do NOT spawn bare agents in parallel without a team. Bare agents have no shared task list, no coordination, and no conflict management.

**Why:** User corrected this three times in one session. Bare agents can conflict on shared files (e.g., two agents both modifying mount.c). A team lead manages ordering, detects conflicts, and synthesizes results.

**How to apply:** Any time you're about to spawn 2+ Agent calls, stop and create a team first. The only exception is truly independent, non-overlapping research queries.
