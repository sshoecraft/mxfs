---
name: Runbook worker prompts
description: Worker prompts for runbook-based tasks must say "follow the instructions AS WRITTEN" — no over-specification, no extra restrictions
type: feedback
---

When spawning a worker to follow a runbook document, the prompt must:
1. Tell the worker to read the doc and "follow the instructions AS WRITTEN"
2. Provide only the node-specific details (hostname, SSH tool, output paths)
3. NOT re-specify what's already in the document (workloads, parameters, steps)
4. NOT add restrictions or "do NOT" lists — that belongs in the document itself

**Why:** Over-specified prompts cause workers to freelance — they read bench.json, skip steps, or invent their own approach instead of following the document. The phrase "as written" anchors the worker to the document. If the document is complete, the prompt should be trivially short.

**How to apply:** Every runbook-based worker prompt follows this pattern:
```
Read /src/mxfs/docs/RUNBOOK.md and follow the instructions as written for node HOSTNAME.
SSH tool: /src/mxfs/tools/mxfs_sshpass.sh HOSTNAME /tmp/.mxfs_pass "COMMAND".
[any node-specific output paths]
```
