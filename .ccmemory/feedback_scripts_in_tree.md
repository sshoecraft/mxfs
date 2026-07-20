---
name: Persistent scripts live in /src/mxfs, not /tmp
description: For MXFS work, test/experiment scripts that need to survive reboots go in the source tree, not /tmp — overrides the global /tmp-for-scratch rule
type: feedback
originSessionId: bbe79d3b-3c97-4ae3-be56-74257be1f617
---
For MXFS, any script that needs to survive a reboot belongs in the
project source tree (e.g. `/src/mxfs/tests/`, `/src/mxfs/scripts/`,
or another subdir that fits), NOT `/tmp`.

**Why:** The MXFS test cluster (test1/test2 VMs) and the dev host get
rebooted regularly during stress testing — sysrq-b after wedged
unmounts, kernel panics, etc.  Scripts in /tmp evaporate on reboot,
which has burned cycles re-creating harnesses (e.g. mxfs_stress_v033.sh,
mxfs_cluster_reset.sh have lived in /tmp and had to be rebuilt).

**How to apply:**
- Truly ephemeral one-shot scratch (parsing a single log, a one-off
  awk pipeline) — /tmp is still fine.
- Anything I'd want to re-run, anything a future session might need,
  anything that's part of the hypothesize→measure→develop→commit loop —
  put it in the source tree.
- This OVERRIDES the global ~/.claude/CLAUDE.md rule "NEVER put
  temporary files or test scripts in the project directory - ALWAYS
  use /tmp" for the MXFS project specifically.
- Pick a sensible location: bench harnesses → `/src/mxfs/tests/`
  or `/src/mxfs/bench/`; diagnostic/instrumentation scripts →
  `/src/mxfs/scripts/` or alongside the code they instrument.
