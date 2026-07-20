---
name: infra-ccloop-leaves-stale-sessions-alive-KILL-AT-START
description: CRITICAL: ccloop relay does NOT kill the old claude session — it keeps WORKING (Stop-hook loop) and launches rival run.sh, power-cycling nodes mid-ru…
metadata:
  type: project
---

# ccloop leaves predecessor sessions ALIVE and WORKING — kill them at session start

## What happened (ccloop run 46efd8b6, sess3, 2026-07-10)
At context-fill relay, ccloop spawns the next session but does NOT terminate the previous claude process. It gets orphaned (PPID=1) and KEEPS EXECUTING its agentic loop — the Stop hook ("HAVE YOU MET THE CRITERIA? keep working") drives it to keep launching test runs forever.

Sess3 found BOTH predecessors alive:
- sess1 claude (PID 1660037), alive 5.7h, idle since ~20:33
- sess2 claude (PID 1809191), alive and ACTIVE: kept launching `timeout 3100 ./run.sh 16 caw dir_reuse_coherency` retry after retry from its afterlife

## Damage it caused (all of sess3's early evidence was sabotage)
- sess3 run1 (32-node): PREP FAIL "converged 17/15 split" — actually sess2's rogue 16-node prep power-cycled test21/22/23 mid-prep AND its 16-node convergence saw 17 members (sess3's mounts appearing).
- sess3 run2 (040242Z): 0/32 FAIL + all of test17-32 power-cycled at 04:06:17 mid-test (libvirt "is tainted" = domain start events) — rogue prep treated 17-32 as "extras holding mxfs" and destroy+started them. Survivors (1-16) livelocked in a P7B-BASTNOTIFY ino=131 storm (dead nodes' holder bits never reaped — separate robustness gap, node-death recovery is not part of cache_coherency).
- Fabricated signatures to distrust: sudden membership splits, whole-cluster stalls, mass reboots with NO panic on serial, `.cache_coherency` vanishing, nodes going EIO-dead when a rival re-preps/mkfs/PR-registers the shared LUN mid-run.

## MANDATORY at every ccloop session start
```bash
# 1. Find stale ccloop claude sessions for THIS project (not your own PID, not other projects'):
pgrep -af "claude --.*-src-mxfs|claude --.*session-id" | grep -v $$   # or: ps -eo pid,ppid,lstart,cmd | grep 'claude --'
# your own session-id is in the env; predecessors are listed in .ccloop/runs/<run>/sessions.log
kill -9 <stale PIDs>
# 2. Sweep their orphaned work:
pgrep -af 'run\.sh|dir_reuse|cache_coherency|mxfs_sshpass'   # kill local trees
# per node: pkill -9 -f <suite script name>  (ssh kill does NOT kill remote bash)
# 3. Check /tmp/run_* dirs and /tmp/claude-1000/-src-mxfs/*/tasks/*.output mtimes for runs you didn't launch.
```

## Hardening added sess3
run.sh takes an exclusive flock on /tmp/mxfs_run.lock — a second concurrent run.sh instance FAILS FAST with a loud message instead of silently stomping the cluster. If run.sh reports the lock is held, find and kill the holder (or a stale session).

## Evidence-trust rule
Any run result from a window where a rival session was alive and possibly active is CONTAMINATED — reproduce on a clean field before acting on it. Sess2's clean-substrate A/B (031632Z floor=0 PASS vs 032702Z/033921Z floor=1 0/32 + ICD wedge) completed while sess2 was still the sole active session (pre-22:46), so it PROBABLY stands, but sess3 re-verifies before fixing.
