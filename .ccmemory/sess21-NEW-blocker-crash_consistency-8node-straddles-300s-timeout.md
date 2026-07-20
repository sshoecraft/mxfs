---
name: sess21-NEW-blocker-crash_consistency-8node-straddles-300s-timeout
description: sess21(ccloop) crash_consistency 8-node: standalone=29s PASS 8/8 but IN-SUITE FLAKY (passed run A, HUNG/timed-out run B >300s) → cascade. NOT inheren…
metadata:
  type: project
---

## sess21 (ccloop) — crash_consistency 8-node is FLAKY in-suite (NOT slow standalone)

Build 8D9D586E. DECISIVE measurement: **`./run.sh 8 tcp crash_consistency` standalone (clean reboot) = PASS 8/8 in 29s WALL.** So crash_consistency is FAST and CORRECT on a fresh cluster.

### But IN THE FULL SUITE it is FLAKY:
- Full run A (build 8D9D586E, 12/17): crash_consistency **PASS 8/8** (completed <300s in-suite).
- Full run B (with dir_reuse per-test budget): crash_consistency **FAIL 0/8 by TIMEOUT** (>300s, killed) → CASCADED into dir_reuse 0/8, fence 4/8, fault 3/8, soak FAIL, tcp_dlm_scaling 4/8 → final **11/17**.

### So crash_consistency in-suite went from 29s (standalone) to >300s (hung/killed) — a ~10× blowup = a FLAKY HANG, not linear slowness. Root is a recovery/rejoin RACE under ACCUMULATED suite state (11 prior tests: cached DLM locks, dirty data, journal growth, orphaned files). crash_consistency reboots a writer node → survivors detect death (lease_timeout_ms=16000) → replay dead journal → rebooted node 8-way rejoin → verify. Under accumulated state one of these steps sometimes WEDGES/stalls past 300s.

### This is the PRIMARY 8/tcp blocker now (it fails FIRST, position 12, and cascades). It is a REAL reliability bug, NOT a budget issue (29s standalone proves the work is cheap). dir_reuse (position 13) only failed here as cascade contamination — its OWN fix is valid (8/8 standalone proven).

### NEXT SESSION (RULE 4):
1. Reproduce the flaky hang cheaply: run a SHORT in-suite prefix ending in crash_consistency, e.g. `./run.sh 8 tcp rsync_paired crash_consistency` or `dlm_scaling crash_consistency`, repeat — find which prior test's leftover state triggers the crash_consistency hang. (rsync_paired runs immediately before it.)
2. When it hangs, capture WHERE: which node, which phase (death-detect / replay / rejoin barrier). Check dmesg on all 8 + the rebooted node's rejoin. Look for a stuck DLM acquire / lease / membership barrier under accumulated locks.
3. Likely an 8-node membership/recovery race exposed only under accumulated DLM state. Fix the race (would also harden dir_reuse's in-suite cumulative slowdown, sess20 +71s).
4. Standalone repro is CLEAN (29s) — MUST reproduce in-suite (or with a contaminating prefix). A fresh-reboot crash_consistency will always pass and mislead.

### State of 8/tcp: 11 PASS (all coherency+scaling+rsync) + crash_consistency-flaky-hang (THIS is the blocker) + dir_reuse fundamental-speed (budgeted 480, valid fix) + cascade victims (fence/fault/soak/tcp_dlm_scaling all pass when not cascaded). FIX crash_consistency flaky-hang → likely unblocks the whole tail. See [[sess21-FIX-union-merge-rebase-shortform-reconciles-rename-miss-and-dir_reuse]] [[sess21-dir_reuse-8node-speed-is-fundamental-necessary-coherent-IO]].
