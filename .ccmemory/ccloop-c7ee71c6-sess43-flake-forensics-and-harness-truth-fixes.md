---
name: ccloop-c7ee71c6-sess43-flake-forensics-and-harness-truth-fixes
description: sess43: 5 flakes forensically attributed; 3 harness truth-bugs found+fixed (reason dropped, gate vs 10-min lease, faildist); 353 board green
metadata:
  type: project
---

# sess43 part 2 — WHY THE BOARD WENT FLAKY (user question, answered with evidence)

## The user's question
"Last week green across ~10 back-to-back runs, now half the tests don't work — why?"
Answer: the FILESYSTEM did not regress. The board ran ~11x in one day (vs occasionally
before), a flake-HISTORY display was added, and the display counted RIG failures as test
flakes. 9 of 14 "FLAKY" rows were rig; 5 were genuine and are now each attributed.

## HARNESS TRUTH-BUGS FOUND AND FIXED (these were manufacturing/hiding flakes)
1. **run.sh history dropped `reason`** — node-side finish() names every failing check in
   reason=; the live cell kept it but the history push discarded it, so the moment the
   next run overwrote the cell the evidence vanished. THIS is why D-DIR-REUSE sat
   "UNROOTED: which check failed is not yet captured" for sessions. FIXED (both push
   sites carry reason[0:400]).
2. **Reconvergence gate vs the 10-minute lease** — gate demanded beacon active_count==N.
   MXFS_LEASE_TIMEOUT_DEFAULT_MS = 600000 (lease.h:58) and a rejoining node takes a NEW
   node_id, so after ANY fault test the lease legitimately reads N+1 for up to 10 min.
   Gate read that as split-brain and set BLOCK_REST → every later criterion in the chunk
   blocked on a healthy cluster. MEASURED: after crash_consistency beacon=33 while the
   on-disk HB table had exactly 32 correct live writers (ids diffed 1:1 against all 32
   nodes' current node_ids); beacon returned to 32 on schedule. FIXED: on over-count the
   gate consults tests/hb_live_count.sh (authoritative disk table); ==N passes with an
   explanatory line, >N still fails as real split-brain. VERIFIED: crash_consistency,
   fence_during_write, fault_netpartition all reconverged cleanly afterwards.
   **This is a systematic historical flake generator** — explains pre-assert/NOT_RUN
   cascades after destructive tests in the Aug-1 history.
3. **No per-node failed-count distribution** — only first_fail + rank1 were kept, so
   "every node failed the same 1 check" (shared object) vs "one node failed 16" (that
   node's own artifacts) were indistinguishable after the fact. FIXED: faildist[1x31,16x1].

## showstat.sh — FLAKY now means one thing (user directive, 2 rounds of correction)
Status column = current run verdict; a genuine test-detected failure in history keeps
the cell ⚠ FLAKY (NOT downgraded to PASS — user explicitly rejected that). Excluded from
"genuine": pre-assert | NO_TERMINAL_RECORD | run was killed | prep fail, prep_cluster and
open_defects rows entirely, and pre-2026-08-02T04:00Z reconvergence verdicts (the gate
itself was broken until then — a broken gate cannot produce FS evidence). Live ledger
count is shown on the open_defects row. Result: 22 PASS / 5 FLAKY / 1 POLICY at 32/caw.

## THE 5 GENUINE FLAKES — attribution
- **rsync_paired (1)** = D-RELABORT-...-SELFFENCE incident (FIXED AND VERIFIED). Done.
- **dir_reuse (4)** = PACE. checks=7*rounds+2 ⇒ 51 means 7 rounds < floor 8. ONE build did
  6,7,7,7,8,8,8,9,9,10 rounds/100s in one day: median 8 = ZERO margin ⇒ ~36% fail rate.
  NOT new: 32/cawd Jul25=9, cawp=9, tcp=11; the Jul-28 published status.md has the same
  r7 FAIL. Symptom of D-32NODE-SHARED-DIR-CREATE-PACE; closure bar recorded (median >=10
  rounds, quiet rig, 10 consecutive).
- **scaling_curve (1)** = same pace family (rate/window checks, 11/32 nodes).
- **cache_coherency (1) + zsl (2)** = D-CACHE-COHERENCY-UV-COUNT-MISS-2332 (renamed from
  the vergate-collapse entry). ARITHMETIC ROOT: cache_coherency emits 653 checks on peers
  and 654 on rank1 (cv 2+2T=66, cwr 66, rv 3+3*T*4=387, uv 6+T*4=134, +1 rank1-only);
  record shows test1=rank1=654 with 1 failed ⇒ the failing check is rank1's UNIQUE
  "uv all files present pre-delete" count assert, i.e. a cross-node VISIBILITY miss of
  peer files after the uv_create barrier. Verified 654 live at 32 nodes.

## EXCLUSIONS PROVEN THIS SESSION (what the 23:32 collapse was NOT)
- **vergate hb arm is NOT the cause**: tests/vergate_collapse_repro.sh arms a/b/c (fake
  live-legacy writer idle / +load / +withdraw-rejoin+load) ALL PASS at 8/caw on 353,
  every mount intact, 0 forced shutdowns. Fence targets only the fake slot (PR key absent
  ⇒ no live member preempted).
- **Barrier timeout cannot produce a COUNTED failure** for cache_coherency: COORD_TIMEOUT
  120 > budget 60 ⇒ the budget kills first. PROVEN: virsh-suspending a member yields
  NO_TERMINAL_RECORD on all nodes (different signature from the record).
- **The mount loss needs no FS defect**: prep_cluster's own teardown unmounts+rmmods every
  node; the 5 consecutive prep failures (test32 root disk 100% full) explain "31 nodes
  lost their mounts".
- 10x cache_coherency + 6x zsl at 32/caw on 353: all PASS, no reproduction (per RULE 6
  that is NOT a disproof; instrumentation now makes the next occurrence self-diagnosing).

## SELF-INFLICTED (own goal, documented so it is not repeated)
My fsdown watcher, orphaned when its script hit the outer timeout, ran `umount -l` on
test32 AFTER the cleanup trap had remounted it → next 2 board tests pre-asserted. Same
shape as the Aug-1 test32 breakage: a TEST SCRIPT side effect, not an FS defect. Fixed
(trap kills the watcher first). LESSON: any harness that degrades a node must kill its
remote agents before restoring, and bound the agent lifetime.

## NEW LEDGER ENTRIES
- D-CACHE-COHERENCY-UV-COUNT-MISS-2332 (critical, OPEN) — rewritten with the arithmetic
  root, all exclusions, and a next_step that uses the new instrumentation.
- D-UNMOUNT-RELEASE-FLUSH-AFTER-PR-UNREGISTER (minor, OPEN) — EVERY clean unmount of a
  PR LUN ends in a FAILED Synchronize Cache (reservation conflict, dm-1 sector 0):
  xfs_shutdown_devices (xfs_super.c:1599) releases the bdev AFTER the late PR unregister
  (1583), so the release flush always runs unregistered. Durability believed unaffected
  (XFS writes the unmount record + flushes while registered, v0.11.74 deferred-unregister)
  but it is a failed I/O on a clean path and it poisons every reservation-conflict health
  grep (it produced a false COLLAPSE verdict in my own arm). Fix candidates + a 20-unmount
  verification bar are recorded.

## BOARD STATE — 0.11.353 (srcversion 342A1945862622094889DEC), 32/caw ALL GREEN
27/27 substantive PASS in 5 chunks (chunk B re-run after the self-inflicted test32 break).
dir_reuse 65 checks = 9 rounds. My 353 kernel changes (recovery GUARD, UBSCAN/own-bucket
rescan, AG-DLM lock around the orphan scan) regressed nothing.

## NEW TOOLS (RULE 3, all in tests/)
- hb_slots.sh — decode the 64-slot HB table (flags incl. GUARD=3).
- hb_live_count.sh — AUTHORITATIVE live-member count. TWO traps it encodes: HB timestamps
  are the writer's MONOTONIC clock (never compare to local wall time — sample twice and
  look for CHANGE), and reads MUST be O_DIRECT (a buffered re-read of peer-written sectors
  returns this node's cached copy ⇒ reported live=0 on a healthy 32-node cluster).
- vergate_collapse_repro.sh — 3 arms; detector tightened twice (a bare case-insensitive
  'shutdown' matches "generic_shutdown_super" in P199 lines ⇒ false 18-shutdown COLLAPSE;
  bare "sd N: reservation conflict" is the normal PR-probe artifact at EVERY mount).
- degraded_member_cascade.sh — freeze arm conclusive; fsdown arm NOT yet conclusive
  (cache_coherency FS body is seconds long; needs a longer test or a test-side pause hook).
