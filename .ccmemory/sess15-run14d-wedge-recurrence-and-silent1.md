---
name: sess15-run14d-wedge-recurrence-and-silent1
description: sess15: SCST wedge RECURRED mid zero_silent_loss (iter2 mkfs); fixes: chunked BLKZEROOUT (v0.4.11), pre-mkfs rmmod barrier, forensics-on-loss. NO hos…
metadata:
  type: project
tags: [sess15, scst-wedge, zero-silent-loss]
---

# sess15 (run 14d31183) — wedge recurrence + the silent=1 residual

## State entering session
Host clyde freshly rebooted (sess14 wedge). Build `9C2D4FA6` everywhere.
/tmp wiped by reboot → recreate `echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass; chmod 600` —
without it cluster_reset_n.sh silently "succeeds" (fixed: script now aborts if
WANT_SV empty; modinfo needs /usr/sbin on PATH).

## zero_silent_loss runs (build 9C2D4FA6)
- Run A (300s budget, too small): iter1 silent=0, iter2 silent=0, iter3 storm
  completed (1600/1600 dirs) but verify never ran — killed by timeout.
  Per-iter wall ≈120s incl. full remount. Budget row updated to **480s**
  (TIMEOUT_BUDGETS.md; SUCCESS_CRITERIA per-iter ceiling = 5 min).
- Run B (480s): **iter1 silent=1** (pre_drop=1599 AND post_drop=1599 —
  missing both before and after drop_caches, i.e. never durably visible);
  iter2: ALL 15 joins failed → SCST WEDGE RECURRED (2 D-state
  iscsi_conn_cleanup, 33 EXEC_CHECK_BLOCKING on host).

## silent=1 — what's known (NEW bug class, NOT the old families)
- Zero P108, zero DABUF_MAP_HOLE, zero FS shutdowns in all-16 dmesg harvest:
  `.ccloop/runs/14d31183-…/forensics-s15/dmesg.test*` (survives reboot).
- Cannot identify the missing name post-hoc (iter2 re-mkfs wiped namespace;
  P127-DIRMISS logs only a subset; P-DIRWR leafn traces stop ~500 entries on
  dir format conversion).
- Frequency ~1 iter in 6. Could be: (a) creator's mkdir errored (swallowed by
  2>/dev/null — NOT silent loss, different bug) or (b) created-then-lost.
- **Forensics now built into the workload script**: per-node /tmp/wa_fail.$I
  error capture + on silent>0 enumerates missing names, creator's view,
  creator's recorded errors, per-node error counts — all while iter FS still
  mounted. Next failing run will be self-diagnosing.

## Fixes landed this session (all test-infra/tools, v0.4.11)
1. `tools/mkfs_mxfs.c zero_region`: BLKZEROOUT now issued in **4MB chunks**
   (was one 33MB WRITE SAME = strictly-serialized SCST cmd that starves >60s
   initiator timeout under load → ABORT→LUN_RESET→nexus loss→permanent wedge).
   `make tools` done; nodes see it via NFS.
2. `scripts/sess88_workload_a_modeN_baseline.sh`:
   - pre-mkfs BARRIER: every node verified umounted+rmmod'd (6 retries) before
     NODE0 mkfs — mkfs racing live CAW heartbeat was the wedge trigger.
   - pre/post sanitized to digits (`tr -cd 0-9`); non-numeric verify → loud
     VERIFY FAILED (was: `find: unbound variable` crash → fs_silent=999999).
   - per-iter timestamps: mount_s/storm_verify_s/iter_wall_s.
3. `scripts/cluster_reset_n.sh`: hard-fail if local srcversion unreadable
   (sess17: verify loop also parallelized).

## Criteria status (run-level)
13 PASS / 2 FAIL: zero_silent_loss (above), mkfs_timing (rc=1 — stale, re-run
after reboot; likely wedge-era artifact). Never-run: crash_consistency,
fence_during_write, scaling_curve, posix_semantics --nodes 16. Then full
verify_ship.sh.

## ⚠️ Wedge recovery — RULE 2 SUPERSEDES the old protocol
The old protocol here ("re-arm @reboot hook, sudo reboot") was followed and
**hung clyde hard — user had to HW-reset it. NEVER reboot clyde** (CLAUDE.md
RULE 2, [[never-reboot-clyde]]). If the SCST wedge recurs: document the wedge
state (D-state iscsi_conn_cleanup threads, EXEC_CHECK_BLOCKING counts, dmesg)
and STOP — report that the host needs a manual reset by the user. Prevention
is the real fix: the chunked-BLKZEROOUT + pre-mkfs rmmod barrier above
removes the known trigger.

After a user-performed host reset: recreate /tmp/.mxfs_pass,
`scripts/cluster_reset_n.sh 16` (measured budget, ~180s), re-run
zero_silent_loss with timeout 480.

Related: [[sess14-scst-wedge-host-reboot]], [[sess135-p108-strip-race-and-dir-relflush]], [[never-reboot-clyde]].
