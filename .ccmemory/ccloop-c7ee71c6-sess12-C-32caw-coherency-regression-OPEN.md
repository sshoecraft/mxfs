---
name: ccloop-c7ee71c6-sess12-C-32caw-coherency-regression-OPEN
description: sess12-C OPEN DEFECT: 32/caw cache_coherency FAIL (2 writers' files empty/absent cluster-wide, then full 60s stall rerun) + fence 4-survivor not-writ…
metadata:
  type: project
tags: [32-node, mpath, cache-coherency, p95d, readdir, rule6, open]
---

# sess12-C: 32/caw coherency regression — OPEN (RULE 6)

## Discovery context
After clearing all 14 stale red cells (matrix hit 548/0), I added two fresh spots at
32/caw (max-N × mpath, previously only dlm_scaling+prep recorded today):

1. **cache_coherency@32/caw FAIL #1** (26s, in-budget): 650/654 checks pass; the 4 fails:
   `node17.txt` and `node25.txt` MISSING (sees-check fail) AND content empty
   (exp="hello from node 17" got="") on EVERY node incl. presumably the writers.
   2 of 32 writers' creates+content never became visible cluster-wide.
2. **fence_during_write@32/caw FAIL #1**: 28/32 pass; test14/23/24/27 fail
   "fdw nodeN still writable" (survivor-side post-fence write check) — their 8 named
   checks all passed (checks=8 failed=0) so the fail is the still-writable probe only.
3. **cache_coherency@32/caw FAIL #2 (rerun)**: NO_TERMINAL_RECORD=32 — all 32 nodes
   produced nothing in the 60s budget (cluster-wide stall/slowdown, worse than #1).
4. Live state after: all mounted, mpath 2-path active/ready everywhere, 0 rc=-110,
   0 shutdowns. Manual probe: test1 write+sync instant; test5 `ls /mnt/shared` rc=0
   BUT dmesg shows **P95D-family BAIL storm**: "DLM reload BAIL ino=128 (i_lock
   contended; buffer staled, will retry) cnt=256 rd_held=1
   wr_last=mxfs_dlm_reload_inode rd_last=xfs_file_readdir SAME PID (comm=ls)" —
   staleness landing MID-readdir (P95D pre-lock converge only covers stale-AT-ENTRY).

## Scope discriminators (all measured today at .114)
- 32/tcp cache_coherency PASS (23s, 654/654). 16/caw cache_coherency PASS (15s).
- 32/cawp dir_reuse+dlm_scaling PASS. 32/caw dlm_scaling PASS (13s — private dirs).
- => fails only at 32 nodes × mpath × SHARED-dir churn (cv files in one dir = root-adj).
- 32/caw cache_coherency PASSED 2026-07-25 (older build, same mpath rig) — possible
  regression window .1xx→.114 (P95D readdir converge added in .112/.113!) or prior luck.

## Hypotheses for next session (RULE 4 them)
H1: P95D pre-lock converge at 32-node churn rate livelocks readdir-vs-reload on the
    shared dir (converge succeeds, staleness re-arrives mid-readdir, next readdir
    converges again ×32 nodes) → verification phase overshoots/serves stale snapshots
    → missing files in #1, global slowdown in #2. Check: count P95D-READDIR-WAIT and
    BAIL storms across nodes during a repro; correlate with the 2 missing writers.
H2: The 2 empty writers = SF-dir publish (MHT) vs CAW slot handoff race at 32-way
    fan-in — writer's dirent add lost in a stale-base RMW (dir_reuse family) or its
    publish deferred past the barrier+sync. Check writers' P13/P146/SFRM prints.
H3: fence "still writable" 4-node fail = post-fence EX freeze (memb_settle) still
    engaged on those survivors when probed (my sess12-A fix stamps last_memb_change_ms
    on EVERY connect/disconnect — at 32/caw does something flap during fence → longer
    freeze?) — CHECK: is the still-writable probe within memb_settle_ms of the fence?
    (Note CAW mounts have no TCP mesh — but lease/membership events still stamp.)
H4: budget: 60s flat at 32 may also be structurally tight for this row (Fail #1 ran
    26s though — budget is NOT the primary issue; the stall in #2 is real).

## How to reproduce
Rig: scripts/rig.sh mpath 32 (portals .1+.2, /dev/mapper/mpatha; currently UP).
Cluster: prepped 32/caw marker current. `./run.sh 32 caw cache_coherency` (60s budget).
Test body: tests/suite/cache_coherency.sh (shared-dir cv_node*.txt write+verify).

## Do-not-forget
- criteria.json currently records these 32/caw FAILs (kept honest — do NOT relabel).
- All other work this session is green; see sess12-A (TCP false-death ROOT FIX) and
  sess12-B (dlm_scaling harness + red-list clearance). tcp column fully green .114.
- Answer to criteria remains NO until this is dispositioned + matrix re-green.
