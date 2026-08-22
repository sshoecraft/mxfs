---
name: ccloop-c7ee71c6-sess218-ROOT-shared-log-slices-4-vs-32-nodes
description: sess218 ROOT CAUSE incident474 slot-30: 8 nodes SHARE each log slice (mkfs default -n 4, prep_fs.sh passes no -n; slice=slot%4). H-A refuted.
metadata:
  type: project
---

# sess218 — incident474 slot-30 forever-retry ROOT CAUSE

## The root
`mkfs_mxfs` default `log_node_count = 4` (tools/mkfs_mxfs.c:1479, flag `-n`,
1-64). `tests/setup/prep_fs.sh:74` runs `mkfs_mxfs -f $DEV` with **no -n**, so
every rig prep formats **4 XFS log slices**. Slice index = `slot %
m_mxfs_log_node_count` (xfs_log.c:811 foreign replay; xfs_mountfs same
mapping). At 32/caw, slots 0..31 ⇒ **8 nodes concurrently write each slice**
(slots 2,6,...,30 → slice 2). Proof line: test1 19:35:19 "foreign replay of
dead slot 30 (slice 2/4) offset=52592784 bblks=131072".

The slot30_slice.gz "two inconsistent chains" (7285/7291 iunlink chain vs
7294/7297 SB-covering dummies claiming prev=7290) are TWO DIFFERENT NODES'
interleaved streams, each self-consistent. find_tail on the soup → the
deterministic -EIO at xfs_log_recover.c:1091 (empty 1-block search window).

## Evidence
- All 1529 slice headers: ONE uuid 5fd0a6b2a0794a33bfac589dc4929d32, zero
  lsn-vs-block skews (scripts/xlog_slice_scan.py, now prints uuid+skew+summary).
- LUN sector-0 MXFS super uuid @byte16 = same uuid; prep 19:33:53Z mkfs'd
  unconditionally (FS_PREP_OK, rc=0); gen_uuid=/dev/urandom v4 ⇒ **H-A
  (stale residue) REFUTED** — everything is current-incarnation.
- test1's FIRST replay attempt 19:35:19 already rc=-5 ⇒ corruption predates
  any survivor recovery (concurrent writers during 19:34 load, not
  post-death rewrites).
- Timing: 2 covering dummies need ≥2 idle 30s log-worker ticks — impossible
  for test30 (~70s life, busy under load); natural for an idle slice-2
  co-tenant whose mount-time find_tail adopted head 7294 / tail 1:7290 from
  the shared stream.

## Collateral finding
`xlog_clear_stale_blocks` (xfs_log_recover.c:1391) is gated only on
`!xfs_readonly_buftarg` — foreign shadow replays that pass find_tail WRITE
cycle-filler into the victim's slice. Design says foreign replay leaves the
slice untouched (xfs_log.c:760 comment). Independent hazard.

## Implications
- Every 32-node "victim slice" analysis to date assumed per-node slices —
  wrong premise; crash_consistency/fence replay tests have been replaying
  8-writer soup. How boards passed 27/27 needs an answer (LSN-gate luck?).
- Fix shape (pending RULE-5 consult): prep_fs.sh pass `-n <nodes>`; consider
  mkfs default = 64; PLUS hard guard making sharing unrepresentable: refuse
  mount/slot-claim when slot >= xfs_log_node_count, same in foreign replay.
- Separate: bounded retry + escalation for unreplayable slice (474
  containment hole) still needed.
