---
name: sess121-bnobt-clobber-writeside-fix
description: sess121 (ccloop): bnobt double-free shutdown FIXED via write-side interlock (P122) at xfs_buf_submit. Build E9963FFA. Remaining: dir-visibility barri…
metadata:
  type: project
---

# sess121 (ccloop run 4eef1f39) — bnobt double-free SHUTDOWN fixed

## Build: `E9963FFA` (KEEP — proven corruption fix)

## ROOT (RULE-4 proven, decisive)
cache_coherency `rename_visibility` shutdown = **bnobt lost-update** →
`xfs_free_ag_extent` trips `ltbno+ltlen>bno` (xfs_alloc.c:2244) = freeing a
block already free in bnobt → EFSCORRUPTED. P81 verdict `DISK-INODE-OWNS-FREED
=> bnobt-lost-update`; P28 `disk_differs=0,in_ail=0` = durable on disk.

**Producer = `xfsaild` (P93-REVERT-CLOBBER)**: AIL writeback daemon flushes a
PRIOR-TENURE stale bnobt/cntbt buffer (in-core nr=1 pristine) OVER a peer's
durable split (disk_nr=2). Buffer state at clobber: `in_ail=1 dirty=0 pin=0
delwri=0 held=1 buf_gen==pag_gen` (meta-gen FROZEN at 1 → all gen-based
checks see it as "fresh"). Mechanism: AIL presence OUTLIVES buffer writeback
(BLI removed on log-tail advance, not on write completion), so a drained
clean bnobt buffer lingers in_ail across AG tenures; a peer modifies the AG
durably; xfsaild then re-pushes our stale image = revert.

## Why all prior acquire/release-time fixes MISSED it
- Read-time hook `mxfs_ag_meta_invalidate_stale`: only fires on a READ of that
  exact daddr; frozen gen defeats the gen-lag precondition.
- Acquire cold-read `mxfs_ag_meta_coldread_discard` (sess117): SKIPPED all
  in_ail buffers. My sess121 extension (P121: discard destaged in_ail
  bnobt/cntbt via `mxfs_buf_is_undestaged`) **NEVER FIRED** — the clobber is an
  EX-held IN-TENURE xfsaild push with NO release+reacquire between our commit
  and the push, so no acquire hook runs.
- Slow-path `mxfs_dlm_invalidate_ag_meta` stales in_ail bnobt but wasn't the
  taken path (P79=0).

## THE FIX (P122, write-side interlock — GPT RULE-5 design)
The ONLY chokepoint that catches xfsaild = `xfs_buf_submit()` (pal/linux/xfs_buf.c).
The existing P93 detector there reads on-disk numrecs via `mxfs_ag_buf_disk_bnobt`
and fires when `disk_nr > nr`. Converted it to a PREVENTER:
- Guard: bnobt/cntbt write + `disk_nr > nr` + `in_ail && !dirty && !pin &&
  !delwri && !mxfs_buf_is_undestaged(bp)` (un-destaged/dirty/pinned = genuine
  this-node-ahead → excluded, still written).
- Action (before bio submit): refresh `bp->b_addr` from COHERENT cache via
  `mxfs_pal_bdev_read_plain_bdev` (PLAIN bio — under `fua_disable=1` plain reads
  hit the peer-visible SCST write-back cache; FUA reads the STALE platter), then
  `xfs_buf_ioerror(bp,0); xfs_buf_ioend(bp); return;` — completes writeback as
  SUCCESS (BLI iodone removes from AIL, log tail advances) WITHOUT the stale
  physical write. NO `xfs_buf_stale` (avoids BLI-state surprise). Refresh-read
  fail → `xfs_force_shutdown` (fail-safe, never write stale).

## RESULT (4-node, clean power-cycle+reset4)
- P122 fired 2× on test2/3/4; **ltbno=0, shutdown=0 on ALL nodes** (was
  EFSCORRUPT shutdown @235s on C3B5DFE4). Corruption ELIMINATED.
- Cross-node visibility IMPROVED (node1 now sees peer node4's renames: ASSERT OK,
  was [FAIL]).

## REMAINING BLOCKER (next)
rename_visibility still TIMES OUT (EXIT=124): concurrent DIRECTORY-op coherency.
Final barrier wedges: `touch .mxfs_barriers/rv_verify/node1: No such file or
directory` (concurrent `mkdir -p` of shared barrier dir not visible/created
across nodes). 40 FAILs/node = file-not-found/empty-content, likely cascading
from desynced barriers (broken `.mxfs_barriers/<name>` dir coherency). This is
the dir-block / parent-inode lost-update family (see [[sess106_lessons]]
concurrent same-name mkdir, [[sess88_lessons]], [[sess83_lessons]]). Test flow:
tests/cluster/test_rename_visibility.sh — barriers via mkdir+touch in
`$MOUNT/.mxfs_barriers/<name>/node$id` (tests/lib/cluster.sh barrier_*).

## INFRA
- run rename alone: `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests bash
  tests/run_tests.sh --nodes 4 --phase cluster --test test_rename_visibility
  --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`
- ALWAYS power-cycle (virsh -c qemu:///system destroy+start ALL 4) + reset4
  before trusting results.
