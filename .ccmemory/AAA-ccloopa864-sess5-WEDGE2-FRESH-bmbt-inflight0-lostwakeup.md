---
name: AAA-ccloopa864-sess5-WEDGE2-FRESH-bmbt-inflight0-lostwakeup
description: sess5 wedge#2 FRESH repro (default cfg, build E5F760E6): rank1 rm stuck 192s in mxfs_dir_bmbt_scan→xfs_bwrite→xfs_buf_iowait, inflight=0 (lost-wakeup…
metadata:
  type: project
---

# sess5 — wedge#2 FRESH repro on DEFAULT config (build E5F760E6): durable-signal bmbt flush lost-wakeup

## Clean repro achieved (default config, NO modargs, /dev/mapper/mpatha)
After parallelizing run.sh convergence gate + stabilizing cluster, a default-config 32-node dir_reuse run reproduced wedge#2 at **round 1** (earlier than sess4's r8-9 — timing-dependent). Caught via tests/drc_wedge_capture.sh test1.

## THE STACK (rank1 rm, D-state, stuck 192s+ and counting)
```
xfs_buf_iowait+0x24   [mxfs]
xfs_bwrite+0x2c       [mxfs]
mxfs_dir_bmbt_scan+0x34f      <-- BTREE dir bmbt flush (xfs_mxfs_dlm.c:772), NOT owner_scan
mxfs_dir_flush_data_blocks+0x1d2   (calls bmbt_scan(true) at 3881 for fmt=BTREE)
mxfs_dlm_dir_durable_signal+0x136
xfs_remove+0x416      <-- per-unlink durable signal (xfs_inode.c:4326)
xfs_vn_unlink → do_unlinkat
```
dir ino=131 is fmt=3 (BTREE). rm removing round-1 dir entries.

## KEY DIAGNOSTIC (differs from sess4's AIL-jam theory)
- **inflight=0** on dm-1 AND sda AND sdb (cat /sys/block/*/inflight all "0 0"). So NO bio in flight — the bio was never submitted OR its completion was lost. xfs_buf_iowait (pal/linux/xfs_buf.c:4962 → wait_for_completion(&bp->b_iowait) @4969) waiting forever.
- **LONE stuck task** — only "rm" in D-state. NO bast kworkers stuck, xfsaild RUNNING. So NOT the sess4 multi-party AIL-jam deadlock. This is a **lost-wakeup / not-submitted xfs_bwrite** on ONE buffer.
- multipath HEALTHY (both paths active/ready), ZERO SCSI/iSCSI/blk errors. NOT infra.
- owner_scan's writes SUCCEED right before (P43-OWNERSCAN wrote=1-3) → mpatha I/O works; only THIS bmbt buffer's write lost its completion → intermittent RACE.

## ROOT HUNT (in progress) — the custom buffer completion machinery
pal/linux/xfs_buf.c has heavy mxfs customization around b_iowait:
- xfs_buf_submit (5317): on SYNC submit does `reinit_completion(&bp->b_iowait)` @5381 to "drain a STALE completion token" (sess7 v0.10.33 comment 5368-5381: emulated/skip completions + readahead-steal XBF_ASYNC flips leave stale tokens). 
- complete(&bp->b_iowait) sites: @1701, @1833 (ioend). reinit @1376, @5381.
- HYPOTHESIS: a race between reinit_completion and complete() — real bio completes+complete()s b_iowait, then a stale/emulated path or a second reinit zeroes done again → waiter (@4969) sleeps forever with inflight=0. bmbt_scan @770 does async xfs_log_force(0) then xfs_bwrite @772; the sess134 comment @758 warns xfs_bwrite leaves buffer LOCKED (b_sema history).
- NEXT: read xfs_buf_iowait(4962) + complete sites(1680-1720,1820-1840) + submit_bio(3309) for the reinit/complete race. If spottable → fix root. Else instrument: probe the stuck buffer's b_iowait.done / b_io_remaining / b_flags / pin at the bmbt_scan bwrite site + a bounded wait.

## Candidate fixes (decide after root proof)
1. ROOT: fix the b_iowait reinit/complete race in xfs_buf_submit/ioend.
2. Safer-partial: bmbt_scan flush is a PUBLISH (durable signal DURING op, not release) — make its xfs_bwrite a BOUNDED wait; on timeout log + proceed (release-drain guarantees durability at handoff via Invariant#1). Does NOT violate coherency (publish is best-effort; release-drain is the guarantee). This directly unwedges the rm.

## Also this session: reproducible HARD-HANG (separate bug, spinlock deadlock) — see memory AAA-ccloopa864-sess5-HARDHANG-reproducible-spinlock-deadlock. And run.sh convergence gate parallelized (was serial-32-SSH, false PREP FAIL at N=32).
## Live wedged cluster: rank1(test1) rm D-state; run will fail. All 32 nodes have unknown_nmi_panic=1 (drop-in) for hard-hang capture via inject-nmi.
