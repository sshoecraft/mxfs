# Sess23 Analysis

## Goal
Get MXFS to clean release across 16 nodes. Sess22 ended with v0.3.82 in tree, 3/17 PASS rate (~17%), and a hard-reset gotcha blocking reliable variance sampling.

## Sess23 results summary

**v0.3.83 in tree, validated**: closes iter-1 DLM timeout family by
detecting CAW slot stale-disk garbage (popcount(h_ex)>1 / popcount(h_pw)>1
/ granted_mode != recompute(holders)).  3-cycle stress: avg 3.7 iters
completed before bnobt LEFT/RIGHT-FAIL.

**v0.3.82 baseline rerun**: 0/3 cycles pass iter 1.  Sess22's claimed
"3 PASS runs" were script-bug false positives.

**Remaining bug**: bnobt LEFT/RIGHT-FAIL during exclusive AG hold
(intra-node bnobt buf state lost between alloc and free walk).  P28
captured leaf_buf at daddr=0x8 with BLI attached + flags=0x30
(XBF_ASYNC|XBF_DONE) + content showing pre-modification state.

**Next session**: this is sess22's priority-1.  Hypothesis from sess22:
some xfs_buf_stale caller during exclusive AG hold replaces buf content
while preserving BLI in trans's t_items.  Best candidates per audit:
- `xfs_mxfs_dlm.c:2195` (mxfs_dlm_invalidate_ag_meta) — fires on fresh
  AG-acquire, ALWAYS stales AG-meta bufs incl. BLI-attached.  v0.3.81
  attempted skip-on-bli for btrees, made things worse (cache stayed stale).
- `xfs_trans_buf.c:642` (xfs_trans_binval).
- `xfs_inode.c:1216` / `xfs_icache.c:842` (cluster buf staling paths).

The right fix likely: ensure BLI is fully iflushed (b_log_item cleared)
before staling AG-meta bufs at fresh-acquire.  Currently the deferred-release
drain in bast_work_fn (Phase 2b) submits writes but may not wait for
completion.

## Action #1 (closed): T2 rmmod failure
RESOLVED: transient — refcnt drops to 0 within 60s after umount-busy
window.  /tmp/mxfs_cluster_reset.sh now retries up to 8× with 10s sleeps.

## Action #1 (original notes): Investigate T2 rmmod failure

**Symptom (from sess22 state.md)**: After `umount /mnt/shared` on T2, `rmmod mxfs` fails with "module is in use". Without rmmod+insmod between stress runs, run-2+ fails at 0 iters (DLM timeout). Hard reset on each run is mandatory for representative sampling.

**Hypotheses**:
1. perag held reference not released at umount (xfs_unmountfs path doesn't drop all perags?).
2. DLM thread/workqueue not joined at umount (mxfs_v5_dlm_unmount missing some teardown).
3. PAL bdev reference held (mxfs_pal_bdev_open paired with bdev_release in unmount path).
4. CAW slot/heartbeat thread.
5. xfs_buf cache shrinker callback.

**Diagnostic plan**:
- ssh T2: `lsmod | grep mxfs` (refcnt) and `cat /sys/module/mxfs/refcnt`
- After umount: `cat /sys/module/mxfs/holders/` and look at task wait chains
- `ps auxf` for mxfs-related kthreads still alive
- `/sys/kernel/debug/mxfs/` if debugfs present
- Log umount path with pr_warns at each teardown step

## CRITICAL FINDING — sess22 PASS reports are FALSE POSITIVES

The stress script `/tmp/mxfs_stress_v033.sh` has a fatal hole:
- `shutdown_check` only inspects dmesg for corruption markers.
- It does NOT check that `dd` succeeded (no `T2_DD_OK` count).
- It clears dmesg before run start — so if T2 was already shut down from
  a prior run, no new corruption-marker is logged this run.
- Result: when T2's mount is in shutdown state and dd fails with EIO from
  iter 1, the script reports "ALL 15 ITERS PASSED" because:
  (a) T1's dd succeeds (T1 alone, no peer, doesn't trigger cross-node bug)
  (b) dmesg has nothing new to flag.

Empirical evidence (v0.3.82 logs):

| Log | T1_OK | T2_OK | T2_err | Verdict reported |
|---|---|---|---|---|
| v382_clean1 | 15 | **0** | 30 | ALL 15 PASSED *(false)* |
| v378_run3   | 15 | **0** | 15 | ALL 15 PASSED *(false)* |
| v380_run4   | 15 | **0** | 15 | ALL 15 PASSED *(false)* |
| v378_run1   | 11 | 11    | 1   | FAILED at iter 11 *(real)* |
| v380_run3   | 14 | 14    | 2   | FAILED at iter 15 *(real)* |

The runs that "failed" are the runs where BOTH nodes were actually doing work.
Those got to iter 11-14 before bnobt/DLM bug.  The runs that "passed" are
where T2 was already broken from iter 1.

**Sess22 conclusions to discard**:
- "Three full 15/15 PASS runs" — none were real.
- "FUA architecture is right foundation" — based on bogus pass rate.
- "Variance is real (17% PASS)" — the 17% is the false-positive rate.

**Real v0.3.82 state**: when both nodes work, fails at iter 5-15 with
bnobt corruption or DLM timeout.  When T2 is dead, T1 runs 15 iters
"clean" because there's no cross-node coherency to break.

## Hard-reset gotcha context

Probably the SAME issue.  T2 fails with iter-1 bnobt → FS shutdown →
unmount leaves DLM/PAL refs held → rmmod fails "module in use" →
next stress run starts with degenerate state.

## NEW Sess23 priority order
1. Fix stress script: require T1_DD_OK + T2_DD_OK + rm-OK every iter.
   Don't clear dmesg.  Capture T2 dmesg at fail.  **DONE**
2. Re-run v0.3.82 with corrected script.  Get HONEST baseline.  **In progress**
3. Investigate iter-1 T2 EIO root cause (probably bnobt-as-XFS-layer).
4. Bnobt audit (xfs_buf_stale during exclusive AG hold).
5. Fix rmmod-fail (likely follows from #3 — shutdown FS holds refs).

## Honest run distribution so far (sess23)

| Run | First-fail iter | Mode |
|---|---|---|
| real1 | iter 3 | T2 Corruption(0x8) at xfs_trans_cancel xfs_create — Mode A "Free inode has blocks allocated" family |
| real2 | iter 1 | (script timezone bug — old corruption residual)  |
| real3 | iter 1 | both nodes Connection timed out fdatasync  |
| real4 | iter 1 | T2 DLM inode lock failed ino=128 mode=PR rc=-110 (root dir EX held by T1, T2's open() never gets PR) |

Real PASS observed: 0/4. The 17% sess22 PASS rate was false-positive script bug.

## NEW finding: CAW slot infinite-repair loop

Post-iter-1-wedge state on T2 (mounted, FS not shut down, DLM hung):
T2's dlm_caw read_slot reports CAW slots 58678 + 58679 corrupt
("gm=104 wm=34 w=3382d0158cf22a68 yt=2980091d0278001
h_cw=a0c601a420126500 h_cr=7adf4cf27f7d4290").  caw_repair_slot
CASes to "gm=5 h_ex=e0041d00e1000413 h_pw=cd036650804c0005
h_pr=eb202b0802ee1181".  Next read returns same corrupt content.
LOOP repeats >100×/sec indefinitely.

Both READ and CAW use SCSI FUA (verified working cross-initiator
via tools/fua_verify in sess22).  Yet the post-CAW read sees the
PRE-CAW content.  Three possibilities:
- (a) repair CAS reports success but doesn't persist (FUA broken on this path?)
- (b) Some other thread on T2 is concurrently writing back the corrupt content
- (c) FUA-read on this path falls back to bio (-EOPNOTSUPP)?

Note: "repaired" h_ex/h_pw/h_pr are themselves invalid bitmaps for a 2-node
cluster (e004... is not a 2-bit value).  caw_repair_slot only checks gm/wm
in slot_appears_corrupt(); preserves h_ex/h_pw/h_pr even if invalid.

**Action**: This is a CAW path bug, not the bnobt bug.  Either:
1. CAW slot struct layout/alignment skew across reads.
2. There's a real disk-corruption problem with FUA-CAW + FUA-read.
3. The repair logic needs to also reset h_ex/h_pw/h_pr if they're invalid bitmaps.

Without clean module reload, accumulated state breaks runs. Working sequence per stress cycle:
- T2 umount -f
- T1 umount -f, rmmod, insmod, mkfs, mount
- T2 rmmod, insmod, mount
- run stress

## Don't repeat
- v0.3.70 fua_window_until per-pag gate
- v0.3.72 blkdev_issue_flush in invalidate_ag_meta (deadlock)
- v0.3.74 REQ_FUA on writes (slows xfsaild)
- v0.3.79 retries 100→500 (widens windows)
- v0.3.81 skip-on-bli for btrees in invalidate_ag_meta (cache stays stale)
- All sess14-sess21 entries
