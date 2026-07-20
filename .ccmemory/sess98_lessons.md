---
name: sess98_lessons
description: sess98 — BUILT the long-wanted dir-block WRITE-submission trace (P-DIRWR). PROVES unlink lost-update = nodes' xfsaild flush in-core dir buffers 1-2 d…
metadata:
  type: project
---

# sess98 (2026-06-05/06, ccloop run 29df431e) — write-trace breakthrough

## State at start
cache_coherency blocker. Deployed E06FDBC3 (= cumulative tree: sess95 reloads +
sess96 typeflip-ftype + sess97 release-checkpoint-fence). unlink_visibility fails
(durable lost-update on shared block-format dir); rename/cwr intermittent.
fua_disable=1 default (KEEP). Cluster test1-4 (node_offset 0; reset4.sh 4).

## BUILT THE DECISIVE INSTRUMENT (finally): P-DIRWR write-submission trace
In pal/linux/xfs_buf.c xfs_buf_submit, for every dir block/leaf/data buffer WRITE
on a multi-node mount, log: fmt, owner-ino, daddr, count, stale, active=count-stale,
pin/in_ail/dirty/done, comm, realns. Counter-capped 8000 (not ratelimited — captures
whole test). Per-node dmesg = node identity; realns merges 4 nodes into ONE per-daddr
timeline. Also added P-DIRFASTEX (xfs_mxfs_dlm.c fast-path EX grant for NON-shortform
dirs: ino/dir_gen/loaded_gen/stale_base). Build 8946A0F6.

## PROVEN ROOT (RULE-4, the write trace is airtight)
Unlink dir = ino 135, block-format, single block (daddr=120 one run, 6262080 next —
varies by mkfs). In the DELETE phase `count` stays constant (e.g. 112/122); each
deletion = +1 to `stale` (entry marked stale, not compacted); active=count-stale must
DECREASE monotonically 112→14. Instead **active OSCILLATES — stale DECREASES on some
writes** = a node flushes an in-core dir buffer 1-2 deletions BEHIND a peer's already-
flushed version, durably reverting peer deletions. e.g. `+20165 node3 active 29→30`,
`+20280..20703 node4` repeatedly reverts. THE lost-update, proven at write granularity.

KEY FACTS:
1. **ALL target writes are comm=xfsaild/sda** (async AIL push), in_ail=1, spread over
   10-21s. ZERO writes by the release path. The release-side synchronous flush is NOT
   landing the block — the block reaches the shared target only via async xfsaild.
2. Reverts are NEAR-CONCURRENT during active deletion (node2 flushes stale=20 ~100ms
   after a peer flushed stale=21), so node2's RMW base was ~1 behind the target =
   acquire-side stale read, NOT just seconds-late old-tenure flushes.
3. P-DIRFASTEX stale_base=1 fires (dir_gen=1 > loaded_gen=0) but is a COARSE signal:
   loaded_gen stays 0 because the gen 0→1 arm in xfs_da_btree.c:2904 is a READ hook
   that does NOT reload (loaded_gen only set by slow-path mxfs_dlm_reload_inode). So
   stale_base=1 ≈ "multi-node armed", not reliably "stale". Don't trust it alone.

## FOUND + FIXED a REAL release-side gap (necessary, NOT sufficient)
`mxfs_dir_data_durable` (xfs/xfs_mxfs_dlm.c:85, the GATE that decides if the sess97
release fence loop can break) checked DIRTY|pinned|DELWRI_Q|!DONE but **OMITTED
XFS_LI_IN_AIL**. A removename-committed block is DIRTY=clear,pin=0,DONE=set,IN_AIL=set
(in local AIL, NOT yet on target). So the gate reported it "durable", the loop broke
WITHOUT flushing, and the lock was handed off with the deletion only in-core. NOTE:
`mxfs_dir_flush_data_blocks` (the actual flush) ALREADY tests IN_AIL — the gate was
just more optimistic than the flush (inconsistent). sess43 added IN_AIL to the READ
hook but never to this release gate. FIX: add IN_AIL to `bad`. (Symmetric, 1-condition.)

## RESULT of the IN_AIL fix: STILL FAILS (2-21 survive, run variance), sometimes 5x SLOW
- P-RELFLUSH probe (logs each release-path xfs_bwrite): fired **0×**. So the release
  xfs_bwrite STILL never runs — the whole-AG xfs_ail_push_ag_sync(d_agno) at L1336
  (called BEFORE mxfs_dir_flush_data_blocks at L1338) triggers xfsaild to write+AIL-
  remove the block first, so by L1338 needs_flush=false → skip. The block IS landed
  before release (via xfsaild sync push) so Inv1 ~satisfied, but the whole-AG sync push
  is SLOW (one run 148s vs 26s — timing FAIL) and the reverts persist anyway.
- So Inv1 (release fence) is ~satisfied yet lost-update persists ⇒ the remaining bug is
  ACQUIRE-SIDE: a later EX acquire RMWs a stale base (reads target/cache ~1 deletion
  behind), and/or a per-node in-core buffer is flushed by xfsaild out of tenure order.

## Builds
- 8946A0F6 = E06FDBC3 + P-DIRWR + P-DIRFASTEX probes.
- 1383B52D = +IN_AIL fix in mxfs_dir_data_durable.
- 8AA373A2 (CURRENT) = +P-RELFLUSH probe. All probes KEEP (harmless, capped/ratelimited).

## NEXT (consulting GPT w/ write-trace evidence — RULE 5; sess96 GPT design = [[sess96_gpt_fix_design]])
The "release-flush + reread" class has failed ~4× (sess96×2, sess97, sess98-Inv1).
GPT design (Inv1 release-checkpoint-fence / Inv2 acquire-invalidation-fence / Inv3
DIR-STALE-SKIP→fatal) only PARTLY implemented. New evidence localizes the live bug to
ACQUIRE-side stale base + async-xfsaild out-of-tenure-order flush of per-node buffers.
Implement GPT Inv2 precisely: every dir EX acquire (incl FAST-PATH — P-DIRFASTEX proves
fast grants happen) must hard-invalidate cached dir data blocks so the RMW re-reads the
fresh target; AND prevent xfsaild flushing a superseded in-core buffer after release
(per-node buffer caches + async writeback = no global writeback order = root tension).
Must avoid: whole-AG sync push slowness, rereading a PINNED buf (corrupts, sess64),
writing a stale buf (clobbers, sess96 Fix A). Keep IN_AIL fix; drop whole-AG push for a
targeted per-buffer flush. Related: [[sess96_lessons]] [[sess95_lessons]].
