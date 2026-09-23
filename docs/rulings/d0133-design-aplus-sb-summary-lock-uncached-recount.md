<!-- sess474 RULE-5 ruling D-0133 fix = A+: dedicated SB_SUMMARY DLM EX lock (never AG0) held over uncached-coherent AGF/AGI recount + cover + SB home wri… -->
# sess474 GPT ruling (2026-09-02 ~18:12Z) — D-0133 counter arm fix design

Evidence given: chain 116 s474c laps 1-2 on 0.64.26 (2/2 fail): workers test1/test2 recomputed 128/89 and 128/125 and saw their writes land (POST); 30 idle nodes recomputed 64/61 from their own STALE cached mount-time AG headers (no P-SB-RECOUNT-STALE because pag summary == cached buffer); regressors test9/test11/test28 had PRE durable=128 and wrote 64; final platter 64/61. Unmounts ~300 ms each, spread ~1 s.

## Verdicts
- **A (uncached reads + serialize recount+cover under a cluster lock): PREFERRED but must be A+**: (1) drain local AG metadata BEFORE the recount (log force + AIL push + buftarg wait — xfs_log_quiesce already does this before P30); (2) a DEDICATED DLM resource (never AG0's grant — lock-order hazard across xfs_sync_sb -> commit -> AIL push -> SB I/O); (3) hold the lock until the SB home write AND the required cache flush are complete (not just commit); rule: no inode/AG grant held when acquiring SB_SUMMARY, never acquire it inside a metadata transaction.
- **B (last member only; others preserve): REJECT** — unlocked whole-sector RMW still races; membership==1 is not a safe finalizer election.
- **C: not minimal** (needs A's serialization anyway).
- Read mode: a normal synchronous UNCACHED bio at the coherence point (on the SCST rig a plain bio reaches the coherent cache; a SCSI FUA read pierces to the lagging platter = WRONG for the recount). xfs_buf_read_uncached is fine if it bypasses the stale xfs_buf, is synchronous, verifies (magic/crc/seqno), cannot alias a dirty local buffer (pre-drain), and a read/verifier failure keeps old counters rather than writing a guess.
- Freeze path (fsfreeze -> xfs_log_quiesce): same protocol; never use membership==1; document lock order: cluster freeze/drain -> all normal metadata locks released -> SB_SUMMARY.

## Verification bar (FIXED AND VERIFIED)
Trace per node: drain done < lock grant < fresh reads < cover commit < SB home write done < flush < unlock; across nodes non-overlapping critical sections (A's unlock <= B's grant, no SB write from A after B's grant). Same shape (32 nodes, 2 workers, 30 idle, parallel unmount) ≥3/3 clean laps after the change (baseline 2/2 + s473b/s473c failures retained), vary the workers and the final writer (at least one lap where an idle node is the final writer, one where a worker is), final uncached SB read == recount == chk totals (icount, ifree, fdblocks), and the non-counter SB bytes unchanged across the rewrite.

## Implemented as 0.64.28 (tree): mxfs_sb_summary_key = ((agcount+1+65) << (agblklog+inopblog)) | 1 (slot 65, beyond per-node pw keys and the samenode key 64); mxfs_sb_summary_lock/unlock via mxfs_v5_dlm_inode_lock(EX); mxfs_sb_summary_recount_uncached (xfs_buf_read_uncached, ops=NULL, manual magic/crc/seqno checks); xfs_log_quiesce: PRE -> LOCK -> recount -> RECOUNT-DONE -> WRITE -> xfs_log_cover -> buftarg wait + blkdev flush -> POST -> UNLOCK.
