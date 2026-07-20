---
name: AAA-ccloopa864-sess6-ROOT-wedge2a-async-completion-routing
description: sess6 ROOT PROVEN: dir_reuse@32/caw wedge#2a = lost b_iowait wakeup. owner_scan sync bwrite completes but routes to XBF_ASYNC branch (relse/queue_wor…
metadata:
  type: project
---

## sess6 (ccloop a864) ROOT PROVEN — wedge#2a is a completion-routing race

### Criteria state
Sole gap = dir_reuse_coherency@32/caw (verified criteria.json: every other 1/2/4/8/16/32 caw cell PASS, zero FAIL cells; dir_reuse@32 = only missing cell). One tree at v0.10.51 build 0349484E = union of a864 + 46ef fixes.

### Baseline (build 0349484E, DEFAULT cfg, /dev/mapper/mpatha) — WEDGED at r3
Non-deterministic wedge#2a hit at round 3 (sess5 saw r6-r8; round varies). test1 rm PERMANENTLY stuck (iowait_stuck climbed 2→66→147+, round frozen). Exact stack:
```
xfs_buf_iowait ← xfs_bwrite ← mxfs_dir_data_owner_scan+0x39d ← mxfs_dir_flush_data_blocks
← mxfs_dlm_dir_durable_signal ← xfs_remove ← xfs_vn_unlink ← unlink  (comm=rm, D-state)
```
P-IOWAIT-STUCK (pal/linux/xfs_buf.c:4980), same daddr every 4s:
`daddr=33491704 ops=xfs_dir3_leafn flags=0x30 err=0 wr_counted=0 lseq=91 wseq=91 done=0 dir_inflight=4 rd=0 wr=0 comm=rm`

### Decode → ROOT
- flags=0x30 = XBF_ASYNC(0x10) | XBF_DONE(0x20); no XBF_READ/WRITE.
- lseq==wseq==91 ⇒ a completion RAN (sess42 advances written_seq=logged_seq at __xfs_buf_ioend:1429, counted-writes only ⇒ wr_counted WAS 1 ⇒ a REAL counted write bio completed).
- done=0 ⇒ b_iowait completion NEVER signaled.
⇒ The write bio completed but routed through the **XBF_ASYNC branch** (xfs_buf_bio_end_io:1829 `if (ASYNC) queue_work else complete(&b_iowait)`; xfs_buf_ioend:1698 `if (ASYNC) relse else complete`). owner_scan's sync xfs_bwrite CLEARS XBF_ASYNC at submit (xfs_bwrite:1762), but XBF_ASYNC is a NON-ATOMIC b_flags bit set by 4 other paths that hold b_sema at different times: readahead (xfs_buf.c:987), xfsaild delwri (8097), buf-item unpin-remove (xfs_buf_item.c:554), inode-cluster-flush-fail (xfs_inode.c:6622). A race leaves XBF_ASYNC set at completion ⇒ complete(&b_iowait) skipped ⇒ rm hangs forever ⇒ round stalls ⇒ barrier timeout ⇒ FAIL. Also a double-relse/unlock hazard (async branch relses a buffer whose sync submitter will also relse).

This is the load-bearing per-unlink durable_signal (owner_scan makes dir DATA blocks durable before handoff; can't skip — sess5 durable_caw=0 lost dirents).

### THE FIX (robust, root-level, being built in sess6)
Route completion on **submit-time sync intent**, not the live racy XBF_ASYNC flag. Add `bool b_mxfs_sync_wait` to struct xfs_buf; set `= !(b_flags & XBF_ASYNC)` at xfs_buf_submit entry (~5403, under b_sema); in xfs_buf_ioend(1698) + xfs_buf_bio_end_io(1829) change `if (b_flags & XBF_ASYNC)` → `if ((b_flags & XBF_ASYNC) && !b_mxfs_sync_wait)`. Guarantees a sync submitter is always woken via complete(&b_iowait) + correct ref accounting, regardless of which context spuriously set XBF_ASYNC. Add a counter (P-SYNCWAIT-OVERRIDE) to PROVE it fires (RULE 4).

### Still open after this fix (per sess5 COMPREHENSIVE): wedge#3 acquire-starvation (P138-WAIT climb, tenure-floor/release-abort at high 32-way contention) and the rare hard-hang spinlock. May surface once #2a is fixed. Config: caw_fair_handoff=0 default, inode_mht_ms=300, dir_ex_tenure_floor=1, batch_grace_ms=25.
</body>
