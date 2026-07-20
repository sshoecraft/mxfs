---
name: sess13-two-failure-modes-and-p91-falsepos-resurrection
description: sess13: 2/tcp tcp_dlm_scaling has TWO distinct flaky failures — (A) AG<->dir cross-node deadlock→shutdown, (B) P91-RELOAD-PROTECT false-pos→stale-bas…
metadata:
  type: project
---

## Criterion = full `./run.sh 2 tcp` 100%, validated x3 clean-reboot. NOT met. Marker NOT written.
## Build 5642A8E1 = F967E0F5 (CONVBLK) + sess13 dead-code yield (see below). Cluster: test1=DHCP .114, test2 .182 (DNS resolves names; harness uses names so OK). ALWAYS virsh destroy+start BOTH before a run (contaminated cluster → mkfs returns 1 / module not loaded = false FAILs, NOT real).

## tcp_dlm_scaling (each node: create+rename+rm its own n{R}_* in a SHARED dir) is ~1/3 → ~1/10 flaky with TWO ROOT failure modes (RULE-4 PROVEN this session, both captured via tests/tcp_scaling_capture.sh):

### MODE A — AG<->dir cross-node DISTRIBUTED DEADLOCK → FS SHUTDOWN (nodes_pass=0/2)
- test1 `rm` holds shared-dir inode EX inside a DIRTIED remove txn, then blocks ~60s acquiring AG0's DLM grant → `DLM AG lock failed: ag=0 rc=-110` (ETIMEDOUT) → xfs_remove → xfs_droplink rc=-110 → `xfs_trans_cancel` on a DIRTY trans → "Corruption of in-memory data" → SHUTDOWN (xfs/xfs_trans.c:1060). Stack: do_unlinkat→xfs_remove→xfs_trans_cancel.
- test2 holds AG0 + re-requests dir EX (P-DIRBAST every 6.14s = the MXFS_LOCK_ACQUIRE_WAIT_MS=6s ETIMEDOUT retry) for 60s. Classic ABBA. Cycle exists because AG DLM locks are CACHED across ops.
- **sess13 fix attempt (DEAD CODE — REFUTED): `mxfs_dlm_yield_basted_cached_ags()`** (xfs_mxfs_dlm.c just before mxfs_dlm_ilock_begin; called in the inode-acquire 3-attempt loop ~7160). Yields cached+basted+holders==0 AGs when blocking on an inode lock. **P13-INODE-YIELD-AG fired 0×** — eligibility requires holders==0 but in the deadlock the blocking node holds the AG as an ACTIVE holder (holders>0, both nodes mid-txn), so it never fires. Harmless; keep or revert. The real MODE-A fix needs to break an active-holder<->active-holder inode/AG cycle (lock-ordering or victim-abort that cancels the CLEAN side), OR ensure the AG lock in xfs_remove is taken BEFORE the trans dirties so -110 cancels a CLEAN trans (no shutdown).

### MODE B — shortform stale-base RESURRECTION → leftover dirent (nodes_pass=1/2)  [DOMINANT]
- Leftover e.g. `n1_r6` nlink=1 (rename+rm reverted). Detector `P58-STALE-BASE-ADD pino=… add=[n1_rX.done] fmt=0 dir_gen=12 loaded_gen=3 reload_flag=1` + `P91-RELOAD-PROTECT ino=0x80 blkno=0x80 flags=0x20` on the failing node. P-CONVBLK-DENY (held PR, peer wants EX) also present.
- ROOT: on a fresh dir-EX (re)acquire with peer_modified (dir_gen>loaded_gen), mxfs_dlm_reload_inode tries to stale+re-read the dir's CLUSTER buffer, but **P91 (`mxfs_buf_has_uncheckpointed_mods`, xfs_mxfs_dlm.c:8591) keeps it** → stale base kept → next add RMWs stale base → durably resurrects peer's removed dirent.
- **KEY INSIGHT: P91 is a WHOLE-CLUSTER-BUFFER over-approximation** — `if (bip) { … return true; }` ("BLI attached at all → a transaction touched this buffer"). It CANNOT distinguish: (A) the dir's own mods already ON DISK but BLI lingers in AIL until next log-tail checkpoint [SAFE to reload], (B) a CO-RESIDENT inode (same 4KB/16-inode cluster) with un-destaged mods [keep], (C) genuine un-destaged dir mod [keep]. The captured buffer flags=0x20 (XBF_DONE only, NOT dirty/DELWRI) ⇒ case A false-positive (durable, BLI lingering). This is the SAME contradiction the AG-meta path already solved with the li_lsn-vs-payload_lsn discriminator (`mxfs_ag_meta_payload_lsn` 8645, sess120) — but dinodes have NO on-disk LSN field stamped at write time, so that exact trick doesn't port.
- **FIX DIRECTION (proposed, unimplemented):** reload ONLY the dir's OWN dinode shortform fork from the FUA-fresh on-disk image (per-dinode, not whole-cluster-stale) so co-resident inodes are untouched (no P91 needed). For disjoint-name serialized churn this is sound (at reacquire we have no newer dir mods than disk — peer is ahead). cf existing P9-SFREFRESH (xfs_mxfs_dlm.c ~6240) which already compares in-core shortform vs disk and reloads if differ (but is gated/limited). GPT verdict (prior sessions) = Option A strict dir-EX tenure OR shortform 3-way merge (base snapshot + replay our delta) — both sound for disjoint names.
- mxfs_inode_cluster_durable (1514) DOES synchronously delwri_submit+blkdev_flush the dir cluster on release, so the dir's own mods SHOULD be durable at release; the resurrection is the reload REFUSING to adopt disk, not a non-durable write.

## NEXT: implement per-dinode shortform reload (bypass whole-cluster P91) OR strict tenure; validate FULL run.sh 2 tcp x3 after clean reboot. Touchpoints: reload self-skip/P91 4944-5070; P9-SFREFRESH 6225-6331; reload repopulate after invalidate 5070+. [[sess12-churn-resurrection-root-and-gpt-fix-A]] [[sess10-SYNTHESIS-handoff-and-final-target]] [[sess9-root-durable-revert-and-publish-only-regression]]
