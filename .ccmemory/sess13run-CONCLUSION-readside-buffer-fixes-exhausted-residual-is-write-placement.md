---
name: sess13run-CONCLUSION-readside-buffer-fixes-exhausted-residual-is-write-placement
description: sess13(ccloop) CONCLUSION: ALL read-side/buffer-lifetime fixes exhausted (xfs_buf_stale publish-discard build D7F1FC0B also 399/400, no shutdown). Re…
metadata:
  type: project
---

## sess13 (ccloop) CONCLUSION — the dir_reuse residual is a WRITE-PLACEMENT bug, not a read/cache bug

### Read-side & buffer-lifetime fixes are EXHAUSTED (all land at 399/400, no shutdown):
- fua_always (coherent FUA reads), dir_epoch_adopt (handoff superset adopt), dir_coherent_modify (disk-compare invalidate), dir_force_evict (clean-block evict), inode_mht_ms 0/300/2000.
- sess13 NEW code (build D7F1FC0B, param dir_release_invalidate, DEFAULT 0, NON-REGRESSING — no shutdown):
  1. mxfs_dir_release_invalidate_data_blocks (post-fence clean-block XBF_DONE clear) — INERT (fired ~0-4x).
  2. **xfs_buf_stale publish-and-discard AFTER each dir-block xfs_bwrite in mxfs_dir_flush_data_blocks** (the PROVEN sess99 bnobt/cntbt primitive applied to dir blocks): forces every RELEASED dir block out of cache so the next acquire cold-reads. STILL 399/400. AIL-safe, no corruption.

### DECISIVE INFERENCE
Forcing coherent reads everywhere + no buffer surviving a handoff does NOT recover the lost dirent ⇒ the entry's BYTES are durably OVERWRITTEN on the LUN by another node's dirent at the SAME (daddr, offset). No read-side/buffer fix can ever recover a durably double-written slot. The fix MUST prevent the double-PLACEMENT at write/addname time. Two remaining candidate roots:
1. **True TCP double-grant**: two nodes momentarily both hold dir-EX under the 2nd-wave (.md5) burst → both addname the same block from bases lacking each other's entry → same free offset → one durably clobbered. mxfs_v5_dlm_inode_held is a NO-OP on TCP (sess49) so this CANNOT be detected/prevented on the fast path. NEXT: capture a cross-node EX grant/release timeline for the lost entry's block (P106-EXGRANT/EXREL, lightest instr) to CONFIRM/REFUTE concurrent EX. If confirmed → fix the TCP DLM grant/BAST handshake to be synchronous demote-before-grant (sess49 direction) in dlm/dlm.c (promote_waiters / process_remote_request must not grant EX until the prior holder ACKs release).
2. **Peer-write-not-on-platter at FUA-read**: A commits entry to LIO write-back cache; if A's block is not forced to platter before B's FUA read (despite the sess97 fence + H26 blkdev_issue_flush at release), B FUA-reads the platter missing A's add → collision. Verify the release H26 blkdev_issue_flush truly persists A's specific dir block before A's release message reaches the DLM master (ordering: bwrite→blkdev_flush→unlock vs grant-to-B).

### Builds: D7F1FC0B (publish-and-discard, off by default) supersedes 3091C841 supersedes 40AC2A0C. All behave identically by default. Winning config still 399/400. Criterion NOT met. See [[sess13run-MHT-invariant-residual-leading-hypo-LIO-writeback-vs-FUA-platter-revert]] [[sess49-residual-tcp-doublegrant-dir-resurrection-complete-diagnosis]].</body>
</invoke>
