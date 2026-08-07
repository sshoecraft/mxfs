---
name: ccloop-c7ee71c6-sess32-dir-data-certificate-scoping
description: Dir-DATA certificate scoping: m_mxfs_dir_wr_inflight already fences SUBMITTED dir-block writes at release (sess40); the gap is committed-but-never-SU…
metadata:
  type: project
---

# sess32 — dir-DATA certificate: what exists vs the real gap

## Already in the tree (do not rebuild)
- `m_mxfs_dir_wr_inflight` (xfs_mount.h, sess40 GPT writeback-completion-
  barrier): counts dir DATA/leaf write bios SUBMITTED but not yet completed;
  ++ at xfs_buf_submit_bio (dir-metadata, multi-node), -- at __xfs_buf_ioend;
  **the dir EX release fence already waits for 0 before the DLM unlock** —
  so a prior-tenure stale dir-block bio cannot land after the next holder's
  cold read (the dir_reuse readdir=799 root).
- `mxfs_dir_flush_data_blocks` / `mxfs_dir_data_durable` iterate the fork and
  flush/verify dir blocks in the release pipeline; `__mxfs_dlm_dir_inode_
  durable` covers the dinode cluster (all formats, dirty-gated).

## The actual remaining gap (buffer-side analog of cls=UNCOPIED)
A dir-block change COMMITTED (in CIL/AIL) but never SUBMITTED by release
time: the inflight counter is 0 (nothing submitted), the flush passes may
miss it (pinned/CIL-resident, or the scan races a relog — same families as
the inode-core leak P220 measured), and the release proceeds. The per-tenure
obligation registry (GPT sess32 ruling §3) targets exactly this: register
{buffer, tenure generation} when a protected dir buffer is LOGGED, retire at
its home iodone, require the generation's count==0 (after the final cache
flush) before unlock — mirroring the inode-core pending/durable ledger at
buffer granularity. Ownership rule: parent-dir blocks close at the PARENT's
release boundary (a child-core predicate cannot certify them).

## Implementation sketch for session 15+
1. Registry: per-inode (the dir ip) counter pair analogous to
   pub_pending/durable — `dir_buf_pending_seq` ++ at xfs_trans_log_buf on a
   dir-owned buffer (attribution: bp->b_mxfs owner or the dirty-range's
   owner inode — needs a cheap owner tag on dir buffers; check what
   watch_ino/P-DIRWR use for attribution), `dir_buf_durable_seq` promoted at
   that buffer's write completion (the __xfs_buf_ioend path already
   distinguishes dir-metadata writes for the inflight counter — same hook).
2. Extend mxfs_relbar_close_or_defer's predicate to
   (pub_pending!=pub_durable || dir_buf_pending!=dir_buf_durable) for dirs;
   the close pass adds mxfs_dir_flush_data_blocks before re-check.
3. A/B via the same relbar_enforce knob + new counters in the P220 dump.
