---
name: sess55_lessons
description: sess55 — Gemini 3-part design for the NL-cached inode-reuse coherency blocker (CAW_EVICT_RING + VFS staleness trap + dir-format re-read on DLM grant). RULE5 max_tokens fix.
metadata: 
  node_type: memory
  type: project
  originSessionId: 5e33333b-079d-40c5-aeb4-3514eb065500
---

# sess55 (2026-06-03) — Gemini architectural design saved; RULE 5 amended

## Two deliverables landed this session
1. **`mcp__ask_gemini__query` MUST omit `max_tokens`.** Setting it caps the TOTAL
   budget including Gemini's internal thoughts tokens (10k+ on hard questions) →
   the answer truncates mid-design, wasting the call. Omit it → server uses full
   default → `finish_reason: STOP`, complete answer (sess55: 14.5k tok whole).
   Codified into CLAUDE.md RULE 5.
2. **Saved Gemini's 3-part fix design** for the NL-cached inode-reuse coherency
   blocker (defeated sess40/48/52/53/54) to `/src/mxfs/notes/sess55_gemini_design.md`
   (full detail there; survives reboot per RULE 3).

## The design (summary — full in notes/sess55_gemini_design.md)
Root (sess54, proven): VFS cache served at NL (no DLM grant); CAW poll only scans
slots WE hold → peer free/realloc/dir-modify never BASTs us → stale served.
Invariant: VFS cache must project DLM state (GFS2 glock model).

- **Part 1 — CAW_EVICT_RING** (core fix, Failure A = inode free+reuse type
  confusion): on-disk ring of `{ino,gen}`+`head_seq` in CAW LUN metadata.
  Producer = `xfs_ifree()` appends to in-mem staging, flushed by existing CAW
  heartbeat (zero fast-path I/O). Consumer = `caw_poll_thread()` diffs head_seq,
  lockless `radix_tree_lookup` on `pag_ici_root`; if incore at NL →
  `set_bit(XFS_ISTALE_CAW)` + queue BACKGROUND workqueue `d_prune_aliases` +
  `xfs_irele` (OUTSIDE xfs_iget/ILOCK = avoids wedge). Ring-wrap → bg sweep.
- **Part 2 — VFS staleness trap**: move detection OUT of xfs_iget INTO
  `xfs_vn_lookup()` (hold parent i_rwsem, NOT child ILOCK). Check XFS_ISTALE_CAW
  OR ftype mismatch → irele + d_prune_aliases + bounded retry. No DLM/ILOCK.
- **Part 3 — Failure B** (file invisible to own creator = concurrent
  shortform→block dir conversion lost-update): dir mods don't free inode → never
  hit ring. Fix at DLM grant-completion callback on NL→PR/NL→EX: synchronous
  inode-cluster re-read (`xfs_iread_extents`/`xfs_trans_read_buf`) to refresh
  di_format/i_size BEFORE any txn takes ILOCK (safe — inside lock-acq state
  machine, before XFS ILOCKs).

## Implement order: Part 1 (highest leverage) → Part 2 → Part 3.
Code anchors: xfs_lookup evict `xfs/xfs_inode.c:701-738`; `mxfs_drevalidate`
`pal/linux/xfs_super.c:1786` (compares ino NUMBER only — misses same-number
reuse); `mxfs_dlm_reload_inode` `xfs/xfs_mxfs_dlm.c:1097`; CAW poll `dlm/dlm_caw.c`
~L1446; producer `xfs_ifree()`.

Repro (instr=0, 19s): `MXFS_TESTS_DIR=/src/mxfs/tests ./tests/run_tests.sh --nodes 4
--phase cluster --test test_cross_visibility --pass-file /tmp/.mxfs_pass --device
/dev/sda --mount-point /mnt/shared`. Deploy: `MKFS_OPTS=-f bash tests/reset4.sh 4`.
Build under test: srcversion `C2D30DB0A37A12264B76A35`. See [[sess54_lessons]].
