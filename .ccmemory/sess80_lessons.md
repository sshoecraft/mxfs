---
name: sess80_lessons
description: "sess80 (ccloop, 2026-06-04) — generalized HB evict-ring to DIR_MODIFY (build 71FD67B0) to fix shared-dir reader-staleness + write-side dir-block lost-update (rename/unlink visibility); bnobt double-free SHUTDOWN still open, Gemini says move AG versioning to a shared on-disk AGF epoch (local pag_dlm_meta_gen stuck at 1)."
metadata:
  node_type: memory
  type: project
  originSessionId: 760b6ece-53ba-47d0-831d-f56a934ad725
---

# sess80 lessons (ccloop run 29df431e, 2026-06-04)

## Authoritative cache_coherency failure profile (build DA1CF4D8, instr=0)
Ran the REAL criterion (`tests/criteria/cache_coherency.sh`, writes an unbuffered
mktemp log): cross_visibility **PASS**; rename_visibility **FAIL** (all 4 nodes
rc=1); unlink_visibility **FAIL** + triggers the **bnobt double-free SHUTDOWN**
that unmounts node1 → cross_write_read **FAIL** ("Node 1 not mounted"). So 3/4 fail.

**RENAME root nailed:** the failing op is `mv: cannot stat node3_before_9: No such
file` — node3 cannot stat its OWN just-created file. = WRITE-side dir-block
LOST-UPDATE: all 4 nodes add dirents to the SAME shared dir concurrently; a peer
(NL reader, never BAST'd) RMWs off a STALE cached dir DATA block missing node3's
entries → writes back a block without node3's dirents → node3's files vanish. The
barrier itself (`find` for peer marker files in a shared dir) has the same
dependency. cross_visibility passes only because its shared dir has 4 entries =
SHORTFORM (carried in the inode → inode coherency works); rename/unlink grow the
dir to BLOCK format → separate dir blocks → the staleness bites.

## FIX landed (build 71FD67B0, deployed — VERIFIED KEEP)
**RESULT: cache_coherency passed=2 failed=2 (was 1/3). rename_visibility now PASSES**
(the DIR_MODIFY fix worked); cross_write_read now RUNS (no shutdown-unmount cascade
this run), failing only on its own di_size=0 empty read (1-2/6). Still failing:
unlink_visibility (1→23 assert fails/~121, ~19s = phantom readdir, stale dir block
still lists deleted names — evict-ring should cover it; check EVICT-RING-DIRMOD fired
for the unlink dir + that INODE_FREE and DIR_MODIFY ring entries coexist on the unlink
path) and cross_write_read di_size=0 (READER reg-file content staleness, separate).

Generalized the heartbeat evict-ring (was inode-FREE only, sess55/56) to carry
**DIR_MODIFY** entries (Gemini Priority-2):
- Wire: `struct mxfs_evict_entry` `pad`→`type` (0=INODE_FREE backward-compatible,
  1=DIR_MODIFY). Threaded `type` through `mxfs_disklock_note_freed(+type)` and
  `evict_cb(+type)` (disklock.h/.c, v5_mount.c/.h, xfs_mxfs_dlm.h).
- Producer: `xfs_dir_createname/removename/replace` (xfs/libxfs/xfs_dir2.c) call
  `mxfs_dlm_note_dir_modified(dp->i_mount, dp->i_ino)` on success (multi-node only).
- Consumer: `mxfs_dlm_evict_inode_cb` (xfs_mxfs_dlm.c ~L3706) branches on type; for
  DIR_MODIFY, radix-lookup the dir inode, if live `S_ISDIR && i_dlm_dir_gen!=0` →
  `i_dlm_dir_gen++` (runs in HB monitor thread, spinlocks only). The EXISTING
  `xfs_da_read_buf` invalidation then FUA-re-reads stale-but-CLEAN cached dir blocks
  on the peer's next readdir (only CLEAN — our own dirty/in_ail blocks preserved).
- Dedup in note_freed: skip if last staged entry == same (ino,type) → 20 renames of
  one dir = 1 ring entry (ring depth 28). Detector: EVICT-RING-DIRMOD (ratelimited).
- KEY: this fixes BOTH reader-visibility AND the write-side lost-update (a writer
  re-reads fresh before its RMW). Durability of the modifier's blocks is covered by
  the existing dir-data-durability drain on each DLM-EX handoff (all 4 nodes modify
  the shared dir in turn). The pin-skip wall (sess75) is a WRITER problem; this
  invalidates a READER's CLEAN cached block → safe.

## bnobt double-free SHUTDOWN — still open; Gemini RULE-5 verdict
Decisive evidence (build DA1CF4D8): P47 verdict=DISK-LIVE-same-gen=A-lost-removal (a
LIVE reg file's block-free lost from bnobt); P28 disk_differs=0 at shutdown (clobber
DURABLE on disk = WRITE-side); P88 at write-submit = in-core bnobt PRISTINE
(rec0=[9,260906]) flushed OVER allocated disk (rec0=[9,7]), buf_gen=1 pag_gen=1
in_ail=1. **pag_dlm_meta_gen STUCK at 1** on all nodes ⇒ the AG-meta local-gen
coherency is effectively disabled (stale buffer marked fresh, never re-read, RMW'd,
flushed = clobber). **P75 REL-LEFT-DIRTY = ZERO** ⇒ the BAST release path is clean
(refutes "release drops lock w/ in_ail buf" for THAT path); but 3 OTHER release paths
lack the meta-drain/P75 check (deferred iodone→release_work_fn = only blkdev_flush;
unmount; fallback).

**Gemini (omit max_tokens, full reply in transcript):** the local-acquire-counter gen
scheme is NOT salvageable. Move AG (and dir) versioning to a **SHARED ON-DISK EPOCH**
stamped in the AGF on every AG-modifying commit, FUA-compared on every cross-node-fresh
acquire; if disk epoch > local → evict ALL cached AG bufs. Also: guarantee
destage+AIL-clearance before unlock on ALL release paths, then DROP the "in_ail =
this-node-ahead, preserve" rule. NEXT: implement on-disk AGF epoch OR first prove WHY
pag_gen is stuck at 1 (is the AG held continuously/nested so the staleness is
SELF-inflicted via a FUA read-vs-destage race on the node's OWN buffer — sess44 comment
flagged exactly this: FUA READ(16) reads the PLATTER, bypassing the SCST write cache, so
an un-destaged own-write returns stale pristine). See [[sess79_lessons]].

## Mechanics confirmed
- ssh wrapper: `tools/mxfs_sshpass.sh <node> /tmp/.mxfs_pass "<cmd>"` (pass file survived).
  Loaded srcversion: `cat /sys/module/mxfs/srcversion`.
- run_tests.sh / criterion stdout is BUFFERED when backgrounded → harvest dmesg directly
  for detector evidence (the real signal); the criterion's mktemp log has per-subtest asserts.
- Build `make modules` then reset4 deploys (nodes NFS-mount /src/mxfs/mxfs.ko).
