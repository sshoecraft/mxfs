---
name: sess72_lessons
description: sess72 — FIXED & PROVEN Face A inode-reuse type-confusion (stale i_fop after in-place reload). Remaining = Face B dir-block lost-update.
metadata: 
  node_type: memory
  type: project
  originSessionId: 160f3570-152b-491c-bd0f-3341f846edb0
---

# sess72 (2026-06-04) — Face A FIXED & PROVEN; Face B now sole rename_visibility failure

Build `8B1A4AD61C2D29EC5B5D0DB` (deployed test1-4, KEEP). Criteria PASS=10 FAIL=2
(cache_coherency, rsync_paired). Marker NOT written.

## ✅ FACE A FIXED (`cat node1_after_1: Is a directory`) — RULE 4 step 2b complete

**Decisive proof** (instr build 51A6A9DC, added `ip=%px` + `fop_dir=%d` to P-EVICT-RESULT and
`ip=%px` to P-DIROPEN): ONE in-core inode `ip=ffff8e0a99f7cd80` for ino=131 showed
`final_mode=0100644(REG) inew=0 fop_dir=1` at P-EVICT-RESULT, and P-DIROPEN fired for the SAME
pointer at mode=REG. So it is a single inode whose `i_mode`=REG but `i_fop`==`xfs_dir_file_operations`.
`cat` opens → `xfs_dir_open` → read → `generic_read_dir` → **-EISDIR**.

**Root**: an in-place dinode reload that flips S_IFMT (peer freed inode N as a dir, reused N as a
regular file) updates `i_mode` in `xfs_inode_from_disk` but NEVER re-wires `i_op`/`i_fop`/`a_ops`.
`xfs_setup_iops` runs only on the XFS_INEW iget path (`xfs_iget` ~L1342 `xfs_setup_existing_inode`);
the in-place reload returns a live cache-HIT (`inew=0`) so it never fires. This is why sess55-71's
inode-layer chase (eviction repairs i_mode correctly) never fixed it — the residue was the vtable.

**Fix** (xfs/xfs_mxfs_dlm.c `mxfs_dlm_reload_inode` ~L1420): capture `old_ifmt = i_mode & S_IFMT`
before `xfs_inode_from_disk`; if S_IFMT changed afterward, call `xfs_setup_iops(ip)` (declared in
xfs/xfs_iops.h; pure pointer writes for REG/DIR branches, no I/O/alloc/lock — safe in reload ctx).
Logs `P-RELOAD-IOPS-REWIRE` (KEEP detector).

**Validated**: repro `tests/catch_rename_fail.sh` went FAIL@iter2 → 8 consecutive PASS;
P-RELOAD-IOPS-REWIRE fired (test2×1 test3×2); ZERO "Is a directory" across the whole run.

## ⛔ REMAINING = FACE B (concurrent dir-block LOST-UPDATE) — sess69's other face

Now the sole rename_visibility failure (was masked behind more-frequent Face A); hit ~1/9 iters.
Ground truth (iter 9): node3 `mv: cannot stat node3_before_4..8: No such file or directory` — a
CONTIGUOUS SUFFIX of node3's OWN Phase-1 entries vanished from the shared dir (before_1..3 survive),
missing on ALL 4 nodes incl node3. A peer modified+wrote the SHARED dir block from a STALE cached
copy (had early entries only) → clobbered node3's committed dirents. No corruption/shutdown/eviction.

NEXT (RULE 4): sess69 H-DIR — on a FAST dir-inode re-grant after a peer modified the shared dir,
`i_dlm_dir_gen` is NOT bumped (it bumps only on the SLOW-path acquire, xfs_mxfs_dlm.c L2123-2124),
so stale cached dir DATA blocks are served without FUA re-read; the node modifies+writes a stale
block → lost-update. Consumer hook = xfs_da_read_buf (xfs/libxfs/xfs_da_btree.c ~L2894-2968:
invalidate when `b_mxfs_dir_gen != i_dlm_dir_gen`, skips dirty/in_ail/pinned). Instrument the
dir-inode acquire/re-grant (does the gen bump on the write path's acquire?) and the dir-block modify
(is `b_mxfs_dir_gen == i_dlm_dir_gen` at the clobbering write?). Repro: catch_rename_fail.sh 15.
See [[sess69_lessons.md]] (Face B framing), [[sess55_lessons.md]] (Gemini design).
