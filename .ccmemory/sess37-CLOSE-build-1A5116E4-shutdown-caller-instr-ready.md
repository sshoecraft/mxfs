---
name: sess37-CLOSE-build-1A5116E4-shutdown-caller-instr-ready
description: sess37 CLOSE: build 1A5116E4 = B5 toctou fix (inert for dir_reuse, doesn't fire) + block-297 free caller instr (P15 caller=%pS). Shutdown still flaky…
metadata:
  type: project
---

## sess37 CLOSE — final state for dir_reuse_coherency 2/tcp

**Build 1A5116E4** = A695EC5C + B5 inactivation TOCTOU fix (xfs_inode.c ~2960, drop !local_unlink) +
P15-INSTR free-fail CALLER instrumentation (xfs_alloc.c ~2260, `caller=%pS caller2=%pS comm=`).
Criterion NOT met. Marker NOT written.

### B5 fix is INERT for dir_reuse (does NOT fire):
Across 5 runs with B5, `INACT-SKIP-STALE = 0` every time (B5 never triggered: the EX acquire for the
inactivating inode always succeeded, so `!mxfs_inact_dlm_locked` was never true on the failing path).
A shutdown STILL occurred (run3: readdir=0 ×39, same P47-INACT block 297 inode 2099107 disk_di_mode=0
disk_gen=incore+1) with B5 NOT firing and `will_skip=1 count=0` — so the B5 path is NOT the actual
shutdown culprit. **The inact_ino=2099107 GLOBAL (mxfs_dbg_inactive_ino) is likely STALE** — the
block-297 free almost certainly comes from a DIFFERENT caller (a dir-block free during rm-rf, or a
bmap/bunmapi path), not 2099107's file inactivation. KEEP B5 as a documented candidate (sound
principle, inert here, low risk) OR revert for a clean baseline — next session's call after full-suite
validation. The decisive unknown is the block-297 free CALLER (now instrumented).

### KEY INFRA LESSON (cost me several confusing analyses):
The node dmesg ring PERSISTS across runs (mkfs/remount does NOT clear it; a shutdown leaves the ring
full of the old corruption). `drc_cap2.sh` streams the WHOLE ring, so `grep` over _cap/*.log picks up
PRE-RUN RESIDUE → false "shutdown" / stale P47-INACT readings. FIX: `dmesg -C` on each node OR `virsh
-c qemu:///system destroy+start test1 test2` (clean reboot, ~45s) BEFORE a diagnostic run. After a
shutdown the nodes WEDGE (rmmod fails, stuck FS thread) → virsh reset is required (umount -l + rmmod
does NOT recover a shut-down FS). virsh names: test1=dom184, test2=dom185 on qemu:///system.

### NEXT SESSION — decisive step is ready:
1. `virsh destroy+start test1 test2` (clean ring), then `MXFS_EXTRA_MODARGS='inode_mht_ms=300' bash
   tests/drc_cap2.sh` REPEATEDLY until a shutdown hits (~1-in-3..6 flaky). grep `FREE-AG-EXTENT-FAIL.*
   caller=` → the caller of xfs_free_ag_extent for block 297 = the path doing the stale double-FREE.
   That pinpoints whether it's dir-inode bmap (rm-rf dir shrink) or a file inode → the fix locus.
2. The dir-block faces (data-loss readdir<200, leaf-hash lookup_fail node1_f47-50.md5) are the more
   FREQUENT failures and need separate fixes — see
   [[sess37-B5-toctou-fix-landed-dir-faces-remain]] (data-loss: dir-block double-alloc candidate, P55
   only checks inode chunks; leaf-hash: evict keeps undurable stale leaf P21S, needs merge but
   dir_leaf_rebuild=1 SHUTS DOWN via data-over-inode double-alloc).
3. All faces share the stale-state-survives-REUSE root ([[sess37-bnobt-is-doubleFREE-stale-bmap-not-doublealloc]]).

### sess37 net: refuted sess31-36 P31E "root" (benign); refuted allocator double-alloc (confirmed
sess55); refuted stale-bmap-at-modify, evict-keep-stale-DATA, read-hook-retry; PROVED the shutdown is
a stale double-FREE (not double-alloc); landed B5 (inert here); instrumented the free caller. No
reliable PASS achieved. Build 1A5116E4.
