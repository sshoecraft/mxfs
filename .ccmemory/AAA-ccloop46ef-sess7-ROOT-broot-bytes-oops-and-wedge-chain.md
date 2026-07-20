---
name: AAA-ccloop46ef-sess7-ROOT-broot-bytes-oops-and-wedge-chain
description: sess7 ROOT PROVEN: dir_reuse@16 wedge = create oops (broot=NULL bytes-stale nop-path) kills dd in place holding dir locks; fixes A+B in v0.10.31 buil…
metadata:
  type: project
---

# sess7 (ccloop 46efd8b6) — dir_reuse@16 root cause PROVEN + fixed (v0.10.31, srcversion 70EA513FC2DCF5156CD1F6C)

## The full failure chain (all steps evidence-backed, live-debugged on test9)
1. Dir ino=131 (shared test dir) converts extents→btree during create storm (`if_broot` alloc'd, `if_broot_bytes`=S1) — fmt=3 seen t=79.2s.
2. An mxfs reload/adopt later destroys+rebuilds the LIVE fork from an extents-format disk image: `xfs_idestroy_fork` frees `if_broot`, NULLs it, **but leaves `if_broot_bytes`=S1 stale** (upstream never re-reads it; mxfs live-reload does). Same class as the documented `if_data`/`if_bytes` landmine (xfs_mxfs_dlm.c:16305 comment).
3. Next extents→btree conversion (`xfs_bmap_extents_to_btree` → `xfs_bmap_broot_realloc(ip,fork,1)`): `new_size==old_size` **nop path returns NULL if_broot** → `xfs_bmbt_init_block` writes header at NULL+4 → **Oops 0002 kernel NULL write, RIP xfs_btree_init_block+0x36** (test9 t=213.6s, pid 1362 dd creating node9_f38; RBX=0, R13=xfs_inode addr).
4. The oops kills dd **in place** (no unwind): dir's VFS `i_rwsem` (write), `i_lock` (write), `i_dlm_ex_holders=1` leaked forever. Verified via /proc/kcore scan: both rwsems count=3 (WRITER|WAITERS), owner=dead-task slab addr (recycled to an unrelated kworker later).
5. Every subsequent dir op parks: O_CREAT opens on i_rwsem (top frame open_last_lookups+0x137, rwsem frames hidden — __sched filtered); non-create opens park in mxfs_dlm_ilock_begin (D). Node starves the CLUSTER: on-disk CAW slot h_ex=0x800 (test9=node_bit 11) frozen while waiters=0xc7c7 — the "SESS50-STARVE h_ex=800" from sess6 is a **bitmask**, NOT a clobbered counter (sess6's memory-clobber theory REFUTED).
6. P36-MHT-REARM dwork re-arms every ~8ms forever (ex=1 never drops), holds iget ref → unmount leaks inode ("Objects remaining on __kmem_cache_shutdown") → post-rmmod bio completions call into unloaded module text (netconsole `Oops: 0010 blk_done_softirq`) — the panic family. A release drain finally shut the FS down after 180s i_lock timeout (P132-ILOCK-TIMEOUT, pre-existing escape).

## Fixes in v0.10.31
- **Fix A (root)**: `xfs_idestroy_fork` (libxfs/xfs_inode_fork.c) now zeroes `if_broot_bytes`; plus `P80-BROOT-TORN` WARN-and-heal guard at `xfs_bmap_broot_realloc` entry (xfs_bmap_btree.c) for any other producer.
- **Fix B (containment)**: `i_dlm_dwork_strikes` (new u16 in xfs_inode) — dwork busy re-arms strike out at 2500 (~20s continuous busy): log P36-STRIKEOUT, drop iget ref, stop re-arming; bast_pending stays set (ilock_end/unpin refire or peer 1s-retries re-arm; strikes reset only on fresh episode = bast_pending 0→1 at 6 sites + quiescent + init). P36-MHT-REARM print now includes ex/pr/pin/mode/state/strikes.

## Live-debug toolkit built (REUSABLE, in sess7 scratchpad)
- `rdring.py` — reads mxfs_dlmtr ring + idx from /proc/kcore by kallsyms vaddr (ring floods in ~3s under BAST spam; watch_ino was 131 via test suite).
- `findino.py` — scans /proc/kcore direct-map for a given ino's xfs_inode (needle i_ino @+32, verify mode @+480, VFS i_ino @+816+80), dumps DLM counters + i_lock/i_rwsem count/owner + owner task comm/pid. Offsets extracted via gdb from mxfs.ko DWARF (xfs_inode: i_lock=168, vnode=816, mode=480, state=481, ex=528, pr=530, pin=532, bast_pending=464; inode: i_rwsem=176; rwsem: owner=8; task: comm=3032, pid=2488). **This found the smoking gun in one shot.**
- Dump trigger: lookup of `.mxfs_dirdump1` in ANY healthy dir dumps global dlmtr ring (dead after FS shutdown — xfs_is_shutdown check precedes it in xfs_lookup).

## Non-fatal residue noted
- `xfs_assert_ilocked` WARN t=79.2 (rwsem.h:85, pid dd, during reload family) — lock-discipline smell in reload path, not the killer; revisit if it recurs.
- P15-REL-ABORT/P79-STALEBAST-CLEAR transitions healthy.

## State at memory-write
- Run launched: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS=caw_fair_handoff=1 timeout 2900 ./run.sh 16 caw dir_reuse_coherency` (log: sess7 scratchpad `run31-dirreuse16.log`), prep power-cycling the wedged cluster.
- Remaining agenda after this run: (c) rmmod in-flight-bio safety if panics persist; then 16 board complete → 32-node (cache_coherency 31/32 uv ghost — dirent-analogue skip `|= XBF_DONE` resurrect suspect at pal/linux/xfs_buf.c ~4112-4128) → full 1/2/4/8/16/32 ladder.
