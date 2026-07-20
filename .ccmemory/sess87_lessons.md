---
name: sess87_lessons
description: sess87 (ccloop) — reload-shutdown FIXED via verified-dinode-snapshot (build 77C90663); PROVEN deep root = inode DOUBLE-ALLOCATION (same-gen dir+reg type confusion)
metadata:
  node_type: memory
  type: project
  originSessionId: 7ba77e77-ab4e-4293-96a5-399031997af5
---

# sess87 (2026-06-04, ccloop run 29df431e)

## Build state
- Current build = `77C90663` (snapshot fix), deployed test1-4, reset OK, 4 nodes mounted.
- Prior heads: sess86 `5D6A63D2` (d_revalidate rename fix). Intermediate `183DB004` (early-verify attempt, superseded).

## WIN 1: reload-shutdown FIXED (snapshot fix, KEEP)
**ROOT (PROVEN, RULE-4):** cache_coherency shutdown during unlink_visibility had a
NEW signature this session: `Corruption of in-memory data ... xfs_iflush_cluster`
(xfs/xfs_inode.c:3625) + `Metadata corruption at xfs_dir2_sf_verify ... data fork`
on the actively-modified dir inode 135. Traced to `mxfs_dlm_reload_inode`
(xfs_mxfs_dlm.c): it calls `xfs_idestroy_fork(&ip->i_df)` BEFORE
`xfs_inode_from_disk()` validates (from_disk runs xfs_dinode_verify FIRST). The
`down_write_trylock` spin loop (cond_resched, up to 1000 iters) opens a WIDE window
in which a concurrent re-read of the SHARED inode-cluster buffer mutates `dip`'s
bytes between any check and from_disk → from_disk verify fails AFTER the fork was
destroyed → in-core inode HALF-BUILT (if_data=NULL, dir mode) → next xfsaild flush
hits sf_verify → SHUTDOWN. Seeds a propagation cycle (bad in-core → flushed to disk
w/ valid CRC → peers reload bad image). sess86 d_revalidate reload-storm EXPOSES it.

**FIX (build 77C90663, xfs_mxfs_dlm.c mxfs_dlm_reload_inode, KEEP):** after acquiring
i_lock EXCLUSIVE (spin window closed), take a STABLE private snapshot
`snap = kmalloc(sb_inodesize); memcpy(snap, dip, sb_inodesize)`, verify the SNAPSHOT
via `xfs_dinode_verify(mp, ino, snap)`, retry torn reads (re-stale + re-imap_to_bp +
re-copy) up to 8×, and BAIL (keep authoritative in-core, leave i_dlm_stale set) on
persistent failure. Set `dip = snap` so P-SFDIR-REVERT/TYPEFLIP/from_disk all use the
immutable copy. kfree after from_disk. Detectors: RELOAD-VERIFY-BAIL,
"RELOAD-VERIFY recovered torn read". An EARLY pre-spin verify (build 183DB004) did
NOT work — from_disk still failed because the mutation happens DURING the spin.
**RESULT:** shutdowns dropped (test1 1, others 0 vs many) — but criterion still FAILs.

## WIN 2 (the real blocker): PROVEN deep root = INODE DOUBLE-ALLOCATION
After the snapshot fix removed the shutdown, cache_coherency went passed=0 failed=4
because cross_visibility HANGS: `/mnt/shared/.mxfs_barriers` (ino=4194435) is a
REGULAR FILE on ALL 4 nodes → every `mkdir -p .mxfs_barriers/<name>` fails →
barrier_wait times out 120s × every barrier → all 4 sub-tests fail.

**Decisive dmesg (all nodes):** `P-RELOAD-TYPEFLIP ino=4194435 incore_mode=040755(dir)
disk_mode=0100644(reg) incore_gen=411917721 disk_gen=411917721`. **SAME generation,
different type** = inode NUMBER allocated twice without an intervening free (free+realloc
bumps di_gen; identical gen rules that out). ino 4194435 = AG 2, agino 131 (inodes/AG =
2097152 = 0x200000; geometry agcount=20, blocksize=4096, isize=512, inopblock=8). The
dir `.mxfs_barriers` and a colliding REG file BOTH got ino 4194435; the reg write won
on disk → the dir's dirent now resolves to a reg-file dinode.

**Node-affine alloc (sess45, xfs_ialloc.c xfs_dialloc_pick_ag):** BOTH dirs AND reg
files use `m_mxfs_node_slot % m_maxagi`. test1=slot0→AG0 … test4=slot3→AG3 (P10-INSTR
slot=0 on test1). So AG2 is test3's affine AG → BOTH the dir and the reg in AG2 should
be test3's → looks like a SINGLE-NODE double-alloc within its own AG2 (surprising under
continuous AG-EX), UNLESS (a) a peer's affine AG filled and wrapped into AG2
(for_each_perag_wrap_at), or (b) slot→AG collision. NOT yet disambiguated.

**This is the long-standing bug** (sess44-52 "AG/inode double-alloc", bnobt double-free
family). Prior REFUTED: concurrent-EX (P88 ex_pop=1/ex_nslots=1), release-before-drain
(ag_held=1 durable). Prior localized: read-side "gen-fresh-but-content-stale" buffer.
Fresh-CAW acquire DOES bump pag_dlm_meta_gen + mxfs_dlm_invalidate_ag_meta (stales
AGI/AGF/inobt/finobt/AGFL). Cached fast-path (pag_dlm_cached) skips invalidation
(justified: still hold EX on disk, no peer touched).

## NEXT SESSION (RULE 4 → likely RULE 5)
1. DECISIVE INSTRUMENTATION (was mid-writing): in `xfs_dialloc` right before
   `*new_ino = ino;` (xfs_ialloc.c ~L2168), FUA-read the on-disk dinode for `ino` and
   if `di_mode != 0` log DOUBLE-ALLOC with node_slot, ino, agno, agino, requested mode,
   on-disk di_mode/di_gen, AG-DLM held/cached/gen. Reuse the FUA mechanism from
   `mxfs_inode_disk_di_size` (xfs_mxfs_dlm.c: SCSI READ(16) FUA, di_mode at dinode
   off 0x02, magic 0x494e at off 0, lba = im_blkno + bt_sector_offset). This proves
   single-vs-cross-node and whether finobt showed a live inode as free.
2. Determine: single-node (test3 reallocating own AG2 inode → its own finobt stale, or
   alloc-after-free without gen bump) vs cross-node (a peer allocated in AG2 via wrap).
3. RULE 5: this class (AG-meta read coherency) has failed ~10 sessions — consult Gemini
   with the clean same-gen dir/reg evidence + node-affine-distinct-AG fact once the
   alloc mechanism is nailed. Omit max_tokens.

## INFRA
- test3 wedged (ssh dead, libvirt "running") after corruption shutdown → needs
  `virsh destroy test3; sleep 5; virsh start test3` (LIBVIRT_DEFAULT_URI=qemu:///system),
  then re-mount NFS: `mount -t nfs 192.168.1.4:/src /src` (for .ko) +
  `mount -t nfs 192.168.120.1:/src/mxfs /mnt/mxfs-src`. reset4.sh hangs if a node is
  wedged — hard-recover first.
- Criterion takes ~15min (longer with shutdowns→120s barrier timeouts). Run bg.
- P88-INSTR bnobt-WRITE-low-numrecs is NOISE (disk_differs=1 expected at writeback).
