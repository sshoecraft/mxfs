---
name: sess33-run14d-zsl-relflush-stale-write-root
description: sess33(14d): zsl FIXED release-flush stale-write war (!XBF_DONE bug, 6AB6018C KEEP). Remaining ~80 quiet loss = ORPHANED dir block (extent-replacemen…
metadata:
  type: project
---

# sess33 (ccloop 14d31183) — zero_silent_loss: one root FIXED, next root PROVEN

## Status at handoff
Build `6AB6018CB94AD2646492DBF` (KEEP — carries FF401F22 fence-gate + this session's stale-write fix). zsl still FAILs but losses 261→~80-109/iter and the cross-node dir-block stale-write war is GONE (crc lineage: 27 flagged → 0 genuine). 17/18 criteria otherwise PASS.

## FIXED this session (PROVEN, keep)
**Release-flush stale-write war.** `mxfs_dir_flush_data_blocks` (needs_flush) and `mxfs_dir_data_durable` (bad) and `mxfs_dir_bmbt_scan` (needs) all treated `!(b_flags & XBF_DONE)` as "not yet landed". But a clean !DONE buffer there is one the EVICTION FENCE INVALIDATED (cleared XBF_DONE so next read re-fetches the peer's image). The release path then xfs_bwrote the invalidated STALE content over the peer's newer durable block. Proof: P-DIRRD/P-DIRWR crc lineage — 27 flagged stale writes, all `done=0 dirty=0 in_ail=0 pin=0 comm=kworker/u*` (BAST release ctx), wcrc == already-superseded image, incl. test10↔test7 verbatim re-push ping-pong. Fix: drop `!XBF_DONE` from all three disjunctions (anything genuinely unlanded is dirty/in-AIL/pinned/delwri). Also fixed en route: the P133-DIRINO-REVERT (stale dinode xfsaild write, test11 8192-over-12288 with stack) **stopped firing entirely** after this fix (0 in 3 runs).

## REMAINING quiet-loss root (PROVEN by raw-disk forensics, NOT yet fixed)
~80 dirents/iter vanish with ZERO stale block writes, ZERO dinode revert/READSTALE, monotone dinode completion timeline. Forensics on the intact post-run FS (run 13:01Z, missing=node10_dir28 et al):
- `grep -abo node10_dir28 /dev/sda` → hit at abs 10787847845 inside a VALID XDD3 dir data block (~daddr 20873324).
- Parsed the on-disk BTREE bmbt of ino 131 (`scripts/sess33_bmbt_dump.py /dev/sda 131`, works on-node): 34 extents, 115 data blocks + leafs. **daddr 20873324 is NOT in the map.**
→ A concurrently-growing node REPLACED the dir-offset mapping: two nodes allocated different fsblocks for the same dir offset (stale extent/leaf view during grow), the loser's block — full of committed dirents — got orphaned. Size/nx stay monotone so all write-side revert probes are blind to it. This is the extent-REPLACEMENT double-map, sibling of the old double-alloc family.
- The 12:51Z storm run's `xfs_dabuf_map HOLE` internal error (xfs_da_btree.c:2765 in xfs_create) + cluster EUCLEAN is the same mechanism seen from the other side (mapping inconsistency), triggered after a `P131-WAITLONG 30.5s` EX starvation.

## NEXT (in order)
1. Instrument the GROW path: log (startoff→fsb) on every dir bmap allocation (xfs_bmap_btalloc/xfs_da_grow_inode for ino-dir forks, multi-node) + on reload log the extent LIST diff, to catch two nodes mapping the same startoff to different fsb. Correlate with P106-EXGRANT tenure boundaries — suspect the grower's in-core extent tree is one behind despite fresh dinode (BTREE: dinode core reloaded but **iext/bmbt children may be re-read from stale cached bmbt buffers** — check whether reload invalidates cached bmbt blocks for BTREE dirs before xfs_iread_extents; the eager evict only handles DATA blocks; `mxfs_dir_bmbt_scan` exists but reload path may not call any bmbt invalidation).
2. Likely fix shape: at reload/acquire of a BTREE-format dir, stale+invalidate cached xfs_bmbt_buf_ops buffers owned by the dir (bounded — use the existing owner-scan with MXFS_BMBT_SCAN_MAX, NOT the O(cache) walk) so xfs_iread_extents re-reads the peer's bmbt children; then re-run zsl.
3. Watch SESS50-STARVE (P131-WAITLONG 30s seen once) — starvation precedes the storm mode.
4. Then iters=3, then verify_ship.sh end-to-end.

## Tools/probes added this session (all in tree)
- `dirwr` param SPLIT: 1 = low-rate write-side probes only (P133/P134 + new P136); 2 = also per-IO P-DIRRD/P-DIRWR crc traces. dirwr=1 reproduces the bug; old full-trace dirwr=1 sometimes masked it.
- `P136-DIRINO-WRDONE` (pal/linux/xfs_buf.c __xfs_buf_ioend write branch): dir-dinode write COMPLETION timeline (completion-order TOCTOU detector).
- `scripts/sess33_bmbt_dump.py <dev> <ino>`: on-disk extent-map dumper (envelope-aware, EXTENTS+BTREE). Note: its "nblocks" field prints extsize (offset bug, harmless).
- crc lineage analysis recipe: collect P-DIRRD/P-DIRWR per node since UTC start, merge by realns, flag W where node's last R crc != last W crc for the daddr. SAME-node flags are false positives (consecutive same-node writes accumulate in-core).

## Env notes
- Storm runs leave D-state umounts pinning the module; teardown then INFRA-fails. Power-cycle ALL nodes (`virsh -c qemu:///system destroy/start test1..16`) between failing runs.
- zsl harness count parse breaks (garbage huge fs_silent) when find/EIO output contaminates the count — pre_drop/post_drop concatenation bug in sess88_workload script, worth fixing.
- xfs_bmap ioctl (XFS_IOC_FSGEOMETRY) rejected on mxfs mounts — use the python dumper instead.
