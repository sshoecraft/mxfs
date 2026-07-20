---
name: sess27-BUG2-CRACKED-lookup-reload-stale-1block-extent-map
description: sess27 BUG2 CRACKED: cold-read lookup datascan ndb=1 scanned=100 (only node1's block) while readdir sees 2 blocks/200. Lookup-path reload gives STALE…
metadata:
  type: project
---

## sess27 (ccloop 8ddb16a2) — BUG2 ROOT CRACKED (decisive instrumentation)

### The finding (build 0548BE0A, partial_iwrite=0, dir_reuse 2/tcp)
Added a `scanned` counter to mxfs_dir2_datascan_lookup. At the failing cold-read lookup of node2_f10:
**`P26-DSCAN-MISS ino=131 ndb=1 scanned=100 name="node2_f10"`** (consistently ndb=1, scanned=99-103).
- The datascan computes ndb=1 from the in-core data-fork EXTENT MAP (my sess27 extent-map ndb fix) → the dir's in-core extent map has only **ONE** data block at lookup time, holding ~100 dirents (node1's).
- But readdir (the first `ls`, same round) lists 200 names across 2 data blocks, and the data block durably HAS node2_f10 (survives 2x drop_caches).
- So readdir's view = 2 data blocks; the lookup-path view = 1 data block. node2_f10 lives in block 1, which the lookup never reads → leaf miss + datascan miss → ENOENT.

### Root: lookup-path reload installs a STALE 1-block extent map
xfs_lookup → mxfs_dlm_dir_consumer_refresh (top of xfs_lookup) consumes MXFS_IF_DIR_RELOAD → mxfs_dlm_reload_inode rebuilds the dir's data fork from the ON-DISK inode. The disk dir inode's di_size / di_nextents reflects only 1 data block (the dir's GROW to 2 blocks — di_size and the 2nd data extent — was NOT durably committed by the writer, OR the reload reads a stale di_size). So the reload SHRINKS the reader's in-core extent map from 2 blocks (what readdir built) to 1 block. = a durable di_size/extent-map lost-update (same WRITE-side class as BUG1; cf sess57 di_size!=blksize, sess65/sess74 torn-dinode-barrier). readdir worked because it ran BEFORE/with a different refresh that still had 2 blocks, or built its view differently.

### NEXT (fix BUG2) — verify then fix
1. CONFIRM: on the left-mounted failing dir, dump the on-disk dir inode di_size + di_nextents (tools/chk_mxfs or a probe in mxfs_dlm_reload_inode logging di_size/nextents read from disk) vs the in-core extent count after readdir (P26-RDDIR shows nextents=3 = 2 data + 1 leaf). If disk di_size=4096/nextents=2(1data+1leaf) while it should be 8192/3 → durable di_size lost-update CONFIRMED.
2. FIX options (write-side, per [[sess27-gpt-design-release-drain-is-foundation-unified-root]]): ensure the dir-inode's di_size + extent-map grow (block0→block1, single-leaf→ or +data block) is durably destaged before the dir EX is handed off / before the writer's release. The dir-inode is destaged by mxfs_dlm_dir_inode_durable (bast release) and the data blocks by the sess97 fence — but the writer that GREW the dir may not have BAST'd (sole holder), so its di_size grow only reached the local AIL, not disk; the peer's reload reads the stale (pre-grow) di_size. Likely need: when a node grows a shared dir (adds a data block), make the dinode di_size durable promptly (FUA-write is DEAD on LIO — use synchronous metadata writeback / xfs_bwrite the inode cluster), OR on the reader side, do NOT let mxfs_dlm_reload_inode SHRINK the in-core extent map below the current in-core max (a reload should only ADD peer entries, never drop a data block the reader already has).
3. READ-SIDE STOPGAP to test the theory fast: in mxfs_dir2_datascan_lookup, scan up to max(extent-map blocks, di_size blocks, and a few extra) — but if the EXTENT MAP itself is 1 block, there's no block-1 mapping to read, so the read-side can't recover without the durable extent. So the real fix is WRITE-side durable di_size/extent grow OR reader reload must not shrink.

### Tree: 0548BE0A = baseline + diagnostics (P26 detectors ratelimited, datascan extent-map ndb + scanned counter) + partial_iwrite toggle(default 1). Behavior==orig for default args. partial_iwrite=0 PASSES cache_coherency/strong_consistency/posix_multi and fixes BUG1+data-block; ONLY BUG2 (di_size lost-update) blocks dir_reuse. FUA DEAD (LIO). Reboot cluster before runs. See [[sess27-FINAL-bug2-is-lookup-bug-datascan-misses-present-dirent]] [[sess27-partial-iwrite-0-viable-only-leafhole-remains]] [[sess27-PROVEN-root-durable-inode-alloc-revert-not-leafhole-not-fua]].
</body>
