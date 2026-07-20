---
name: sess48-KEY-backing-is-coherent-writethrough-loss-is-bufcache-invalidation
description: sess48(ccloop) KEY: the test cluster target is LIO FILEIO write-through (emulate_write_cache=0, single /home/steve/disk.img) = PERFECTLY coherent bac…
metadata:
  type: project
---

## sess48 (ccloop 4cb2d0a2) KEY REFRAME — the backing is coherent; the bug is xfs_buf invalidation

### Target config (verified on clyde, this host)
NOT SCST — it's **LIO** (target_core_mod + iscsi_target_mod). Backstore = FILEIO `mxfs` →
`/home/steve/disk.img`. attrib: **emulate_write_cache=0** (WRITE-THROUGH), emulate_fua_write=1,
emulate_fua_read=1. So: a single shared file behind a single host page cache, write-through.
=> the shared backing is PERFECTLY cross-initiator coherent — any node's write is immediately
visible to any node's read. There is NO un-destaged write-cache staleness.

### Implication (resolves the long FUA-read-stale confusion)
The 8/tcp dir_reuse durable lost-update is therefore NOT a target/FUA coherency gap. With a
coherent backing + all writer durability verified (P68 DURABLE, DIRREL_DIFFERS=0, P37=0) +
reader extent map consistent (P48-RDRELOAD bailed=0, nx_before==nx_after), the ONLY remaining
mechanism: a node RMWs/serves a STALE CACHED xfs_buf (in its own buffer cache) instead of
re-reading the coherent backing — i.e. an mxfs BUFFER-CACHE INVALIDATION miss across an EX
handoff. The cached dir block's b_mxfs_dir_gen wasn't advanced past i_dlm_dir_gen (or the block
wasn't evicted by owner_scan), so the cache-hit serves a peer-superseded image and the RMW
drops the peer's dirent.

### Refuted this session
- fua_disable=1 (read from write-cache instead of FUA backing): WORSE (7/24 rounds fail). The
  FUA-read of the coherent backing is the better path; the gap is the local xfs_buf cache, not
  the read source.

### THE FIX DIRECTION (next): bulletproof clean-dir-block invalidation on multinode dirs
Since the backing is coherent, serving a CLEAN cached dir block (not this node's dirty/in-AIL
uncommitted work) across any potential peer modify is the ONLY correctness risk. Make the dir
DATA/LEAF block read (xfs_da_read_buf mxfs hook) ALWAYS re-read from backing for a CLEAN cached
buffer on a multinode dir (ignore cache-hit unless dirty/in-AIL = our own work). The existing
gen-based invalidation (b_mxfs_dir_gen < i_dlm_dir_gen) intermittently misses because the gen
isn't reliably bumped on every handoff a peer modified in. RULE-0: re-reading every clean dir
block is slow — scope tightly (only when dir_gen>0 / cross-node) and measure. Alternatively fix
the gen-bump to be reliable on EVERY cross-node modify (not just handoffs this node sees).
See [[sess48-REFINED-all-durability-passes-residual-is-fua-read-stale-content]].
</body>
