---
name: sess-tcp-ROOT-stale-incore-extent-map-getdents-blk0-daddr
description: BREAKTHROUGH: dir_reuse 2/tcp loss = STALE IN-CORE EXTENT MAP. getdents iterates in-core map (blk0@stale daddr 112, cnt=88) while disk+leaf are corre…
metadata:
  type: project
---

## dir_reuse_coherency 2/tcp — ROOT NEWLY PROVEN (build 2045BCE9, = 6E20D7F9 + P-GROW0 instr)

### CRITERION still NOT met. Marker NOT written. Reproduce: `MXFS_EXTRA_MODARGS='inode_mht_ms=300 dirwr=1' bash tests/drc_cap2.sh` (~50% FAIL; inode_mht_ms=300 STILL not code default — must change before criterion run). Logs land in tests/_cap/test{1,2}.log.

### THE SIGNATURE EXPLAINED (readdir short + lookup_fail=0):
Failing runs: readdir=183-188/200, missing EXACTLY node1_f1..f12-17 (node1's FIRST data files, NO .md5), lookup_fail=0. This is **NOT on-disk data loss** — it is a **STALE IN-CORE EXTENT MAP**:
- **getdents (xfs_readdir) iterates the dir's IN-CORE data-fork extent map** → reads logical blk0 at node2's STALE daddr **112** (cnt≈88, missing node1_f1..f12) → readdir lists only 188.
- The **leaf/lookup path reads the CORRECT blk0 @ daddr 120** → every listed name IS lookup-able → lookup_fail=0.
- Map (getdents) and leaf (lookup) are INCONSISTENT — that exact split produces readdir-short + lookup_fail=0.

### DECISIVE FORENSICS (P-GROW0 = new instr at xfs_dir2_grow_inode; P-DWR/P-DRD content count):
1. **node1 ALWAYS allocates blk0 @ fsb=15 = daddr 120** (P-GROW0, 24×/run, every round). **node2 NEVER allocates blk0** (P-GROW0=0, even on FAIL). So blk0's canonical daddr is ALWAYS 120; node2's blk0@112 is a STALE prior-incarnation daddr it never reconciles.
2. **Disk @ 120 is CORRECT**: P-DRD (cold reads, comm=ls/bash at verify) = node1_cnt=100. The loss is NOT durable on-disk corruption (refutes the sess-tcp "divergent block0 cache writeside" framing).
3. node2's **xfsaild/kworker destages a stale buffer @ 112** (P-DWR cnt=80) during the failing round — the lingering prior-incarnation buffer.
4. node2 P62-RELOAD-FORK-SHRINK shows incore_gen ≠ disk_gen (different incarnation), incore_nx=3 vs disk_nx=1.

### WHY the in-core map stays stale (hypotheses, RULE 4 next):
- Reload (mxfs_dlm_reload_inode, xfs_mxfs_dlm.c ~6629 sess33 DIR-GROWTH-REVERT-GUARD) FALLS THROUGH for gen-mismatch (rm+recreate), SHOULD adopt disk (blk0@120). But it either (a) BAILS on the bounded down_write_trylock(&ip->i_lock) under create contention (~6717, leaves i_dlm_stale set, stale map kept), or (b) never runs for getdents.
- **getdents/xfs_readdir reloads the inode ONLY for SHORTFORM dirs** (MXFS_IF_DIR_RELOAD consumer "before sf getdents", ~xfs_mxfs_dlm.c 11941). For BLOCK/LEAF dirs, getdents uses the in-core extent map with NO coherent reload → stale blk0@112.
- Cross-node dir-modify notify (disk-heartbeat evict ring) is ASYMMETRIC: node1 receives 0 EVICT-RING-DIRMOD, node2 338. Producer dedup bug (disklock.c ~1037): node2 only ever modifies ino=131 so every DIR_MODIFY after the 1st is permanently deduped (prev==same ino,type) → node1 never re-notified. Fix: reset dedup per-publish (track evict_published_seq).

### FIX CANDIDATES (next session):
1. **Make BLOCK/LEAF-dir getdents reconcile the extent map** (reload when multi-node + i_dlm_stale/gen-mismatch), like it does for shortform. Targets the proven getdents-reads-stale-map root directly.
2. **Reload must not bail silently on i_lock trylock** for a gen-mismatch (dead incarnation) reload — the dead-incarnation in-core map MUST be discarded; bounded-retry harder or block (it's process ctx at acquire).
3. **Evict orphaned buffers on reload**: snapshot old extent-map daddrs before xfs_idestroy_fork, after rebuild xfs_buf_stale any old daddr (112) not in the new map (120) so xfsaild can't destage the orphan.
4. Fix the evict-ring dedup asymmetry (per-publish reset) so node1 also gets dir-modify notifications.

Supersedes/refines [[sess-tcp-drc-residual-is-divergent-block0-cache-writeside]] (disk is NOT divergent; in-core MAP is). Relates [[sess36-PROVEN-datainit-zeroes-live-block0-root]] (datainit-zero is benign per sess37; real root is the stale in-core map). [[sess-tcp-HANDOFF-phantom-ex-fixed-residual-incarn-aba]]
