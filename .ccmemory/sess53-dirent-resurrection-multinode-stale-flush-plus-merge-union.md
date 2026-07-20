---
name: sess53-dirent-resurrection-multinode-stale-flush-plus-merge-union
description: sess53: dirent leak = MULTI-NODE: node1 stale-flushes removed source dirent to disk, node2 3-way SF merge UNIONS it back (P-SFMERGE 1+1→2). DIRGEN-BU…
metadata:
  type: project
---

## sess53 — dirent resurrection is multi-node (stale flush + merge union); 2 fixes refuted

### Reliability ladder this session (PLAIN `./run.sh 2 tcp`, default cfg dir_pr_release_fast=1 sf_merge=1):
- Build D67776EC+P52 (no new fix): **d1-d4 PASS, d5 FAIL(leak) = 4/5**.
- +DIRGEN-BUMP (99EBB950): f1 FAIL(iunlink crash), g1 FAIL(leak) = 0/2.
- +DIRGEN-BUMP+idempotent-iunlink (8658DF88, CURRENT mxfs.ko): g1 above. iunlink face didn't recur.
The 16 non-tcp_dlm_scaling tests are RELIABLE every run. tcp_dlm_scaling has TWO intermittent faces.

### FACE 1 — durable dirent RESURRECTION (the leak, ~1/5). MULTI-NODE mechanism (g1 forensics, ino 8948642, leftover n2_r137):
node2 does `mv n2_r137 n2_r137.done`. Leftover = the SOURCE name n2_r137 (the removal didn't stick).
- **node1** stale-flushes {n2_r137} to disk (a removed source dirent it still had cached) — DURABLE
  (both nodes see it after drop_caches).
- **node2** then 3-way SF-merges: `P-SFDIR-REVERT incore_cnt=2 disk_cnt=1`, `P-SFMERGE incore_bytes=21(1)
  theirs_bytes=21(1) merged_bytes=41(2)` → UNIONS its in-core {n2_r137.done} with stale disk {n2_r137}
  → 2 entries. Massive EVICT-RING-DIRMOD flood (gen->18..27, 10 reloads in 1ms) — the ring is firing
  constantly yet the stale disk image wins.
- So: stale FLUSH (write-side, node1) + merge UNION re-add (node2) compound. Reads are coherent
  (fua_disable=1: SCST write-back cache), so it's NOT a read-staleness; the bad image is on the LUN.

### REFUTED this session (do NOT repeat):
1. **DIRGEN-BUMP** (xfs_mxfs_dlm.c mxfs_dlm_bast_process ~5132): bump i_dlm_dir_gen on every dir
   release so next acquire reloads (reliable, vs lossy evict-ring). Gated on fua_disable. It does NOT
   regress cache_coherency/cross_write_read under fua_disable=1 (defeats the sess43 FUA blocker — good
   to know) BUT does NOT fix the leak (g1 leaked anyway). Reason: the resurrection is a BACKGROUND /
   false-sharing FLUSH + peer MERGE, not node1 modifying a stale in-core at acquire. Consider REVERTING
   (adds reload overhead, no benefit).
2. **sf_merge=0** (adopt-disk on reload): e1 PASS, e2 FAIL (still leaked n2_r60 + REGRESSED
   fence_during_write). The merge is ONE vector but disabling it alone doesn't fix the leak (disk is
   already stale from the flush) and breaks fence_during_write. KEEP sf_merge=1.

### FACE 2 — iunlink corruption shutdown (~1/5, the r1/sess45 face). FIX ADDED (idempotent-iunlink, in 8658DF88, UNVERIFIED):
P53 data (xfs/xfs_iunlink_item.c): `old_ptr=0x10de old_agino=NULLAGINO next_agino=0x10de
i_next_unlinked=0x10de uncp=1 bli=1` — rapid free→reuse→free advances buffer+in-core to the item's
next_agino before its precommit; only the captured old_agino is stale. FIX: in xfs_iunlink_log_dinode,
when `old_ptr==next_agino && i_next_unlinked==next_agino` (chain already in desired state) → idempotent
no-op instead of force-shutdown. SAFE (only no-ops when already-correct). Not yet seen recur to confirm.

### NEXT: FACE 1 is the dominant blocker. It's the 40-session dir-coherency core: stale dir-fork FLUSH
(node1) + 3-way SF merge UNION (node2) under heavy rename churn. The GPT Step-4 flush-fence design
([[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]]) targets the flush side; the merge-union
side may need a tombstone/seq so a peer-deleted entry isn't re-added from a stale disk image. CONSULT
GPT-5.5 (RULE 5 met: complete diagnosis + 2 refuted distinct fixes + architectural). Repro: PLAIN full
suite ~1/5 (intermittent; warm-FS repeat driver INVALID — node2 trans_cancel crash cascades).
Related: [[sess53-BREAKTHROUGH-plain-defaults-plus-P52-guards-17of17]] [[sess53-residual-durable-dirent-resurrection-stale-dir-flush]]
