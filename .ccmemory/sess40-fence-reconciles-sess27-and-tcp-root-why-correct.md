---
name: sess40-fence-reconciles-sess27-and-tcp-root-why-correct
description: sess40: the incarnation-fence (build C22056240) reconciles sess27 (durable on-disk) + sess-tcp-ROOT (stale in-core map) — corruption is node2's stale…
metadata:
  type: project
---

## sess40 (ccloop 8ddb16a2) — verifying the incarnation-fence fix for dir_reuse_coherency 2/tcp. Build **C22056240** (= AFE4E833 + fence). Marker NOT yet written.

### The fence (xfs/xfs_inode.c mxfs_iflush_cluster_merge_dirs ~5226-5258)
In `xfs_iflush_cluster` (line 5549, covers BOTH direct + co-resident cluster flushes), for a slot in the `flushing` mask (EX-held / own-flush, normally "authoritative, don't overlay"): if it's a DIRECTORY whose in-core `di_gen` (dbuf) DIFFERS from the fresh on-disk `di_gen` (ddisk), overlay the canonical on-disk image. Logs `P-CLMERGE-DEADINCARN`.

### WHY structurally correct — reconciles the two proven roots:
- **sess27** (build F156B768): durable on-disk corruption, BOTH nodes agree after `drop_caches`. → corruption is in the DINODE written to disk.
- **sess-tcp-ROOT** (build 2045BCE9): node2's stale in-core EXTENT MAP (block0→daddr 112, a freed prior-incarnation daddr) — "disk DATA @120 is correct."
- **Reconciliation (sess-tcp-FIX-DESIGN):** the corrupting object is the INODE FORK, not the data block. node2's stale fork (block0→112) gets FLUSHED INTO the on-disk dinode (xfs_iflush → xfs_inode_to_disk writes the extent map into the dinode), overwriting node1's canonical fork (block0→120). Then both nodes cold-reiget ino=131 → read the corrupted dinode → getdents reads logical block0 @ daddr 112 (missing node1_f1..f12) → readdir short; leaf lookup still works → lookup_fail=0. So sess27 "durable, both agree" AND sess-tcp "stale map" are the SAME bug: a stale fork made durable in the dinode. P-DRD measured the DATA block @120 (correct); it never measured the dinode's extent map (the corrupt part).

### Why the fence catches it (round sequence):
1. rank1 (node1) `mkdir D` → ino=131 realloc'd, NEW di_gen (G_new), block0 freshly @ daddr 120; node1 `sync` → G_new durable on disk BEFORE the dir-ready barrier releases.
2. Both nodes create 50 files in D. If node2's ino=131 VFS inode SURVIVED the prior round's `drop_caches` (pinned/dirty/referenced), node2 keeps the dead prior incarnation (G_old, block0→112) and never reloads (the INODE_FREE/DIR_MODIFY notify is lost — evict-ring 28-entry overflow / asymmetric dedup).
3. node2 `sync` flushes ino=131's dinode carrying G_old/block0→112. Fence: dbuf->di_gen=G_old, ddisk (fresh disk read)=G_new → MISMATCH → overlay → node2 writes G_new/120 instead. Disk stays canonical.
4. Self-reinforcing: disk is G_new (node1's mkdir-sync); every node2 flush this round is fenced to G_new, so disk never flips to G_old. Cold readdir reads block0→120 → PASS.

### Why `di_gen` is a faithful proxy (not a hole):
i_generation and the extent map are BOTH set by xfs_inode_from_disk (reload). A reload rebuilds both together; no path updates i_generation without rebuilding the fork. So "di_gen == disk" ⟺ "fork is this incarnation." A stale fork ALWAYS carries the stale (mismatched) gen.

### The one theoretical hole (low risk):
If node2's G_old image reached disk BEFORE node1's G_new (so ddisk=G_old matches dbuf=G_old) the fence skips. But node1's mkdir-`sync` durably writes G_new before the barrier, and node2 flushes only after — so disk=G_new when node2 first flushes. The fence catches the first stale flush each round; disk never goes to G_old. Holds as long as Invariant-1 (node1's mkdir durable-before-barrier) holds.

### EMPIRICAL so far: iter1 PASS (2/2), fence fired **0×** both nodes, no real shutdown/corruption (only benign "DLM shutdown complete" teardown). 0× = node2 re-iget'd ino=131 COLD that round (G_new, no staleness) = the COMMON case; the fence only fires when node2's inode survives drop_caches stale. A single 0-fire PASS is NOT proof (historical ~50% fail). Running tests/drc_loop.sh 4 (build asserted on all nodes by run.sh prep) to get 5 total data points + see if the fence ever fires on a would-fail round.

### FALLBACK if fence proves flaky: the robust primary (sess-tcp-SEED-ROOT, sess-tcp-FIX-DESIGN) = incarnation-verify on dir-EX ACQUIRE — read on-disk di_gen, if != in-core i_generation force a full reload so node2 NEVER holds a stale fork. Fast-path gate is at xfs_mxfs_dlm.c ~8608 (dir_ex_stale_refresh) which currently keys ONLY on i_dlm_dir_gen>loaded_gen || MXFS_IF_DIR_RELOAD (both lost for ino=131). Reload self-skip (mxfs_dlm_reload_inode ~6122 peer_modified_since_load) is also gen-keyed — must add an incarnation-mismatch override. Related: [[sess-tcp-FIX-DESIGN-fence-stale-dir-inode-fork-flush]] [[sess-tcp-SEED-ROOT-ino131-free-lost-to-evict-ring-overflow]] [[sess-tcp-WHY-merge-misses-it-EX-held-stale-incarnation-fork]]
