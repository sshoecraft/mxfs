---
name: compiled-dir-leafhash-sess20-21-reflush-clobber
description: sess20-21 dir leaf-hash loss: bgen=0 readahead clobber (fixed), then reuse pinned-leaf stale-RMW root + GPT leaf-rebuild fix (build 71E1C8A9, 90/91).
metadata:
  type: project
tags: [compiled, dir-coherency, leaf-hash, dir_reuse_coherency, readahead, leaf-rebuild, sess20, sess21]
---

## Compiled: dir leaf-hash loss under concurrent + reuse churn (sess20→sess21)

Central topic: durable directory **leaf-hash index** loss (readdir lists all names / count=200, but `lookup` ENOENTs the peer's entries) on a 2-node TCP cluster sharing one dir inode (ino 131, leaf daddr 2093296). Two distinct sources were found and fixed across two ccloop-8ddb16a2 sessions: (1) a `b_mxfs_dir_gen=0` readahead-origin stale-leaf clobber (sess20, FIXED), and (2) a **pinned+undestaged leaf stale-RMW on the acquire path** under rm-rf+recreate reuse churn (sess21, root PROVEN + leaf-rebuild fix landed, 90/91). Lost entries are ALWAYS the non-owner/rank-2 node's (node2), because only node2 crosses a DLM EX handoff to insert into rank1's dir.

---

### sess20 — first fix: readahead bgen=0 leaf clobber (crash_consistency / non-reuse)

PROVEN discriminator [[sess20-PROVEN-bgen0-leaf-clobber-discriminator]] (build 5E54558B, `bgen` added to P16-DIRBLK-SUBMIT + P-LEAFWRITECLOBBER): the clobbering leaf buffer carries `b_mxfs_dir_gen=0` — a stale image set by `mxfs_dir_evict_data_blocks` at acquire (or fresh-init) and NEVER re-stamped to the current dir gen — flushed by `xfsaild` over a coherent on-disk block a peer grew. Caught: `P-LEAFWRITECLOBBER daddr=2097480 buf_cnt=119 disk_cnt=202 bufgen=0 comm=xfsaild`. Legit current-tenure writes carry `bgen == i_dlm_dir_gen` (P16: dgen=270 bgen=270). Discriminator is clean: **bgen < i_dlm_dir_gen = stale-base image; bgen == i_dlm_dir_gen = current/fresh.** Existing guards missed it because `b_tenure_id` is a touch-stamp (current) while content is stale; `b_mxfs_dir_gen` is the image-origin epoch (stamped only at `xfs_da_read_buf` read, 0 after evict; readahead bypasses that stamp = GPT "Hole B").

TWO FIXES landed, build E0C391F3, both KEEP [[sess20-FIX-2tcp-leafclobber-and-reada-disable]]:
1. **PRIMARY — dir readahead auto-disabled on multinode.** `mxfs_dir_no_reada` default 0→1; gate in `xfs_da_reada_buf` (xfs/libxfs/xfs_da_btree.c) scoped to `m_mxfs_dlm && !is_single_node && S_ISDIR`, so single-node keeps readahead (no perf regression). Removes the stale-base source entirely. crash_consistency → 3/3 (was 1/2).
2. **BACKSTOP — `mxfs_buf_leaf_clobber_skip`** (xfs/xfs_mxfs_dlm.c, called in pal/linux/xfs_buf.c `xfs_buf_submit_bio`): for a leaf1/leafn write, fast-path `bgen >= dir_gen` → normal write; only `bgen < dir_gen` → plain-bdev-read coherent disk leaf and skip (emulate clean ioend, clear XBF_DONE|_XBF_FUA_FRESH) iff valid LEAF magic + same owner + `disk_cnt > buf_cnt`. In final runs P20 fired 0× (readahead-off removed the source). CAUTION: the emulate-ioend backstop drops a still-committed log delta — safe for drop_caches crash_consistency, but a real node-kill + log-replay could replay a stale-base delta; the readahead-off primary is what actually avoids the stale RMW.

Result: official `./run.sh 2 tcp` = **16/16** (E0C391F3), reproduced across multiple full-suite runs. `dirwr=1` HIDES the race (timing).

---

### sess20 — reuse variant surfaces (dir_reuse_coherency), NOT the same bug

The readahead fix did NOT fix the **reuse** variant. New tracked criterion `tests/suite/dir_reuse_coherency.sh` (criteria.json row 13, coord=barrier, min_nodes=2) [[sess20-dir-reuse-coherency-reliable-repro-characterization]]: 24 rounds (DRC_ROUNDS), NF=50, both nodes concurrently create NF data+NF md5 into ONE shared dir → barrier → every node cold-reads + per-entry `lookup` (the check crash_consistency lacked) → barrier → rank1 rm-rf+recreate (reuse churn) → barrier. Characterization (build F8FF8E54): always node2's entries missing; `readdir=200` always, only lookup fails (pure leaf-hash index loss); **cumulative + growing** (r16=6, r17=10, r18=16, r19=18 missing, each ⊇ prior) DESPITE rm-rf each round; first ~15 rounds clean, manifests from ~round 16 (why a 10-round test false-greened). Reliable + SAFE (no wedge) → good debug loop.

Ruled-out hypotheses (RULE 4 elimination, do not repeat) [[sess20-reuse-leafhash-ruled-out-hypotheses]]:
1. xfsaild stale-leaf reflush count-short (P-LEAFWRITECLOBBER `buf_cnt<disk_cnt`) — did NOT fire while test failed.
2. Content-divergent leaf write at equal count (new hashval sum+xor fingerprint detector, build 64B8DBFD) — fired **0×** under dirwr=1 while failing ⇒ no leaf write through the `xfs_buf_submit_bio` chokepoint drops node2's hashes.
3. NL-released dir-skip suppression (`mxfs.dirskip`) — dirskip=0 STILL fails and WORSE ⇒ suppression is not the dropper.
4. ABA / prior-incarnation leaf — `buf_incarn == cur_gen` (2263907978), same incarnation, not ABA.
5. Readahead — reuse variant persists with reada=1.

Partial lead handoff [[sess20-reuse-leafhash-root-pinned-undestaged-leaf-handoff]]: `P-EVICT-SKIP ino=131 daddr=2093296 pin=1 undest=1` — modify-path evict keeps a pinned+undestaged leaf; but P-LEAFWRITECLOBBER did NOT fire, so at that point it might just be node2's legit current work — mechanism unidentified. Noted `mxfs_dir_flush_data_blocks` (release, xfs_mxfs_dlm.c ~1267) already log-forces + wait_unpins before handoff, so a naive "release doesn't unpin" theory is wrong.

The separate corruption-shutdown variant [[sess20-residual-is-daddr-reuse-corruption-not-leafhash]] (build E0C391F3/E0C391F3): under rm-rf+recreate, `xfs_da_read_buf → xfs_corruption_error` (dir DATA block fails verifier during addname) → `xfs_dir2_leaf_addname → xfs_dir_createname → xfs_create → xfs_trans_cancel` (DIRTY) → "Corruption of in-memory data (0x8)" → shutdown, both nodes. This is the historical inode/daddr-REUSE double-alloc / stale-extent-map family (sess39 EFSBADCRC, sess87 double-alloc, sess111 stale bmap). P20 guard is NOT the cause (test1 shut down with 0 P20 fires). This variant CAN wedge the cluster (umount hang → rmmod busy → needs `virsh destroy/start test2`).

REFRAME (sess20, later REFUTED in sess21) [[sess20-REFRAME-reuse-bug-is-cross-node-dir-format-divergence]]: build E98F295F, `dirwr=1` — smoking gun that the two nodes DISAGREE on the SAME dir's data-fork FORMAT: test1 P16 ops only `xfs_dir3_block` (BLOCK format), test2 ops `xfs_dir3_data`×4 + `xfs_dir3_leaf1`×6 (LEAF format). Hypothesized: rm-rf+recreate makes the block↔leaf FORMAT transition non-coherent across nodes → incompatible RMW at same daddrs → ENOENT + verifier shutdown. Proposed next-locus [[sess20-reload-selfskip-format-adoption-gap-next-locus]]: `mxfs_dlm_reload_inode` (xfs_mxfs_dlm.c:5547) self-skip guards (sess36/49/58/59/8) keep a stale in-core inode/format when `!mxfs_dir_disk_superset && i_itemp && (IN_AIL||DIRTY||ili_fields||pincount>0)`, so a peer's block→leaf conversion is not adopted. Build boundary E98F295F (P-LEAFWRITE trace, readahead-disable kept, P20 removed).

---

### sess21 — REFRAME REFUTED, true root PROVEN, leaf-rebuild fix

The sess20 "cross-node dir FORMAT divergence / reload self-skip" reframe is REFUTED [[sess21-PROVEN-root-pinned-leaf-staleRMW-and-gpt-rebuild-fix]] (build 4942DEC9): detectors P21-SELFSKIP-DISKAHEAD=0 and P58=0 both nodes; block↔leaf are BOTH `di_format=EXTENTS` (only `di_nextents` differs, verified vs kernel xfs_dir2_block.c/leaf.c) so the P16 "block vs leaf" op difference was not a real on-disk format divergence. Also a harness bug invalidated some sess20 data: **test2 was silently running an OLD module** (no per-node srcversion assert) → run.sh now asserts per-node `srcversion == local .ko`.

PROVEN ROOT (build 4942DEC9, DRC_ROUNDS=15, NO dirwr — dirwr=1 changes the failure mode, do NOT diagnose with it): the shared dir's SINGLE leaf block (daddr 2093296, ino 131) is **perpetually pinned + undestaged** (`P21S-EVICTSKIP-LEAF ino=131 pin=1 undest=1 dirty=0 in_ail=0`, 60×/365×) — every create touches the one leaf → CIL never quiesces it. DATA blocks are NOT perpetually pinned (each dirent → one of several data blocks → they quiesce → evict refreshes them → readdir COMPLETE=200). The acquire/reader evict (`mxfs_dir_evict_data_blocks` AND `mxfs_dir_drain_evict_data_blocks`) SKIPS the pinned leaf (can't clear XBF_DONE while pinned → would lose uncheckpointed delta = sess64 corruption). So a node acquires EX with a STALE in-core leaf (missing peer's recent hashvals), inserts its own entry, destages it → durably DROPS the peer's hashvals. **The bug is ACQUIRE keeping a stale pinned leaf, not release** — release DOES destage it (`xfs_log_force(SYNC)` + `xfs_ail_push_ag_sync`, xfs_mxfs_dlm.c ~4392-4396; P21F-RELFLUSH-LEAF=0). Round ~15 lookup_fail; round ~17 test2 shuts down (xfs_create→xfs_trans_cancel dirty-cancel, secondary) — cap DRC_ROUNDS=15 to repro the hole without the wedge.

Prior fixes that don't work (why): merge-via-separate-DLM-acquire = TCP DLM timeout shutdown (sess18); force-evict-on-release = resurrection (sess96); bounded pin-drain at acquire = storm re-pins faster (sess74/97); unbounded = 5.5× slowdown (sess97); clearing XBF_DONE on pinned = corruption (sess64).

GPT-5.5 fix design (leaf is DERIVED metadata; rebuild from coherent DATA inside the modify's OWN tp+grant — no extra DLM acquire, no XBF_DONE-clear-on-pinned): detect (set `MXFS_DIR_DERIVED_STALE` when a pinned/undestaged leaf is skipped; `MXFS_DIR_DATA_UNSAFE` if a data block is skipped) → repair at top of createname/removename/replace (scan coherent in-core DATA, `xfs_dir2_hashname` + `xfs_dir2_db_off_to_dataptr` per live dirent, sort by (hash,addr), OVERWRITE the pinned leaf in-core, RELOG via `xfs_trans_log_buf`) → lookup fallback via data scan while stale → add log reservation for a full leaf block → rebuild only when DATA proven coherent.

IMPLEMENTED (KEEP), build 71E1C8A9 [[sess21-leaf-rebuild-fix-works-90of91-residual-stale-datablock]]:
- New inode flag `MXFS_IF_DIR_LEAF_STALE` (xfs/xfs_inode.h, 1<<21), set in BOTH evict-skip-leaf sites (`mxfs_dir_evict_data_blocks` ~2094, `mxfs_dir_drain_evict_data_blocks` ~3322) when a LEAF block is skipped.
- New fn `mxfs_dir_rebuild_leaf_from_data(args)` in xfs/libxfs/xfs_dir2_leaf.c (decl xfs_dir2_priv.h, `#ifdef __KERNEL__`): scans data blocks db 0..bestcount-1, collects {hashval, address} per live dirent, sorts by u64 `(hash<<32)|addr`, OVERWRITES leaf ents+hdr+bests, relogs via `xfs_dir3_leaf_log_header/ents/bests` (NO XBF_DONE clear, NO extra DLM acquire). Bails clean (return 0, no mutation) on block/node format, holes, would-overflow-leaf, OOM.
- Called at top of `xfs_dir_createname` (xfs/libxfs/xfs_dir2.c ~533, `#ifdef __KERNEL__`) gated on `xfs_iflags_test_and_clear(dp, MXFS_IF_DIR_LEAF_STALE)` — fires ONCE per acquire (perf-safe; FASTEX creates in same tenure reuse the corrected leaf).

RESULT (dir_reuse_coherency 2/tcp, DRC_ROUNDS=15, NO dirwr): checks=91 passed=**90** FAILED=**1**. Rounds 1-14 PASS; round 15 single lookup_fail (node2_f34.md5); NO shutdown either node; reservation OK. (Was: lookup_fail 2-9 growing to 22-29 + round-17 shutdown.) P21S still fires (leaf still skipped) — rebuild corrects it after.

RESIDUAL (1 miss) = the rebuild read an IN-CORE data block that was itself STALE (undestaged-skipped at acquire by drain_evict, missing the peer's recent add to THAT block); cold `readdir=200` proves the entry is durable on disk, so the rebuild's cached read missed it = GPT's `MXFS_DIR_DATA_UNSAFE` edge. NEXT FIX (union read): in `mxfs_dir_rebuild_leaf_from_data`, rebuild from the UNION of (a) the in-core data block (this node's uncommitted adds) and (b) a COHERENT plain-bio read of the same physical daddr (`dbp->b_maps[0].bm_bn + bt_sector_offset`, len `BBTOB(dbp->b_length)`, `mxfs_pal_bdev_read_plain_bdev` with fua_disable=1 = coherence point, has peer's durable adds); collect {hash,addr} from both, sort, dedup consecutive-equal, size kv array 2*max_ents; validate disk block magic (XFS_DIR2/3_DATA_MAGIC) + owner==dp->i_ino before parsing, else fall back to in-core only for that block.

---

### Harness / repro (KEEP)
- `run.sh` asserts per-node srcversion == local .ko (catches stale-build deploy — caused invalid sess20 conclusions); `prep_node.sh` umount -f + rmmod retries; `MXFS_TEST_ENV` passthrough; `tests/force_reset.sh`.
- Fast repro (caps before round-17 shutdown wedge): `MXFS_TEST_ENV="DRC_ROUNDS=15" ./run.sh 2 tcp dir_reuse_coherency`. Full criterion = DRC_ROUNDS=24 default PASS + full `./run.sh 2 tcp` suite 100%.
- Diagnostic rule: use NO dirwr for this bug (dirwr=1 changes the failure mode / hides it); official `./run.sh 2 tcp` core = 16/16 (non-reuse fix), dir_reuse_coherency (row 13) is the open reuse criterion.
