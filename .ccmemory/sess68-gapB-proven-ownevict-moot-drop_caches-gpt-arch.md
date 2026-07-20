---
name: sess68-gapB-proven-ownevict-moot-drop_caches-gpt-arch
description: sess68: PROVEN gap-B (dir inode extent map not durable at release for non-LOCAL dirs) FIXED+KEEP. owner-evict REFUTED (drop_caches→collected=0). GPT…
metadata:
  type: project
---

## sess68 (ccloop 4cb2d0a2) — 4/tcp dir_reuse_coherency: gap-B proven+fixed; owner-evict refuted; GPT architecture obtained

CRITERION: 1/2/4/8 tcp 100%. 1✅ 2✅ (sess58). **4/tcp still FAILS only on dir_reuse_coherency** (~1 round in ~15, durable single/few-entry COUNT loss: LOOKUP_ENOENT + REREAD_MISS on ALL nodes after drop_caches = genuinely off the LUN; lost entry varies run-to-run: node2_f33.md5, node3_f2, node4_f40.md5, node1_f4+f5, node4_f36...). 8 untested.

### BUILD STATE (current tree, NOT the shipped 91962D4A)
- srcversion at handoff ~`2CF2C45B` (has all sess68 changes). Shipped-proven baseline is still `91962D4A` (force_block=1, epoch_adopt OFF).
- **KEEP (proven correct + necessary): gap-B fix** in `mxfs_dlm_dir_inode_durable` (xfs/xfs_mxfs_dlm.c ~1984): the old `if (if_format != LOCAL) return;` SKIPPED making a grown EXTENTS/BTREE dir's INODE extent map (di_size/di_nextents, inline in dinode) durable at EX release — only data/leaf/bmbt BLOCKS were flushed. So a peer's post-handoff FUA read of the dinode saw a stale SMALLER extent map → couldn't locate grown data blocks → re-allocated divergent block (count loss) OR adopted stale-small disk (P33-FROMDISK-DIRSHRINK tear). FIX: make the dinode cluster durable for ALL dir formats, GATED on the inode being dirty (pincount/ili_fields/in-AIL) to avoid the sess42 ungated ~30x-iflush perf regression. Verified the flush succeeds (no P68-DIRINODE-DURABLE-FAIL).
- **REFUTED + likely revert (inert for THIS test): owner-evict** (`mxfs_dir_evict_owned_dir_blocks`, wired pre-from_disk in reload_inode on gen-change/shrink, + xfs_iget_recycle, + post-from_disk flag). P68-OWNEVICT fires but **collected=0 evicted=0** EVERY time → the owner-walk finds ZERO cached dir blocks. ROOT: **the test does `echo 3 > /proc/sys/vm/drop_caches` every round** → cached data/leaf blocks NEVER survive → the "orphaned stale cached block / leaf-vs-data tear from surviving cache" theory is REFUTED. (Defensively correct for a real no-drop_caches workload, but moot here.)

### KEY INSIGHT (sess68, decisive): drop_caches drops the BUFFER cache (data/leaf blocks) but NOT the in-core INODE (i_df extent map persists — inode stays referenced). So:
- The PERSISTENT staleness that survives drop_caches = the **in-core data-fork EXTENT MAP** (i_df), not cached blocks.
- The durable loss = an **on-disk write loss** during the concurrent 4-node create wave (verify reads COLD after drop_caches and the entry is genuinely gone from the LUN), OR the node grows/RMWs using a stale i_df extent map.

### EXPERIMENTS THIS SESSION (all 4/tcp, FAIL):
1. baseline 91962D4A: count loss (node2_f33.md5).
2. epoch_adopt=1 (full from_disk i_df rebuild on EX-acquire when DLM epoch advanced): **count loss DISAPPEARS** (RDMISS=0!) but NEW failure = leaf-hash lookup_fail + P33-FROMDISK-DIRSHRINK (adopts a reset/shrunk incarnation). So epoch_adopt's extent-map rebuild DOES fix the count loss; its only problem is the shrink-adopt tear.
3. gap-B alone (no epoch): count loss (node3_f2, early entry).
4. gap-B + epoch_adopt: count loss returns (node1_f4+f5 / node4_f9).
5. gap-B + owner-evict + epoch / no-epoch: still loss; OWNEVICT collected=0 (moot).

### GPT-5.5 CONSULT (RULE 5, full diagnosis) — ARCHITECTURE for next session:
TWO separate bugs needing TWO keys:
- **Bug #1 (same-di_gen lost-update / count loss):** needs a **DLM-EPOCH**-keyed invalidate/re-read BEFORE dir RMW. di_gen CANNOT catch it (same incarnation). Cached block has same gen but stale content / last-writer-wins RMW. NOTE: the existing modify-prelock epoch gate (`mxfs_dir_modify_extent_adopt`, sess67) is INERT because (a) it's count-based and the divergence is CONTENT not count, and (b) valid_epoch is already set == grant_epoch by the acquire reload, so grant_epoch>valid_epoch is never true at modify time.
- **Bug #2 (gen-change tear):** owner purge ordered BEFORE from_disk (moot here due to drop_caches).
- **Buffer stamps** should be keyed `(ino, di_gen/incarn, dlm_epoch, dir_cache_seq)` and validated in the READ path (xfs_da_read_buf / xfs_dir3_*_read), not just b_mxfs_dir_gen.
- **Deepest root (GPT):** an inode number REUSED cluster-wide while a peer still holds the old incarnation active VIOLATES a core XFS invariant. Robust fix = **inode-lifetime fencing**: a separate DLM lifetime lock; before xfs_ifree/reuse, acquire EX → BAST peers → peers purge+reclaim old incarnation before reuse proceeds. Large change.

### NEXT STEP (RULE 4): the count loss is bug #1 (epoch-keyed RMW). epoch_adopt (acquire-side i_df rebuild) FIXES it but tears on shrink-adopt. So: (A) make epoch_adopt the default AND fix the shrink-adopt tear by NOT adopting a smaller disk image when it's the SAME incarnation with our grow not yet durable — but gap-B should now make disk authoritative. Re-examine WHY DIRSHRINK still fires with gap-B (is the growing node's release actually reaching mxfs_dlm_dir_inode_durable at 5925? add a release-side probe logging in-core vs on-disk di_size/nextents AFTER the flush for non-LOCAL dirs — the existing verify at 5933 is gated to fmt==LOCAL only; EXTEND it to all formats). (B) OR add a write-side probe in the dir data-block WRITE/verifier path to catch the exact lost-update (a block committed with FEWER entries than the prior durable version). (C) consider the data-block RELEASE durability (mxfs_dir_data_durable) + whether the cold re-read pierces the SCST write-cache (FUA).

REPRO: clean reboot/rmmod test1-4, `MXFS_EXTRA_MODARGS='dir_epoch_adopt=1' ./run.sh 4 tcp dir_reuse_coherency` (~5min; mkfs prep FAILS if test1 has a leftover mount — umount -l + rmmod test1 first). Probes added (KEEP): P68-DATAINIT (xfs_dir2_data.c, all-block, no-IO), P68-OWNEVICT/PREEVICT/DIRINODE-DURABLE-FAIL (xfs_mxfs_dlm.c). test5-8 booted, shared LUN+NFS for 8/tcp.

[[sess67-ROOT-datainit-zeroes-live-dirblock-4node]] [[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]] [[sess58-CRITERION-MET-2tcp-17of17-8consecutive]]</body>
