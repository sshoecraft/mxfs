---
name: sess19-GPT2-dir-index-freshness-barrier-fix-spec
description: sess19 GPT-5.5 consult #2 — DEFINITIVE fix spec for 2/tcp leaf-hash clobber: dir LEAF/NODE/FREE index buffers need an IMAGE-ORIGIN epoch (set at read…
metadata:
  type: project
---

## sess19 (ccloop 8ddb16a2) GPT-5.5 consult #2 (RULE-5, 2nd GPT call on this issue) — the DEFINITIVE, implementable fix for the 2/tcp dir LEAF-HASH clobber [[sess19-PROVEN-xfsaild-stale-leaf-reflush-clobber]] [[sess19-refine-clobber-is-content-divergent-not-count]].

## CORE INSIGHT: MXFS's per-buffer `b_mxfs_dir_gen` is a USE/TOUCH stamp (set on cache-hit/!XBF_DONE pre-read/post-read restamp), but correctness needs an IMAGE-ORIGIN epoch. `current-tenure ACCESS != current-tenure CONTENTS`. That is why the clobbering xfsaild leaf write showed tmism=0 (current modify epoch) over stale 140-content. Fix = tie freshness to where the CONTENTS came from, and prevent a stale-image dir index buffer from ever becoming dirty/written.

## THE FIX (single best, GPT-decisive):
1. Per-directory `epoch` (use the existing i_dlm_dir_gen or a dedicated counter): increment on every peer-modified DLM grant (slow-path acquire). Do NOT bump on continued local cached tenure.
2. Per-buffer `image_epoch` for dir DATA-fork index buffers (leaf/node/free AND data): set ONLY at read COMPLETION, to the epoch captured at read SUBMISSION (`read_submit_epoch`), NEVER on cache-hit, verifier success, buffer-lock, trans-attach, or xfs_buf_find. CRITICAL for late-readahead: a read submitted in epoch G that completes after the inode advanced to G+1 must stamp image_epoch=G (stale), so the next-tenure use re-reads. (MXFS today restamps b_mxfs_dir_gen=dir_gen_snap post-read / on !XBF_DONE pre-read — that is the touch-stamp bug to replace.)
3. ENFORCE at three points:
   a. xfs_da_read_buf (dir leaf/node/free): if image_epoch != dir.epoch and buffer is CLEAN → xfs_buf_stale + cold re-read from coherent LUN. If image_epoch != dir.epoch and buffer is DIRTY/PINNED/in-AIL → INVARIANT VIOLATION (stale base already dirtied) → shutdown OR exceptional rebuild-from-data-blocks (NOT a silent keep — the current keep-guard keeping a gen-stale pinned leaf IS the clobber).
   b. dirty/trans-join time: never let a dir index buffer with image_epoch != dir.epoch become dirty.
   c. bio write-submit chokepoint (final guard): a dir index buffer with image_epoch != dir.epoch must NOT be written → force_shutdown (precise diag) or rebuild. Do NOT use buf_cnt<disk_cnt as policy (count compare is UNSAFE — a legit REMOVE writes buf_cnt<disk_cnt legitimately; it passes the epoch check because it operated on a fresh image). Count is telemetry only.

## TWO HOLES TO CLOSE (GPT):
- Hole A (acquire eviction coverage): the acquire-side evict must walk ALL data-fork mapped extents incl. the HIGH dir2 logical offsets (leaf at 0x800000, node, free) — NOT bound by i_size — and ensure the iext map is LOADED first. (MXFS mxfs_dir_evict_data_blocks already does for_each_xfs_iext over the data fork + handles BTREE-not-loaded → likely OK, verify it reaches the leaf daddr.)
- Hole B (late readahead/read repopulates stale): stamp image_epoch from read-SUBMIT epoch, not completion/touch. Consider disabling dir-index READAHEAD (xfs_da_reada_buf no-op) on shared mounts as a simpler partial close.

## REMOVE-SAFE / PERF-SAFE / NO-MERGE: remove-safe because policy is image-freshness not count (a remove on a fresh image passes). Perf-safe because the extra cold-read is once per peer handoff per actually-accessed index block. No hot-path dirent merge, no extra DLM acquire, no pinned-buffer force-refresh (which causes CORRUPT_INCORE — keep that guard; instead the stale-pinned case must be impossible if release drained, else shutdown/rebuild).

## EVIDENCE THIS MATCHES: DIR-STALE-SKIP on the leaf (blk=0x800000) showed buf_gen=0 (image stale/evicted) inode_gen=3 (current) pin=1 → the read-path WANTED to refresh but the keep-guard kept the stale pinned leaf; xfsaild then flushed it (buf_cnt=140 over disk 202). Under GPT's rule, a stale-image (buf_gen != inode_gen) DIRTY/PINNED dir index buffer is an invariant violation → shutdown/rebuild, never write.

## IMPLEMENTATION ORDER (sess20, RULE 4): (1) add image_epoch + read_submit_epoch to the dir-buffer (reuse b_mxfs_dir_gen but FIX its stamping: set at read submit/complete only, remove the touch/cache-hit restamps); (2) add the bio write-submit guard (shutdown+diag) FIRST as a detector to confirm every clobber is image_epoch!=dir.epoch (it should, given buf_gen=0!=3); (3) add the read-path clean→cold-read + dirty/pinned→rebuild/shutdown; (4) verify acquire eviction reaches the leaf daddr. Validate: cc_blockdir_probe 30 50 → 0 short AND every readdir entry lookup-able ×3, + ./run.sh 2 tcp 16/16 (removes must still pass — unlink_visibility/posix_multi). Build base = 8B8D7499. [[sess19-GPT-fix-dinode-coherency-and-cluster-iflush-clobber]] [[sess19-handoff-leaf-hash-fix-plan]]
