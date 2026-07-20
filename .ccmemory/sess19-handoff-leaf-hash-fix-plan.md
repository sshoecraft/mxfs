---
name: sess19-handoff-leaf-hash-fix-plan
description: sess19 HANDOFF v2: 2/tcp blocker = dir LEAF-HASH inconsistency (readdir-yes/lookup-ENOENT), NOT data loss. Official run.sh 2 tcp PASSES 16/16. Read-s…
metadata:
  type: project
---

## sess19 (ccloop 8ddb16a2) HANDOFF v2 — supersedes v1. Cluster: build 1A15B1B5 deployed both nodes (= F13B9FB0 + a read-side P-LEAFREADSTALE detector in xfs_da_read_buf), 2-node tcp mounted, params reset to defaults (dirwr left 1 — reset to 0 if needed). Marker NOT written (bug reproduces).

## ESTABLISHED THIS SESSION (high-confidence):
1. The 2/tcp cc_blockdir_probe "durable dirent loss" is a dir LEAF-HASH-INDEX vs DATA-BLOCK inconsistency, NOT data loss. Reproduced 3×: iter2 (6 md5), iter14 (2 md5: node2_f47/f49.md5), all readdir-visible (ls=200) but lookup/statx→ENOENT. The dirents are durable in DATA blocks; the LEAF1 hash block is missing their hash entries. Full proof [[sess19-ROOT-leaf-hash-inconsistency-not-data-loss]]. (A 2nd variant also seen once: iter9 genuine readdir loss 164/200 — likely data-block lost-update, same keep-vs-adopt tension.)
2. The OFFICIAL `./run.sh 2 tcp` full suite PASSES 16/16 (precond/cache_coherency/strong_consistency/posix_multi/mmap/zero_silent_loss/dlm_*/scaling/rsync/crash_consistency/fence/fault/soak/tcp_dlm_scaling). The bug needs the harsher cc_blockdir_probe (concurrent same-dir creates from BOTH nodes + rm-rf inode/daddr REUSE each iter, ino reused e.g. 131/8929795). crash_consistency is single-writer (no concurrent same-dir creates) → official suite has a coverage gap for this bug.
3. GPT-5.5 consult [[sess19-GPT-fix-dinode-coherency-and-cluster-iflush-clobber]]: treat dir dinode+fork as the DLM coherency payload; drain-on-release + AUTHORITATIVE reload-on-acquire; NO dirent merge; NO tenure-stamp write-suppression.

## RULE-4 EVIDENCE FOR THE LEAF CLOBBER:
- DIR-STALE-SKIP fired 10× on test2 for the LEAF block (blk=8388608=0x800000, the dir2 leaf logical offset): `buf_gen=0 inode_gen=3 pin=1 undest=1 lseq=N wseq=0`. The read keep-guard (xfs_da_read_buf) WANTS to refresh the leaf (gen mismatch) but SKIPS because the leaf is PINNED + UNDESTAGED (this node's own logged-unwritten leaf work). The sess64 pin-guard MUST stay (force-refresh a pinned buf → CORRUPT_INCORE shutdown). So the node RMWs a leaf base that is its own pinned image but MISSING the peer's hash entries → durable hash-entry clobber.
- **P-LEAFREADSTALE (my new read-side detector: buf_cnt < coherent-disk_cnt at leaf read) fired 0× on the failing iter.** So the clobber is NOT a read-time count shortfall — it is a WRITE-ORDERING race (the node reads/keeps a leaf when disk == that stale image, RMWs, writes; the peer's hash entry lands on disk in a window such that the final leaf write drops it). The read-side detector is in the wrong place.

## NEXT STEP (corrected): move the detector to the WRITE/submit side. In pal/linux/xfs_buf.c dir-block submit chokepoint (near P16-DIRBLK-SUBMIT, ~line 1750), for a LEAF1/LEAFN block being submitted on a multinode mount: plain-bdev-read the coherent on-disk leaf at the target daddr and compare xfs_dir3_leaf_hdr.count — if the leaf being WRITTEN has FEWER entries than disk (and we are not legitimately removing), log P-LEAFWRITECLOBBER (the durable hash-entry loss, caught in the act). That pinpoints the writer + tenure. Then FIX per GPT: ensure the leaf is coherently merged/refreshed before the clobbering write, OR ensure the handoff drains+invalidates the leaf so the writer can't hold a pinned-stale leaf missing the peer's hashes. Reproduce: dirwr=1, cc_blockdir_probe 15 50 (fires ~1 in 10-15 iters; ino reuse via rm-rf makes it fire). Confirm fix: cc_blockdir_probe 0 short >25 iters AND every readdir entry lookup-able, + ./run.sh 2 tcp 16/16 ×3.

## DETECTOR CODE (in tree, build 1A15B1B5, KEEP or move): xfs/libxfs/xfs_da_btree.c just before `*bpp = bp;` in xfs_da_read_buf — P-LEAFREADSTALE. Harmless (gated dirwr/instr), but fired 0× so it's not the right probe point; reuse the plain-bdev-read + xfs_dir3_leaf_hdr.count compare idiom on the WRITE side instead.
