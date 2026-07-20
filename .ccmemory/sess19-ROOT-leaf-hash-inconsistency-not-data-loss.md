---
name: sess19-ROOT-leaf-hash-inconsistency-not-data-loss
description: sess19 CORRECTED ROOT: 2/tcp cc_blockdir_probe "loss" is NOT data loss — it's a dir LEAF-HASH-vs-DATA-BLOCK inconsistency. Lost entries appear in rea…
metadata:
  type: project
---

## sess19 (ccloop 8ddb16a2) — CRITICAL CORRECTION to the long-standing "durable dirent loss" framing.

## THE ACTUAL BUG (proven live, build F13B9FB0): the cc_blockdir_probe "lost" entries (e.g. node2_f4/f10/f27/f39/f45/f50.md5) are NOT lost. They are present in READDIR (`ls /mnt/shared/.ccb_2` lists all 100 md5 + 100 data = 200) but FAIL LOOKUP: `stat node2_f4.md5` → ENOENT, `[ -e node2_f4.md5 ]` → false, `ls -i node2_f4.md5` → "cannot access". So the dir is INTERNALLY INCONSISTENT: the dirents are durably in the dir DATA blocks (readdir walks data blocks sequentially → sees them) but the LEAF HASH INDEX block (xfs_dir3_leaf1, daddr=2094824 in the repro) is MISSING the hash entries for those names → namei lookup hashes the name, searches the leaf, fails → ENOENT.

## WHY THE PROBE REPORTED "loss": `ls $D/node*_f*.md5 | wc -l` globs via readdir (sees the name) then statx's each → the 6 fail statx → ls drops them → 194/200. The "permanent, both nodes" verdict is correct in that lookup stays broken (nothing rebuilds the leaf hashes), but it is a HASH-INDEX corruption, NOT dirent/data loss. md5sum-by-name fails (can't open).

## MECHANISM: concurrent same-dir creates from both nodes; the dir grows to LEAF format (data blocks 1912,2094840 + leaf1 block 2094824). The LAST writer (test1 final create, P16-DIRBLK-SUBMIT daddr=2094824 ops=xfs_dir3_leaf1 tmism=1) RMW'd the LEAF block from a STALE base and durably wrote it missing the peer's 6 hash entries. At that acquire the evict SKIPPED the leaf as !XBF_DONE (P-EVICT-SKIP done=0); the subsequent createname leaf read did NOT pick up the peer's durable leaf image (the 6 hashes) → clobber. The DATA blocks were durable (readdir intact); only the LEAF hash index lost entries.

## EARLIER MIS-DIAGNOSES THIS SESSION (corrected): (a) "dinode reverts to shortform" (P62 disk_fmt=1 size=27) is a TRANSIENT during the early concurrent-shortform phase; the FINAL dinode is test2's BLOCK (P133-DIRINO-WR size=8192 nx=3) and is intact (dir size=8192 blocks=24, 3 data blocks present). NOT the root. (b) Inode-cluster-iflush clobber (mxfs_iflush_cluster_merge_dirs) — exists, not the cause here (P91-RELOAD-PROTECT and P133-DINO-READSTALE both fired 0× for ino=1962). The reload read the genuine coherent disk. The loss is purely the LEAF block RMW.

## FIX TARGET (next): ensure the dir LEAF (hash-index) block RMW at a cross-tenure acquire cold-reads the peer's DURABLE leaf image, same as data blocks. The evict/refresh machinery (mxfs_dir_evict_data_blocks walks the data fork iext — leaf blocks ARE in the data fork, so covered) SKIPS !XBF_DONE leaf blocks; the gap is the subsequent xfs_da_read_buf of the leaf returning a stale image at the final-create acquire. INSTRUMENT: at createname's leaf-block read, compare the used leaf against a coherent plain-bdev read; detect when the last writer's leaf is missing the peer's hash entries (mirror of P133-DINO-READSTALE but for the leaf block). Then fix the leaf read/refresh. Validate: cc_blockdir_probe 0 short >25 iters AND lookup of every readdir entry succeeds, + ./run.sh 2 tcp 16/16. [[sess19-dinode-reverts-to-stale-shortform-confirmed]] [[sess19-GPT-fix-dinode-coherency-and-cluster-iflush-clobber]]
