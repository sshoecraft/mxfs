---
name: sess40-fence-REFUTED-real-root-dirdata-clobber-plus-AG-doublealloc
description: sess40 DECISIVE: the incarnation-fence (C22056240) is REFUTED — dir_reuse 2/tcp still fails 1/5 (corrupt=39 EFSCORRUPTED), fence fired 0x even on the…
metadata:
  type: project
---

## sess40 (ccloop 8ddb16a2) — incarnation-fence REFUTED; real dir_reuse 2/tcp roots re-identified. Build C22056240. Marker NOT written.

### RESULT: tests/drc_loop.sh @ inode_mht_ms=300 dirwr=1 → 4 PASS / 1 FAIL of 5 (orig iter1 PASS + batch 1,2,4 PASS, iter3 FAIL). So the bug DOES reproduce (~20% here, historically ~50%). The fence (P-CLMERGE-DEADINCARN, unconditional WARN) fired **0× on EVERY iter incl. the FAIL** → the fence is INERT and IRRELEVANT. The handoff's "incarnation fence fixes dir_reuse" hypothesis is REFUTED (RULE 4, step 2a — disproven).

### iter3 FAIL is COMPOUND (fail_3_test{1,2}.log snapshotted in tests/_cap/):
**Bug A — dir-data block-0 clobber (readdir short, rounds 12,14: rank=2 readdir=187-188/200 missing node1_f1..f13, lookup_fail=0):**
- `P29-DATAWRITE tag=CLOBBER owner=131 daddr=120 buf_cnt=20 disk_cnt=21 comm=xfsaild/sda` (many). node1's xfsaild durably writes block0 with FEWER dirents than the coherent on-disk image → lost-update. P29 is a DETECTOR ONLY (logs at bio-submit, does NOT prevent).
- The existing chokepoint skip `mxfs_buf_xfsaild_skip_dir_write` (xfs_mxfs_dlm.c:15469, called pal/linux/xfs_buf.c:1985) ONLY skips when owner dir `i_dlm_mode==NL`. `P16-DIRBLK-SUBMIT owner=131 daddr=120` shows these writes at **mode=3(PR)/5(EX), nl=0 ALWAYS** → NL-skip never fires. The tenure-mismatch arm is DETECTOR-ONLY (sess17 disabled enforcement: a freshly-converted leaf with unset owner → b_tenure_id=0 false-positive). AND the tenure stamp is INERT here: most writes show `tenure=0 epoch=0 tmism=0` (i_mxfs_ex_grant_seq==0 so mxfs_dir_data_track stamps 0; 0!=0 → no mismatch). So NOTHING catches this held-mode stale flush. Count alone (buf<disk) can't distinguish stale-flush from a legit rm (this node removed entries → fewer = newer); needs union-merge or real epoch authority.

**Bug B — inode-cluster DOUBLE-ALLOC → EFSCORRUPTED shutdown (rounds 15-20: lookup_fail=1 node1_f50.md5, durable):**
- `XFS (sda): Metadata corruption detected at xfs_inode_buf_verify, xfs_inode block 0xb40, error 117 (EFSCORRUPTED)` repeated ~39× (corrupt=39). `P26-IGET-FAIL dp=131 name=node1_f50.md5 inum=2880 err=-117`. ino=2880's inode cluster lives at daddr 0xb40.
- The corrupted buffer's First-128-bytes = HIGH-ENTROPY RANDOM DATA (6a e7 de a0 cc f7...) = /dev/urandom FILE CONTENT, NOT an inode. So a FILE's data extent was allocated at daddr 0xb40 which is ALSO the inode cluster for ino=2880 → the file-data page-cache writeback corrupted the inode cluster. = AG free-space DOUBLE-ALLOCATION (allocator gave 0xb40 to a file data block while it's a live inode cluster).
- `P117-AGMETA-STALE-CLEAN agno=1 ... bnobt` firing (10×) → the free-space btree is stale/incoherent across nodes = the double-alloc source. This is the SHUTDOWN cause and matches the sess39-handoff "remaining hard blocker: AG free-space double-allocation → block shares daddr with inode cluster → EFSCORRUPTED."
- File data does NOT go through the xfs_buf chokepoint (page-cache/iomap), so a write-submit guard can't catch Bug B; the fix must be ALLOCATOR-side (bnobt/agf coherence).

### Both PASS and FAIL iters had benign-only "shutdown" lines EXCEPT iter3 (real EFSCORRUPTED). iter4 PASS had corrupt=2 (unchecked — likely transient, didn't fail the test).

### CONFIG findings (for the criterion run):
- `mxfs_inode_mht_ms` default was 50; raised to **300** in source this session (xfs_mxfs_dlm.c:3718) — memories say 300 needed for dir_reuse timing; canonical `./run.sh 2 tcp` uses module defaults. NOT yet rebuilt/validated.
- `dirwr`/`instr` default 0 (diagnostic). Criterion run must be production (no MXFS_EXTRA_MODARGS beyond what's baked in).
- 16 of 17 2/tcp tests last passed on STALE older builds (Jun 16-19) — full suite must be re-validated on the final build.

### NEXT (RULE 4): two independent deep roots. Bug B (AG double-alloc, EFSCORRUPTED, shutdown) is the more severe. Investigate P117-AGMETA-STALE-CLEAN (xfs_mxfs_dlm.c:12995) — does it prevent or just detect? The fix class = invalidate/refresh stale bnobt/cntbt/agf on AG-lock acquire so allocation reads coherent free-space (cf. sess42 C6970FF9, sess43 BB54A138 in MEMORY.md). Bug A (dir-data clobber) needs union-merge/epoch-authority (sess17 attempted). Reproduce: MXFS_EXTRA_MODARGS='inode_mht_ms=300 dirwr=1' bash tests/drc_loop.sh 5. Related: [[sess40-fence-reconciles-sess27-and-tcp-root-why-correct]] (now superseded — the fence is inert) [[sess16-FIX-LEAD-extend-chokepoint-skip-to-dir-dirent-blocks]] [[sess27-PROVEN-root-durable-inode-alloc-revert-not-leafhole-not-fua]]
