---
name: sess36-PROVEN-datainit-zeroes-live-block0-root
description: sess36 PROVEN ROOT of dir_reuse 2/tcp correctness loss: xfs_dir3_data_init ZEROES block-0 holding 14 live dirents (=node1_f1..f14). P31E live_dirents…
metadata:
  type: project
---

## sess36 — PROVEN ROOT of the dir_reuse 2/tcp durable dir-block loss (the LAST blocker)

Timing is solved (MHT=300, 279.9s; see [[sess36-timing-solved-mht300-and-stall-fixes]]). The remaining
FAIL is CORRECTNESS, and this session PROVED the exact mechanism (build 4D56CB92, MHT=300 run):

### PROOF: `xfs_dir3_data_init` ZEROES a block that already holds live dirents.
Round 13 both nodes readdir=186/200, missing EXACTLY node1_f1..node1_f14 (rank1's first 14 DATA
files; .md5 + f15..f50 + all node2 survive). DURABLE (survives drop_caches → on-disk loss, NOT read-
cache staleness). The smoking gun (xfs/libxfs/xfs_dir2_data.c:868, the P31E detector that READS the
physical daddr before the init zeroes it):
`P31E-DATAINIT-ABA lblk=0 daddr=120 disk_magic=0x58444233(XDB3 block-fmt) disk_owner=131
 live_dirents=14 first_name="." incore_fmt=2 incore_size=4096 dir_gen=2 loaded_gen=2 stale=0 selfc=0
 reused=0 bast_pend=1 ex_gseq=6 dirty_seq=6 comm=dd`
→ block 0 (daddr 120) ALREADY holds 14 live committed dirents on disk, and `xfs_dir3_data_init`
(xfs_dir2_data.c:895 `bp->b_ops=...; Initialize the header`) is about to ZERO+re-init it. **P31E is a
DETECTOR ONLY — it logs then PROCEEDS to zero.** That zero is the durable loss of node1_f1..f14.

### What the fields say:
- `reused=0 stale=0`: in-core does NOT think this is a stale/reused incarnation.
- `ex_gseq==dirty_seq (6==6)`: the dirty fork belongs to the CURRENT EX tenure (NOT a yield+reacquire
  stale-base, sess10 case-b is RULED OUT here).
- `bast_pend=1`: a peer BAST is DEFERRED (MHT batching window active) at the moment of the clobber —
  this node is fast-path-serving an EX MODIFY while the peer waits (sess10 case-a).
- `P32B-DOUBLEMAP=0`: the daddr is NOT mapped at a different lblk by THIS dir's in-core map (not an
  intra-dir double-alloc). So the init is re-creating block 0 the dir already has materialized.
- magic XDB3 = the on-disk block is single-BLOCK-format (xfs_dir2_block); init would overwrite it with
  an empty XDD3 data block.

### Mechanism: during this node's own EX tenure (MHT batch, peer BAST deferred), a dir op
(shortform→block `xfs_dir2_sf_to_block`, or block grow) calls xfs_dir3_data_init on block 0's daddr
which already holds 14 of this node's just-added dirents → zeroes them. NOT the read-side stale-RMW
(the sess36 modify-path-evict retry fix [build 4D56CB92, P36-EVICT-RECOVERED fired 2x but did NOT fix
the loss — KEEP it, it closes a real but different gap]). NOT a yield-reacquire stale base.

### FIX DIRECTION (next session, RULE 4):
The init must NOT zero a block holding live dirents owned by this dir. Options at xfs_dir2_data.c
~857 (where P31E already plain-reads the block + counts `live`): when `isdir && live>0 && down==
dp->i_ino`, do NOT proceed to the get_buf/init zero — instead READ the existing block into bp (xfs_da
read path) and skip the header re-init, so the 14 dirents survive and the caller adds onto them. OR
find WHY the dir op re-inits an existing block-0 (stale in-core extent map / sf_to_block deciding to
create block 0 when block 0 is already materialized on disk under MHT-deferred concurrency) and fix
that root. Verify: re-run drc_cap2.sh MHT=300, grep P31E-DATAINIT-ABA live_dirents (must be 0 with
live>2) AND drc-FAIL=0 across ≥3 runs. Then make MHT=300 default + run full `./run.sh 2 tcp` =17/17.
Marker NOT written. [[sess36-correctness-aba-dirblock-clobber-fix-plan]] [[sess28-dir-data-block-RDMISS-first-block-clobber]]
