---
name: compiled-dir_reuse-intrablock-slot-collision-extentmap-revert
description: sess27 dir_reuse 8/tcp blocker: proven intra-block dir-slot collision + dir extent-map/size revert; read path coherent, loss is write-side.
metadata:
  type: project
tags: [compiled, sess27, dir_reuse_coherency, dir-slot-collision, extent-map-revert, write-side-durability, tcp-dlm]
---

# sess27 (ccloop) — dir_reuse 8/tcp: intra-block slot collision + dir extent-map revert

**Ship state:** 1/2/4-node tcp-DLM dir_reuse_coherency = 100% PASS. **8/tcp is the sole
blocker** — ~50% flaky dirent loss. Keeper build **965BDBD3** (defaults = gen_per_handoff(0)
+ extent_adopt(0)); the working-but-non-default config is modargs
`dir_gen_per_handoff=1 dir_modify_extent_adopt=1`. Cluster left clean.
Harnesses (tests/tcp/): `drc_catch3.sh` (dirwr=1 + DRC_STREAM per-rank NFS dmesg →
drc_cap/stream_rankN.log, ring-rotation-immune), `drc_catch2.sh` (captures the ACTUAL
fail-round dmesg from all 8 nodes), `drc_passrate2.sh` (clears stale markers). `run.sh`
forwards MXFS_TEST_ENV. The dirwr probes P11-DATALOG / P11-POSTADD / P-RELFLUSH dump
per-block dirent-name lists — reuse them.

## The two proven failure shapes (both live at 965BDBD3)

**(1) Intra-block dir-slot COLLISION** [[sess27-SMOKINGGUN-intrablock-slot-collision-off1280-node7-overwrites-node5]].
Byte-exact from stream_rank5.log, round 7, dir block daddr=10466208:
node5 logs+flushes `node5_f46.md5` @ **off=1280** (P11-DATALOG 112.555108, P-RELFLUSH
112.555753 in_ail=1, block dump ends "...node4_f43.md node5_f46.md"); **14 ms later**
(112.569810, same node5 bash thread adding f47 @ off=1312) the block ends
"...node4_f43.md **node7_f47.md**" — node5_f46.md5 GONE. node7's addname picked the exact
slot node5 had just filled and overwrote it → free-space double-allocation. Same root as
sess11 ("dirent bytes logged then vanish").

**(2) Dir EXTENT-MAP / di_size REVERT (whole-block loss)**
[[sess27-CONFIRMED-residual-is-dir-extent-map-revert-not-dirent-content-loss]].
Fresh round-13 capture via drc_catch2.sh: runs 1,2 PASS; run 3 FAIL. The "readdir=799
single-entry" was a **LIE** — `/root/drc_failrounds.txt` lives on the persistent root disk,
is never cleared at run start, so `head -1` returned a PRIOR session's line. Actual RDMISS
from fresh dmesg = **readdir=728** (~72 of node3's entries, ≈ one whole dir DATA block),
durable (LOOKUP_ENOENT + REREAD_MISS), agreed by 6 nodes (1,2,4,5,6,8). **Fix any future
harness to clear /root/drc_failrounds.txt + drc_*.dmesg at run start and read RDMISS from
fresh dmesg, not failrounds.txt head.** Probes: P62-RELOAD-FORK-SHRINK + P26-DSCAN-MISS
(node4/node8 reload the disk on handoff reacquire, post_release=1, and their OWN entries are
"not in any data block" — adopted disk image is missing them). P32-IFLUSH-NXSHRINK fires
but only on comm=rm/EX (rank1's legit rm-rf shrink), not the bug. Net: dir inode data-fork
extent map / di_size REVERTS during concurrent 8-node growth, orphaning whole data block(s).

## Root-cause resolution: the READ path is coherent; the loss is WRITE-SIDE

The session iterated through, and reversed, a read-staleness hypothesis:

- **Read-side detectable staleness — REFUTED** (dirwr=1 round-7 capture)
  [[sess27-REFUTED-four-mechanisms-residual-is-undetectable-content-lostupdate]]:
  P60-GENMATCH-STALE=0, DIR-STALE-SKIP=0, all ~1600 P-TDS-RMW stale_base=0 (dir_gen==
  loaded_gen) + held=1. Also refuted same session: extent-map divergence (P68-MAPDIVERGE=0),
  release-durability (P68-GROWREL STALE-DISK 0 / DURABLE 33-59; dir inode di_size+nx durable
  before unlock via mxfs_dlm_dir_inode_durable @ xfs_mxfs_dlm.c:7424), concurrent-EX /
  double-grant (P-DOUBLEGRANT=0, P-STALEMASTER=0, P106-STALE-EX=0; P-TDS-RMW tenures
  serialize, not interleave).
- **force_coherent=1 — REFUTED, and DECISIVE**
  [[sess27-DECISIVE-loss-is-write-side-force-coherent-doesnt-help]]: forcing every dir-block
  read to FUA-refetch the platter (xfs_da_btree.c:3365) still FAILED (round 1, readdir=788/800,
  wall=497s). Re-reading the platter does NOT recover the entries → they are genuinely NOT on
  the platter → **write-side durable loss**, not read-side stale-base RMW.
- **The FINAL "read-staleness, targeted-reread is the fix" claim — REFUTED**
  [[sess27-FINAL-disambiguation-readstaleness-targeted-reread-is-the-fix]] argued from ONE
  round-7 timeline that the victim was platter-durable before the clobberer picked, so the
  clobberer served a stale cached block, and proposed a scoped coherent re-read of only the
  chosen data block at xfs_dir2_node_addname_int (~1959), gated to a multinode published dir
  and only for CLEAN buffers. This was **overturned** by the two below.
- **The epoch/cache-hit-staleness model — REFUTED**
  [[sess27-CORRECTION-block-is-fresh-read-not-cachehit-epoch-fix-refuted]]: built
  `dir_addname_epoch_refresh` (xfs_dir2_node.c xfs_dir2_node_addname_int, gated default 0,
  build **5B9A014F**); P28-ADDNAME-EPOCHSTALE fired **0×**. P28-CHECK (ino=131, every addname):
  `b_epoch==valid_epoch==master` ALWAYS — dir_gen_per_handoff invalidates on every handoff so
  the addname's read is a cache MISS → FUA re-read → stamped current epoch. The block is read
  FRESH; b_epoch never lags. So it is NOT a stale prior-tenure cache hit — the FINAL
  disambiguation held only for the one trace where node5's RELFLUSH happened to precede node7.
- **DEFINITIVE proof — the platter itself reverts**
  [[sess27-DEFINITIVE-read-coherent-platter-MATCH-loss-is-stale-write-revert]]: build
  **164A6D5D**, param dir_addname_epoch_refresh=1. Probe **P28-PLATTER** FUA-reads the SAME
  daddr from the platter at every node-format addname slot-pick and memcmp's vs the returned
  in-core buffer → **76 MATCH / 0 DIFFER**. The buffer the addname uses to choose a free slot
  ALWAYS equals the platter. So the clobberer's bestfree reflects the platter EXACTLY; it picks
  off=1280 because off=1280 IS free on the platter at read time. Since the victim did add+flush
  it (P11-DATALOG/RELFLUSH), **the platter slot was REVERTED to free by a stale write before the
  clobberer read.** The read is innocent (fully coherent); the bug is a WRITE that puts a stale
  (pre-victim-add) image of the block onto the platter — an ABA / stale-RMW writeback.

Consistent with all of the above: `force_coherent` (read-side) made it worse, `dirskip=1`
(write-suppress) didn't help, `dir_release_fua_write` didn't help,
`dir_release_invalidate=1` FAILED, `inode_mht_ms=600` FAILED. Read-side / durability /
eviction / timing knobs don't touch it [[sess27-HANDOFF-head-state-and-next-step]].

## The design tension: durability ordering, not "re-read more"

[[sess27-SYNTHESIS-slot-collision-needs-durability-ordering-not-more-rereads]]: naive
"force node7 to re-read coherently" fails because force_coherent ALSO re-reads blocks whose
committer's write hasn't reached the platter yet → pulls a stale platter image → reverts that
committer's just-added entry (sess11 "logged-then-vanish"). Net negative (readdir 788 vs 799).
The binding constraint is **durability ordering (Invariant 1 applied to the dir DATA block)**:
node5's release of the dir EX must make the modified data block platter-durable BEFORE the DLM
unlock, so the next holder's read sees the occupied slot. If the block isn't durable at
release → collision; if you force a re-read anyway → you revert node5.

**Concrete coverage gap** [[sess27-LEAD-P11-flush-uncached-release-drain-coverage-gap-create-path]]:
`mxfs_dir_flush_data_blocks` (xfs_mxfs_dlm.c:1599-1625) walks the in-core extent map,
`xfs_buf_incore()` each dir data block, and `continue`s if NOT cached ("not cached => already
on disk"). The code's own P11-FLUSH-UNCACHED comment flags this as a proven hazard. It fires
in the CREATE window (t=102..111, ino=131, comm=dd) on all 8 nodes (r1=12…r8=33). dir_gen_
per_handoff's invalidation clears XBF_DONE on clean blocks → reclaimed → uncached at release
→ skipped. Recurring daddrs across nodes (off=0 daddr=120 = AG0 blk0, off=1 daddr=12559416,
off=2 daddr=10466192…) are node-affine across DIFFERENT AGs; daddr=120 uncached on EVERY node
hints at off→daddr divergence (each node's off=0→120 but it cached a different physical
block). P34-LEAF-DRAIN CACHED=0 also fires heavily (leaf/free blocks uncached at release).

## Next-session plan (RULE 4: catch the reverting WRITE)

1. Instrument the dir DATA-block bio WRITE chokepoint (pal/linux/xfs_buf.c, where
   `mxfs_buf_xfsaild_skip_dir_write` runs) for **node-format** data blocks
   (xfs_dir3_data_buf_ops — P-WRACT is block-format-only and USELESS here), gated ino<=256:
   log per write the daddr + set of live dirents (walk block: freetag==0xffff=free else
   dirent, per xfs_dir2_data.c:833-846) + comm + dlm_mode + b_mxfs_dir_gen/epoch + realns.
   Cross-node by realns: find the write to the victim's daddr whose live-dirent set REVERTS
   (drops the victim on a create-only phase) — its mode/owner/gen identifies the stale writer
   (a node that committed an OLDER image, then its async xfsaild/release-drain wrote it AFTER
   the victim's add landed).
2. Also probe the P11 uncached-skip: at the skip for ino<=256, FUA-read that daddr from the
   platter and compare to the in-core extent map's expectation — if the just-committed dirent
   is absent → confirmed.
3. **Fix direction:** a **content-superset write-guard** at the dir-DATA-block bio write
   chokepoint — suppress/repair a dir-data write whose in-core image is a STALE SUBSET of the
   current platter for the same incarnation (superset, NOT count). For the extent-map revert,
   fence the reverting flush directly (a flush whose extent map is a strict SUBSET of disk for
   the same incarnation while a concurrent grower exists) — **not** dir_modify_extent_adopt's
   BIDIRECTIONAL adopt, which when disk is SMALLER adopts the peer's reverted map and
   PROPAGATES the revert. Don't: union-merge blocks, unconditional per-acquire gen bump
   (re-reads own in-tenure clean blocks = lose work). Note existing
   xfs_dir2_node_addname_int already has the sess22 P22-FREESLOT-STALE repair
   (freeindex-vs-incore-bestfree) but it does NOT catch a bestfree offering an
   occupied-on-platter slot. Also revisit whether lowest-daddr-wins `mxfs_dir_iflush_fence`
   (default 0, marked inert sess65) is needed given the daddr=120 off→daddr divergence.

Build 164A6D5D is keeper-equivalent at default (FUA/epoch probes gated behind
dir_addname_epoch_refresh=1). Capture dirs: tests/tcp/drc_cap/, tests/tcp/loss_cap2/.
