---
name: compiled-sess59-60-4node-tcp-dir-reuse-readdir-miss-writer-clobber
description: sess59-60 4-node TCP dir_reuse_coherency (16/17): crash fix + readdir gen-bump; residual = durable writer-side node1_f1 dirent lost-update.
metadata:
  type: project
tags: [compiled, dir_reuse_coherency, tcp, 4-node, readdir-miss, durable-lost-update, cache_coherency, ship-blocker]
---

## sess59-60 — 4-node TCP `dir_reuse_coherency`: readdir-miss → durable writer-side dirent lost-update

Central topic: the **sole remaining failure** when scaling the MXFS TCP suite from 2 to 4 nodes.
Criterion `dir_reuse_coherency` (tests/suite/dir_reuse_coherency.sh) is transport-INDEPENDENT
and is the same family as the CAW `cache_coherency` ship blocker (sess79-92, sess43-58) — fixing it
on cheap LIO/TCP directly unblocks SCST/CAW. Config: NFILES=50, ROUNDS=24, EXP = 2*NODES*NFILES
= **400 entries/round at 4 nodes** (was 200 at 2). At 2 nodes TCP this criterion PASSED
(sess58 17/17); 4-node concurrency exposes the bug — the mechanism is concurrency-fragile, not
node-count-robust.

### sess59 — first fail + three superseding diagnoses (RULE 4 loop)
`./run.sh 4 tcp` (build **60EFBE5E**) = **16 PASS / 1 FAIL**; sole fail = `dir_reuse_coherency`
(0/4, systematic, NOT a sess58 regression). All sess58 transport-independent inode-lock fixes
(AG↔dir ABBA + ilock_nowait resurrection in xfs/xfs_inode.c) HOLD at 4 nodes. Symptom: on ALL 4
nodes an entry (e.g. round 14 `node3_f18.md5`, round 18 `node4_f35`) is
`missing_from_readdir (399/400)` but `lookup_fail=0` — in leaf-hash, absent from readdir
enumeration; even the creating node misses its OWN entry after drop_caches. Also TIMED OUT at
round 18/24 (TEST_TIMEOUT=300): 400 cold-cache lookups/round + `EVICT-RING-DIRMOD` storm blew the
budget. dmesg: NO EFSCORRUPTED/shutdown; shared dir ino=5481, fmt=1 (block), DLM cache 99% hit.
Do NOT run 8-node (EXP=800, worse). See [[sess59-4node-tcp-16of17-dir-reuse-coherency-fails]].

Diagnosis progression (each superseded the last):
1. **Stale-disksize / gen-equal** [[sess59-drc-readdir-miss-stale-disksize-gen-equal]]: P62 probe
   showed reader in-core dir `incore_size=8192` (2 blocks) vs `disk_size=12288` (3 blocks) with
   `incore_gen==disk_gen`; hypothesis = `i_dlm_dir_gen` not bumped on the dir-GROWTH path, so
   gen-gated reload skips and readdir enumerates by stale smaller i_disk_size while the
   size-independent da-btree hash still resolves lookup. Reproducer built:
   **tests/tcp/drc4_repro.sh** (KEEP) — N-node standalone, no MQTT; the key is CONCURRENT
   cold-read (parallel ssh drop_caches+readdir) matching the suite coord_barrier. Sequential v1 =
   20 rounds clean (race masked, self-heals <1s); concurrent = FAIL. `bash tests/tcp/drc4_repro.sh 4 50 24`.
2. **Grantless-NL async-evict latency** [[sess59-drc-root-grantless-readdir-async-evict-latency]]:
   readdir triggers `mxfs_dlm_reload_inode` (xfs_dir2_readdir.c:638) ONLY if `MXFS_IF_DIR_RELOAD`
   set OR `i_dlm_dir_gen > i_dlm_dir_loaded_gen`; both triggers are delivered SOLELY by the async
   eviction ring (`mxfs_dlm_evict_inode_cb`, run by the disklock heartbeat MONITOR thread). A
   grantless NL reader on a SHARED dir takes NO DLM grant (never BAST'd, xfs_mxfs_dlm.c:12707), so
   at concurrent barrier-release the peer's DIR_MODIFY hasn't arrived → readdir enumerates stale
   in-core size → misses trailing-block entries; ~1s later HB delivers → reload → correct. An
   eventual-consistency gap = FAIL by [[feedback_timing_is_failure]]. Refuted fixes (do NOT
   repeat): tightening heartbeat/DIR_MODIFY latency (500ms WEDGES, 1000ms only ~1/3 clean); a
   per-readdir disk poll on all dirs (sess38/91 perf regression, must stay event-driven for solo
   dirs). Candidate directions: gated synchronous dir-version FUA check for contended dirs
   (i_dlm_dir_gen>0) only; or readers take a real PR grant (heaviest, RULE-0 risk).
3. **CORRECTED root — durable dirent lost-update** [[sess59-drc-CORRECTED-root-durable-dirent-lost-update]]
   (supersedes both above). Decisive classification via drc4_repro.sh round 4 (build **39D3BA93**):
   missing `node2_f20` on ALL 4 nodes was `LOOKUP_ENOENT REREAD_MISS` — NOT lookup-able (stat→ENOENT),
   a SECOND readdir still missed it, absent even on node2 its own creator. So it is a **DURABLE
   dirent LOST-UPDATE under concurrent same-dir create**, not a visibility/enumeration miss. The
   P62 size divergence was a transient reload snapshot; lookup was never verified. Approach A
   (synchronous FUA dir-version check in xfs_dir2_readdir.c) was **REVERTED/disproven**
   (P59-RDSYNC ahead=0). drc4_repro.sh kept, now classifies misses LOOKUP_OK/ENOENT +
   REREAD_SHOWS/MISS. New hypothesis handed forward: a dir-block RMW that adds a dirent reads a
   STALE cached dir DATA/leaf block and on writeback clobbers the peer's entry — review prior
   partial fixes (drain-before-unlock invariant #1, mxfs_dlm_dir_durable_signal, sess83 F08CE615,
   sess88 73B57CCD) before patching.

### sess60 — two fixes landed, one residual
Criterion target = 1/2/4/8 node TCP 100%. State: 1/tcp 16/16, 2/tcp 17/17, 4/tcp blocked on
`dir_reuse_coherency`, 8/tcp never run. See [[sess60-crash-fix-and-readdir-genbump-progress]].

**FIX 1 (KEEP, PROVEN) — kernel crash, build F5D370D8.** 4-node dir_reuse crashed nodes with
`BUG at fs/inode.c:1798` (`BUG_ON(i_state & I_CLEAR)`) in `iput`, from the trailing `xfs_irele(ip)`
in `mxfs_dlm_bast_work_fn` (mxfs-ino-bast kworker). Root (proven: P-IGRAB-NULL site=EDEADLK +
P-BWFN-PREIRELE i_count=0 i_state=0x60 I_CLEAR=1): the EDEADLK self-demote (xfs_mxfs_dlm.c ~9903)
and ACQBAST-HONOR (~10139) queue sites call `igrab(VFS_I(ip))` on a REUSED dir inode mid-eviction
(I_FREEING|I_CLEAR=0x60); igrab returns NULL, the NULL was IGNORED, bast_work_fn queued anyway, and
its unconditional xfs_irele dropped a ref never taken → phantom-bast UAF. FIX: EDEADLK — if igrab
fails, drain INLINE via `i_dlm_demoter=current; mxfs_dlm_bast_process(ip)` (re-entrant-safe via
demoter) then recurse; ACQBAST — if igrab fails, skip the queue; PLUS backstop in bast_work_fn:
skip xfs_irele if i_count<1 or I_CLEAR. Result: 0 crashes.

**FIX 2 (KEEP, partial) — reader-side stale dir-block, build A1419A72.** With the crash gone, the
residual readdir miss (399/400, lookup_fail=0) root (P26-RDDIR): reader holds a CACHED PR mode=3,
`i_dlm_dir_gen` stuck at 1, disk_size==incore_size — peers add dirents into an EXISTING data block
(no di_size growth), and the only producers that bump the reader's dir_gen are the async evict-ring
+ slow-path reacquire; a fast-pathed cached PR hits neither, so xfs_da_read_buf's read-time
invalidation (re-read cached block only if `b_mxfs_dir_gen < i_dlm_dir_gen`) never fires. Size-based
Approach A REFUTED again (P60-RDSYNC=0, miss is SAME-SIZE). FIX (xfs/xfs_dir2_readdir.c ~667): on
readdir of a contended (dir_gen>0) non-EX dir, `dp->i_dlm_dir_gen++` to force xfs_da_read_buf to
re-read all dir blocks from the durable platter (P60-RDGEN probe). Reduced failures from every-round
(~8 by round 5) to ~1-2/20 (round 12).

**RESIDUAL (the real remaining blocker) — writer-side DURABLE lost-update.** Build **EB619331**
adds a suite `mxfs-drc-CLASS` diagnostic. `./run.sh 4 tcp dir_reuse_coherency` FAILs intermittently
(1-2 rounds per 12-21), always **node1_f1** (rank1's FIRST file in the freshly-recreated dir).
Decisive classification (round 4, ALL 4 nodes incl creator test1):
`mxfs-drc-CLASS name=node1_f1 LOOKUP_ENOENT REREAD_MISS` → the dirent AND its leaf-hash entry are
DURABLY ERASED everywhere; the INODE exists (dd created it) but the dirent is gone from both leaf-hash
and data block = orphaned inode. See [[sess60-residual-writer-side-durable-node1f1-clobber]].

REFUTED this session (all instrumented, do NOT repeat): reader-side size-grow (P60-RDSYNC=0);
reader gen-MATCH clean stale-serve (P60-GENMATCH-STALE=0); reader gen-MISMATCH kept-stale dirty/pin
(DIR-STALE-SKIP=0, P133=0); release-side drain gap (bast_process flushes dir data ~xfs_mxfs_dlm.c:4546);
double sf→block conversion (P42-SFCONV: one converter per incarnation); conversion-drop
(P60-SFCONV-BASE); P58 reload self-skip (=0).

**dataclobber=2 REFUTED** [[sess60-FIX-CANDIDATE-enable-dataclobber-2]]: `MXFS_EXTRA_MODARGS='dataclobber=2'`
(build EB619331) made failures WORSE (drcFAIL=3-5 per node by round 7 vs ~1-2 total) while
P-DATACLOBBER-SKIP fired only ONCE across 7 rounds — the stale-tenure writeback guard almost never
catches it (dc_stale `b_mxfs_dir_gen < i_dlm_dir_gen` rarely true), so the clobber is a
**CURRENT-TENURE write** (bgen == dir_gen), and the disk-read-per-dir-write perturbs timing and
exposes MORE races. dataclobber stays default 0. The sess40 ABA writeback skip
(P40-INCARN-ABA-DIRSKIP, pal/linux/xfs_buf.c:2119) also misses it — the clobber writeback has
bincarn==cincarn (SAME incarnation), a CURRENT-incarnation STALE-TENURE block flushed by xfsaild.

Two competing framings of the current-tenure clobber remain open:
- **Writeback stale-tenure flush**: a STALE dir block0 buffer (cached before a peer's intra-incarnation
  modification) is flushed over the peer's newer committed block0, erasing node1_f1. NEXT: instrument
  the dir-block WRITEBACK path (pal/linux/xfs_buf.c near ~2119 and the xfs_buf_submit dir-data branch
  ~2500) — on submit of a dir DATA/leaf block0 log owner ino, daddr, `b_mxfs_dir_gen` vs `i_dlm_dir_gen`,
  `b_mxfs_dir_incarn` vs i_generation; prove the stale-tenure writeback, then suppress/redirect it
  (careful of sess32 AIL-wedge risk) or invalidate at the BAST/gen-bump point. Lineage:
  sess16 stale-tenure keepguard, sess28 first-block clobber, sess40 ABA-refuted.
- **block0 logical→physical SPLIT (sess42)**: node1_f1's dirent lives in a data block at a different
  fsb than the home dinode's logical-0 resolves to (extent-map divergence across nodes, sess42 saw
  node1 fsb15 / node2 fsb14); leaf hash maps to logical-0, and if logical-0 points to the WRONG
  physical block both lookup and readdir miss it — explains LOOKUP_ENOENT+REREAD_MISS with NO
  read/write staleness probe firing. Called the strongest untried lead given everything else refuted.
- Also: free-space/bestfree miscompute (a current-gen block0 RMW computes freespace from a base
  missing node1_f1's slot and places a new entry over it — instrument xfs_dir2_data_use_free/bestfree);
  or transaction-level concurrent dirent-add bypassing gen invalidation.

### Perf (parallel RULE-0 concern)
~13s/round × 24 ≈ 312-320s vs TEST_TIMEOUT=300 → the criterion will timeout near round 23 even when
fully coherent. Per-round cost (4-node cold readdir + ~400 igets + rm + MQTT barriers) must be cut.
ROUNDS/timeout are not scaled for node count.

### Operational notes
- Reliable repro = `./run.sh 4 tcp dir_reuse_coherency` (suite, TIGHT MQTT barrier). drc4_repro.sh's
  looser timing masks it (often 16/16 clean) — use it for classification, the suite for reproduction.
- Detect completion via log `=== done:` marker; `pgrep -f "run.sh 4 tcp"` is UNRELIABLE (matches the
  Monitor's own until-loop).
- Reset cluster: `virsh -c qemu:///system destroy+start test1-4`. Builds deploy to test1-4 via NFS insmod.
- Build progression: 60EFBE5E (16/17) → 39D3BA93 (classifier) → F5D370D8 (crash fix) →
  A1419A72 (readdir gen-bump) → EB619331 (drc-CLASS diagnostic, current head). KEEP all fixes;
  dataclobber default 0.
