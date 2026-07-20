---
name: compiled-bnobt-inode-double-alloc-ccloop
description: Compiled: ccloop cache_coherency bnobt double-free / inode double-alloc root chain, write-side stopgaps, and AG-lock fence design.
metadata:
  type: project
tags: [compiled, cache_coherency, bnobt, inode-double-alloc, ag-meta, ccloop, fence-invariants]
---

# Compiled: bnobt double-free / inode double-alloc — ccloop cache_coherency blocker

All memories below are the single ccloop run **4eef1f39**. The ship blocker is the
`cache_coherency` criterion (`tests/criteria/cache_coherency.sh --nodes 4`, subtests
`cross_visibility` / `rename_visibility` / `unlink_visibility` / `cross_write_read`).
The recurring corruption is a **durable AG-meta lost-update**: an on-disk inode owns a
block the bnobt lists free → `xfs_free_ag_extent` trips `ltbno+ltlen>bno`
(xfs/libxfs/xfs_alloc.c:2244) → EFSCORRUPTED shutdown; and its sibling, **inode
double-allocation / type-flip** → `inobt record corruption` → `xfs_difree_inobt -117`
shutdown. Signature across ~50 sessions: `P47-INACT DISK-LIVE-same-gen`, `P81-DEXT
disk_claims_freed=1`, `P28 disk_differs=0 in_ail=0` (durable, not in-flight).

## The two mechanism families (deduplicated)
- **Write-side revert-clobber (AG free-space trees).** `xfsaild` flushes a PRIOR-TENURE
  stale bnobt/cntbt buffer (in-core `nr=1` pristine) OVER a peer's durable split
  (`disk_nr=2`). Root cause named in [[sess117_lessons]]: **AIL item removal is
  log-tail/checkpoint-driven, NOT buffer-writeback-driven** — a drained-and-bwritten
  clean bnobt buffer stays `in_ail=1` across an AG tenure boundary; a peer commits a
  newer alloc; the read-hook sees `in_ail=1` and *protects* the now-stale buffer;
  xfsaild re-flushes it. Clobber state is invariant: `in_ail=1 dirty=0 pin=0 delwri=0
  held=1 buf_gen==pag_gen`, `comm=xfsaild`, `disk_nr>buf_nr`. Confirmed identically in
  [[sess121-bnobt-clobber-writeside-fix]].
- **Read-side incoherent alloc (inobt + inode-cluster).** The allocator carves an inode
  the *coherent* disk shows already LIVE — proven decisively in
  [[sess24-PROVEN-inobt-incoherent-at-alloc]] (detector P-IALLOC-DBLALLOC, gated
  `mxfs.dbg_ialloc_dblcheck=1`): on a clean 4-node reset, `test_cross_visibility` carved
  ino=4194432/6291584/2097280 whose coherent-disk `di_mode=040755` (live directories).
  ⇒ the inobt free-space view is incoherent with the durable inode-cluster dinode at the
  allocation boundary. Two non-exclusive sub-mechanisms: (1) STALE inobt on this node
  (acquire coldread_discard hole or nested-hold never re-read); (2) UNDRAINED
  inode-cluster on FREE — `xfs_inode_buf_ops` cluster/dinode blocks are in NEITHER the
  AG BAST drain set (`mxfs_dlm_ag_drain_meta_buffers` ~7336) NOR the acquire
  `mxfs_ag_meta_coldread_discard` (~5583), both of which cover only
  AGF/AGFL/AGI/bnobt/cntbt/inobt/finobt. This is sess102's known **"Gap (c)"**, restated
  in [[sess24-ccloop-double-alloc-2consults-W2-gap-c]] as **W2**.

Triggering workload: 4 nodes race `mkdir -p .mxfs_test/<sub>` (same name), each allocs a
candidate dir inode in its OWN affinity AG; EEXIST-losers free their candidate; the
free's dinode-clear isn't durable before the AG/inobt releases → re-carve sees inobt-free
but dinode-live. Same-chunk same-gen proves it (`incore_gen==disk_gen==2964760501` on
ino=4194435): equal gen rules out legit reuse (reuse bumps gen) ⇒ two independent
allocations carved the same inode/chunk ([[sess24-ccloop-double-alloc-2consults-W2-gap-c]]).

## Build / fix progression (chronological)
- **3CBB2553** ([[sess117_lessons]], KEEP): first bnobt double-free FS-shutdown fix —
  release-side stale of CLEAN bnobt/cntbt (P117-AGMETA-STALE-CLEAN), gen-independent
  acquire-side discard on fast reclaim paths (P117-COLDREAD-DISCARD), read-hook discards
  previous-epoch in-AIL clean artifact (P117-INAIL-STALE-ARTIFACT). Killed the
  catastrophic `ltbno` shutdown; runs got FAST. BUT lost-update content-revert stayed
  FLAKY (P93 still fired 2-6×/run). Read-hook fired 0× — xfsaild WRITES before any
  allocator READS, so the read-hook is the wrong place; **the real fix must be at YIELD
  (evict), not READ.** User APPROVED the HARD CACHE-BARRIER re-architecture here.
- **82BB2A09** ([[sess120_lessons]], KEEP): cache_coherency 1/4 → 3/4 (cross/rename/cwr
  PASS, only unlink_visibility fails, zero corruption). Fixed a P110(keep)-vs-P117(discard)
  contradiction on the SAME in-AIL bnobt/cntbt buffer (EEXIST-loser self-corrupts its own
  affine AG — single-node self-clobber, AG affinity holds). Fix = new LSN discriminator
  **`mxfs_buf_is_undestaged(bp)`** (xfs_mxfs_dlm.c ~4944): `calc_crc` stamps
  `bb_lsn=li_lsn` at write-submit only; `li_lsn` advances earlier at CIL→AIL, so
  `in_ail && XFS_LSN_CMP(li_lsn,payload_lsn)>0 → un-destaged`. Verified vs kernel
  xfs_btree.c:454. Gated the sess117 P117 discard with `&& !mxfs_buf_is_undestaged(cbp)`.
- **E9963FFA** ([[sess121-bnobt-clobber-writeside-fix]], KEEP): the **P122 write-side
  interlock** at `xfs_buf_submit()` (pal/linux/xfs_buf.c) — the only chokepoint that
  catches xfsaild. Guard: bnobt/cntbt write + `disk_nr>nr` + `in_ail && !dirty && !pin &&
  !delwri && !mxfs_buf_is_undestaged`. Action: refresh `b_addr` from coherent cache via
  `mxfs_pal_bdev_read_plain_bdev` (PLAIN bio hits the peer-visible SCST write-back cache;
  FUA reads the STALE platter under `fua_disable=1`), then `xfs_buf_ioerror(bp,0)`/
  `xfs_buf_ioend` — completes writeback as SUCCESS (removes BLI from AIL, advances log
  tail) WITHOUT the stale physical write; refresh-fail → `xfs_force_shutdown`. Result:
  `ltbno=0 shutdown=0` all nodes (was EFSCORRUPT @235s). Remaining: rename_visibility
  TIMES OUT on concurrent DIRECTORY-op coherency (`.mxfs_barriers/<name>` dir not visible
  cross-node).
- **57B04634** ([[sess19-local-unlink-flag-reuse-hole]], KEEP but incomplete): traced a
  double-free to test1 inactivating a PEER's LIVE inode (ino=4194443 = node3's file) via
  a **torn in-place reload of a reused inode#**. Added `MXFS_IF_LOCAL_UNLINK (1U<<19)`
  (xfs_inode.h, in XFS_IRECLAIM_RESET_FLAGS), set in xfs_droplink at nlink→0 and in
  O_TMPFILE/orphan iunlink callers; xfs_inactive guard **B3** skips destructive
  inactivation when `!local_unlink && coh_nlink>0` (coh_nlink via PLAIN-bio
  `mxfs_dbg_disk_di_nlink_coherent`). THE HOLE: XFS_IRECLAIM_RESET_FLAGS only clears on
  iget-RECYCLE, not on a DLM in-place reload, so the stale flag makes B3 wrongly proceed.
  NEXT (one edit): clear the flag at TOP of `mxfs_dlm_reload_inode` (xfs_mxfs_dlm.c ~2678).
- **51755ECD** ([[sess19b-shared-epoch-design]], KEEP): implemented the **shared on-disk
  AG epoch** — `pag_dlm_meta_gen` now driven from CAW `slot.generation` (was FROZEN at 1,
  which silently defeated every gen-based read-invalidation check across the whole
  history). Fresh-acquire (~6945): `disk_gen != pag_dlm_disk_gen_seen` → `gen++` + clear
  AGF_INIT/AGI_INIT (rebuild pagf/pagi from re-read). **ELIMINATED the AGF
  longest>freeblks write-verify shutdown** (was 2/4 every run; root was an own edit-B
  reclaim-path AGF_INIT reset pulling pagf backward). ltbno double-free went
  constant→INTERMITTENT. cache_coherency still 1/4: the remaining shutdown is the
  **allocation-side** bnobt-lost-update (inode owns X, bnobt frees X) — the mirror of P93
  that P122/P93 do NOT cover (they catch only the xfsaild SPLIT-revert direction).
- **C91DECFC → C2AD9E9D** ([[sess22-ccloop-inv2-fresh-acquire-coldread-hole]]): PROVEN the
  bnobt clobber is an **Inv-2 acquire-invalidation-fence FAILURE, not exclusion
  divergence** (probe P125-AG-DIVERGE fired 0× → we DO hold the AG on-disk at the stale
  write). THE HOLE: the three reclaim acquire paths (~6722/6781/6804) call
  `mxfs_ag_meta_coldread_discard`, but the **genuinely-fresh CAW-grant path** (after
  `mxfs_v5_dlm_ag_lock` ~6921) bumps the epoch + clears AGF/AGI_INIT but NEVER calls
  coldread_discard → cached bnobt/cntbt aren't bulk-invalidated. Fix in progress: add
  `fresh_peer` arg to coldread_discard, discard in-AIL bnobt/cntbt when
  `(fresh_peer || !undestaged)`; 3 reclaim sites pass `false`. Build compiles but NOT
  behaviorally complete — the ONE remaining edit is to call
  `mxfs_ag_meta_coldread_discard(pag, true)` on the fresh CAW-grant path AFTER
  `pag_dlm_lock` is released. Directive this session: implement the RE-ARCHITECTURE, not
  more write-side band-aids (P124 generalized suppression REGRESSED to 0/4 + new
  in-memory-corruption shutdown — refreshing one bnobt buffer desyncs sibling cntbt/AGF).
- **2C16B9C9** ([[sess23-ccloop-suppression-was-corruptor-3of4]], KEEP): **the P122/P93
  write-side suppression was itself the CORRUPTOR.** `mxfs_suppress_stale_agwrite`
  (pal/linux/xfs_buf.c ~2190) skipped a bnobt/cntbt write whenever `on-disk numrecs >
  in-core numrecs`, assuming stale prior-tenure revert. That discriminator is
  fundamentally broken: **numrecs legitimately DECREASES** on a coalescing free (3 recs
  merge to 1) and on an exact-match alloc. Suppressing a correct-and-ahead in-core write
  left on-disk bnobt at nr=3 while cntbt+AGF freeblks landed → torn AG-meta set →
  `xfs_agf_verify` freeblks-mismatch shutdown AND in-core `ltbno` double-free later. FIX:
  stopped setting the suppress flag (P93 stays LOG-ONLY). Acquire-invalidate + release-
  drain fences proven TIGHT this run (P79=0, P14=0, P47-preserve=0, P126=0), so no stale
  buffer reaches the write side — suppression was unnecessary AND harmful. Result:
  cache_coherency **0/4 → 3/4** (cross/rename/unlink PASS; only cross_write_read FAILS,
  1-2 of 6 assertions/node, all node1-related — a DIFFERENT reg-file
  writer-durability/reader-staleness path).
- **1F7AF33C** ([[sess24-PROVEN-inobt-incoherent-at-alloc]]): ROOT of the inode
  double-alloc/type-flip PROVEN (P-IALLOC-DBLALLOC, see mechanism above). Primary
  candidate fix = **W2 release-side**: add `xfs_inode_buf_ops` to the AG BAST drain set so
  a freed/allocated inode's cluster dinode is platter-durable BEFORE the AG (and its
  inobt) releases. KEEP the P-IALLOC-DBLALLOC detector (gated off) as the regression gate.

## Reality check on "3/4" (variance)
[[sess24-ccloop-double-alloc-2consults-W2-gap-c]]: a fresh `cache_coherency.sh --nodes 4`
on build 2C16B9C9 gave **passed=0 failed=4** — the sess23 "3/4" was a lucky run. The
criterion is HIGH-VARIANCE / cumulative-fragile; `cross_write_read` and `cross_visibility`
PASS in ISOLATION and fail only in the cumulative sequence. The double-alloc fires even on
a passing isolated run — it's just not always fatal. Corollary lesson ([[sess117_lessons]]):
do NOT trust a single PASS; require ≥3 consecutive clean runs. A second concurrent blocker,
**SESS50-STARVE** (per-inode EX-vs-PR convoy on shared-dir inodes 128/132/136 → 120s
barrier timeouts), fires 4-7×/node and is a SEPARATE timing failure.

## The architectural verdict (read before band-aiding again)
[[cache-coherency-rearch-provenance-and-gap]]: the cache_coherency **re-architecture** is a
three-fence-invariant design (provenance: **Grok+Gemini+Claude 2026-06-06**, NOT GPT-5.5 as
[[sess96_gpt_fix_design]] mis-attributes; problem statement in
`/src/mxfs/CACHE_COHERENCY_ISSUE.md`):
- **Inv 1** — DLM EX release/demote is a real checkpoint fence: every protected buffer must
  reach the shared target AND be clean/non-pinned/not-an-AIL-obligation before unlock;
  writeback fail → shutdown (no best-effort).
- **Inv 2** — slow-path EX acquire is an invalidation fence: bump gen, stale cached bufs,
  re-read before first use.
- **Inv 3** — the "keep stale & continue" (DIR-STALE-SKIP) branch becomes FATAL.
- Load-bearing footnote: **the same fence applies to AG locks (AGF/AGI/AGFL/bnobt bufs).**

Key finding: the fence was implemented for **dir/inode locks** (sess88→99→103→107) and
WORKED (rename/unlink/cross_visibility pass), but was **NEVER applied to the AG/allocation
locks** — that omission IS the bnobt double-free. The last ~dozen sessions (incl. ccloop
sess19-24) band-aided it with write-side interlocks (P122 split-revert, P124 alloc-revert,
suppression) instead of fixing the lock-handoff layer; **P122/P124 are STOPGAPS that
RELOCATE the failure, not fix it.** Applying Inv-1's synchronous drain rigorously EXPOSED a
§6 structural lock-inversion (the drain runs in the BAST kworker but must flush buffers
owned by XFS's own b_sema/ILOCK/xfsaild that the kworker can't reach → root-inode ino=128
cluster buffer wedge → liveness hang, sess109-113). The architected answer:
GFS2-glock-style (`inode_go_sync`/`inode_go_inval`) **relocate WHERE the release drain
runs** — make the DLM strictly outermost, or move the drain into the context that already
owns ILOCK — PLUS fix the frozen `pag_dlm_meta_gen` so Inv-2 fires for AG-meta (the
[[sess19b-shared-epoch-design]] shared-epoch, delivered in build 51755ECD).

## Recurring failure modes / do-NOT-repeat
- Frozen `pag_dlm_meta_gen`=1 silently defeated all gen-based invalidation for the entire
  history until 51755ECD wired it to the CAW slot generation.
- CIL→AIL runs on a background kworker AFTER `xfs_log_force` returns, so a just-committed
  bnobt buffer can be unpinned-but-not-yet-in-AIL and look "clean" → drain SKIPS it. Prior
  msleep+double-log_force+`ail_push_all_sync` attempts made it WORSE (2/5 vs 3/5);
  whole-AG `xfs_ail_push` deadlocks cross-AG (sess18/39/111). Do NOT naively retry a
  whole-AG ail_push ([[sess24-ccloop-double-alloc-2consults-W2-gap-c]]).
- Write-side numrecs suppression is broken by legit coalescing (nr decreases legitimately);
  it corrupted the AG-meta set ([[sess23-ccloop-suppression-was-corruptor-3of4]]).
- P124 generalized suppression regressed to 0/4 (refreshing one bnobt desyncs siblings)
  ([[sess22-ccloop-inv2-fresh-acquire-coldread-hole]]).
- Reg-file empty-content on cross_write_read / rename (`expected='content_4_20' actual=''`,
  verify ~373-952ms so NOT slowness) is a DIFFERENT dir/inode durable lost-update path —
  don't conflate with the AG bnobt fix.

## Infra / methodology (all memories agree)
4 nodes test1-4 under `virsh -c qemu:///system` on host clyde. ALWAYS power-cycle
(`destroy+start` ALL 4, wait ~60-90s NFS) THEN `bash tests/reset4.sh 4` (takes a node
COUNT) before trusting any result — back-to-back runs lie; module "File exists" on insmod
means a killed run left it loaded, requiring the power-cycle. Confirm srcversion on all 4,
`dmesg -C` all, then run. Healthy cache_coherency ≈ 20-60s; run with ~120s cap (NOT 700s —
a generous timeout masks slowness which is itself a FAIL); tighten MXFS_BARRIER_TIMEOUT
(tests/lib/cluster.sh L11). Detectors P-IALLOC-DBLALLOC, P125-AG-DIVERGE, P117/P110, and
scripts repro_double_alloc.sh / repro_blockdir_visib.sh are KEEP (gate off / regate to
`mxfs_idbg` before ship). Run one subtest alone with
`MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 4
--phase cluster --test test_<name> --pass-file /tmp/.mxfs_pass --device /dev/sda
--mount-point /mnt/shared`.
