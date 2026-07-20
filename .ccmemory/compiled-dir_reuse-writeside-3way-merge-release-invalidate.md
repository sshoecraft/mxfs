---
name: compiled-dir_reuse-writeside-3way-merge-release-invalidate
description: sess28-29 dir_reuse 8/tcp: EX-holder destages stale in-AIL bgen0 base; write-side 3-way merge refuted, dir_release_invalidate+relinval_clean win ~85%
metadata:
  type: project
tags: [compiled, dir_reuse, cache_coherency, write-side, release-invalidate, tcp-dlm, 8-node]
---

## dir_reuse_coherency 8/tcp — the write-side dirent loss and its fix (sess28-29, ccloop)

Central topic: the sole 8/tcp ship blocker was `dir_reuse_coherency` losing a durable
dirent under concurrent multi-node directory growth. sess28 proved the loss is
**write-side** (not read-side) and pinned the exact mechanism; sess29 refuted the
write-side merge as the fix and landed a **read-side release-invalidation** pair
(`dir_release_invalidate` + `dir_relinval_clean`) that lifts standalone dir_reuse from
~0% to ~85%, with the remaining walls being separate pre-existing shutdowns/hangs.

Working modargs throughout: `dir_gen_per_handoff=1 dir_modify_extent_adopt=1`
(non-default but required baseline). Lock-mode enum: NL=0, CR=1, CW=2, PR=3, PW=4, EX=5.

### sess28: read-side hypothesis raised, then REFUTED as contamination

An early sess28 memory [[sess28-PROVEN-readside-staleness-targeted-platter-guard]]
claimed READ-SIDE staleness, "proven" by a targeted platter guard in
`xfs_dir2_node_addname_int` (build 9074441C, param `dir_addname_platter_guard`): a
`P28W-CLOBBER ... REAL` hit showed the platter holding a live peer dirent
(`pname=[node5_f1.md5]`, pmagic="XDD3", powner==ino, incarn==igen same-incarnation,
clean=1, dir_gen==loaded_gen=52 → missed handoff gen-bump). A read-side fix
`mxfs_dir_addname_coherent_refresh` (build 9AB8E8AE, param `dir_addname_coherent`
default 1) was built for all three addname formats (node/leaf/block), gated on a CLEAN
buffer, with a RULE-0 dedup via a new `b_mxfs_coherent_gen` xfs_buf field, doing a SAFE
invalidate (clear XBF_DONE, brelse, verified cold re-read) rather than an in-place
memcpy — the memcpy form (build E40CD553) was REFUTED (bypasses the read verifier →
shut=3000+ SHUTDOWN cascade). See [[sess28-FIX-allformat-coherent-refresh-platter-groundtruth]].

**That read-side verdict was a CONTAMINATION ARTIFACT.** A surviving background driver
(`drc_diag.sh`, pid 1378265) had been running run.sh concurrently for ~43 min — two
drivers mkfs'ing/writing the SAME shared LUN produced genuine cross-run divergence that
looked like a peer's durable entry at our slot. `pkill -f` on the driver name repeatedly
FAILED to kill it. INFRA LESSON (repeated across memories, cost hours): always
`ps -eo pid,etime,cmd | grep -E 'drc_|run.sh 8 tcp'`, kill the driver PID explicitly, and
verify 0 before trusting any 8-node result.

### sess28: DECISIVE clean-cluster result — the loss is WRITE-SIDE

On a verified single-driver run (build 52EED814, `dir_addname_coherent=1`, DRC_ROUNDS=24),
all 8 nodes: **p28e=300, diff1=0, p28c=0, rdmiss=1, corrupt=0**
[[sess28-DECISIVE-loss-is-writeside-read-coherent-diff0-p28c0]]. `diff1=0` over 300
sampled first-clean-add platter checks means the in-core dir DATA block NEVER diverged
from the platter at addname time — **the read base is always coherent**; the read-side fix
is a DEAD END (`p28c=0` = it caught zero stale bases on a failing run). This confirmed
sess27's write-side verdict. The dirent is added onto a coherent base, then vanishes
durably afterward = a stale dir-block DESTAGE reverts the committed entry.

### sess28: THE mechanism, byte-exact (SMOKING GUN)

The P-WMERGE classifier at the bio chokepoint (`pal/linux/xfs_buf.c::xfs_buf_submit_bio`,
param `dir_writeprobe`, build C1B4BFC0/C71C4EA9) logged `held_mode`, `in_ail`, `dirty`,
`bgen`, `disk_extra`, `incore_extra` for every clobbering dir-data write, NFS-streamed to
survive dmesg ring rotation on the 498s run. Every clobbering write showed
`held_mode=5 (EX) in_ail=1 dirty=0 bgen=0` [[sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded]].

The mechanism, which reconciles read-coherent (diff1=0) with write-side loss:
1. Holder adds A in tenure T1, commits to AIL (base coherent at addname → diff1=0).
2. Holder RELEASES EX.
3. Peer adds B in tenure T2, durable on disk.
4. Holder RE-ACQUIRES EX (T2', held_mode=EX now).
5. xfsaild destages the T1 in-AIL block (base + A, **missing B**) over the disk (base + B).
6. Peer's B is durably LOST.

`bgen=0` = the block's base is a prior tenure (`b_mxfs_dir_gen=0`, acquire-evicted /
never restamped = stale). `incore_extra=1` = holder's own T1 add present;
`disk_extra>=1` = peer adds the stale in-AIL base never saw (test8 saw `disk_extra=154` —
one write about to revert 154 peer entries; test1 daddr=120 pure-stale writes with
`incore_extra=0`).

**Why existing guards miss it:** the `ex_guard`/`P12-DIR-EXGUARD` is gated on
dir-NOT-held-EX, but the holder HOLDS EX at destage → skipped. Acquire-side drain_evict
KEEPS in-AIL-undestaged blocks (can't evict our own committed-unwritten work) → the
stale-base block survives reacquire → destages stale.

### sess28: suppression is the WRONG tool (all variants REFUTED)

- `dir_subset_guard=1` (suppress any write where disk has an inumber in-core lacks):
  CATASTROPHIC **readdir=316/800** [[sess28-REFUTED-subset-guard-overfires-catastrophic-readdir316]].
  During normal concurrent growth, node1's legit write always "lacks" node2..8's
  concurrently-committed adds → suppressed → readdir collapses. Same class as the refuted
  `dir_stale_incarn_skip` (sess22) and "suppression IS the corruptor" (sess23).
- Refined pure-stale-only gate (suppress only `incore_extra==0`): **corrupt=1 SHUTDOWN**
  at wall=91s — the FS/log expects the write; emulating ioend leaves an inconsistency; and
  a legit REMOVE also looks pure-stale (disk_extra=1, incore_extra=0).

The MERGE-NEEDED case (`incore_extra>0 AND disk_extra>0`, both writers have unique
entries) proved the only content-correct fix is a UNION-MERGE (write a superset of both),
not a drop [[sess28-FINAL-writeside-suppression-all-variants-fail-merge-needed]].
sess28's proposed fix was a 3-way merge (base, ours, disk), preferably at REACQUIRE inside
a transaction so the leaf/freeindex hash blocks update coherently (a data-only graft fails
the test's lookup_fail check) — the data-block analogue of the shortform 3-way merge in
`mxfs_dlm_reload_inode`. Keeper handed off at build C1B4BFC0, all sess28 levers default OFF
(behaviorally == prior keeper 164A6D5D) [[sess28-HANDOFF-head-build-C1B4BFC0-next-step-3way-merge]].

### sess29: the write-side 3-way merge was built — and REFUTED

`mxfs_dir3_data_writemerge()` in `pal/linux/xfs_buf.c`, called from `xfs_buf_submit`
before `xfs_buf_verify_write`, param `dir_write_merge`, build BA856D08
[[sess29-write-merge-fix-implemented-build-BA856D08]]. At the chokepoint it FUA-reads the
on-disk image; when both diverge (`ourx>0` AND disk-extra = MERGE-NEEDED) it grafts disk's
name-unique dirents into the in-core block via `mxfs_dir3_data_graft_one` (non-logged byte
surgery + `xfs_dir2_data_freescan` rebuilds bestfree). Logs `P-WMERGE2 grafted=N ourx=N`.
Dedup MUST be by NAME not inumber — v1 (build 51CF6BEE) deduped by inumber and grafted
stale prior-incarnation entries → readdir=845 (45 over-count).

Result: merge fires and lifts early rounds to readdir=800 (from 791 baseline loss), but
carries residuals: **occasional +1 over-count (readdir=801) and lookup_fail=1**. Root of
the over-count [[sess29-GPT-architecture-release-invalidate-is-key-shutdowns-are-wall]]:
the chokepoint sees only the SINGLE block being written, so it grafts a name that already
lives in ANOTHER data block → cross-block DUPLICATE. Whole-dir name dedup is infeasible at
the bio chokepoint. `dir_write_merge` was ABANDONED (default 0, code kept/gated) — the
read-side release-invalidation fix is strictly better.

### sess29: the WINNING fix — release-time invalidation (read-side)

GPT-5.5 RULE-5 consult gave the unifying invariant
[[sess29-GPT-architecture-release-invalidate-is-key-shutdowns-are-wall]]:
> No old-epoch XFS buffer (dirty/pinned/in-AIL/delwri) covered by a DLM resource may reach
> disk after that resource is released. If it can't be drained+invalidated, the unlock
> must NOT complete. FUA reads are NOT a coherency primitive (they read the platter which
> LAGS the target writeback cache → tear). Coherency = DLM exclusion + writer
> blkdev_issue_flush before unlock + local buffer INVALIDATION on release + PLAIN cold-read
> on reacquire.

Two levers deliver it [[sess29-BREAKTHROUGH-dir_reuse-8tcp-4of4-relinval-clean]]:
1. **`dir_release_invalidate=1`** (EXISTING, sess13/19): on dir EX release, `xfs_buf_stale()`
   every clean+durable dir DATA/LEAF buffer it FLUSHES (after a proven-durable bwrite) so
   the next acquire cold-reads coherent. Fixes leaf-content staleness (lookup_fail→0) AND
   eliminates the DABUF_HOLE + xfs_defer shutdowns (they were stale-leaf/extent artifacts).
   Alone = 1 PASS / 3 FAIL (residual single-dirent 799/800 loss).
2. **`dir_relinval_clean=1`** (NEW this session, `xfs/xfs_mxfs_dlm.c` in
   `mxfs_dir_flush_data_blocks` `!needs_flush` branch): release_invalidate only staled
   blocks it FLUSHED; a CLEAN cached but PEER-STALE block (needs_flush=0) was KEPT across
   the handoff → next acquirer RMW'd it stale → dropped a peer's add = the residual 799
   loss. Fix: also `xfs_buf_stale()` clean (XBF_DONE, !dirty !in_ail !pin !delwri) cached
   dir blocks at release (loss-safe: no un-landed work). Lifts ~25%→~85%.

Full winning config: `dir_gen_per_handoff=1 dir_modify_extent_adopt=1
dir_release_invalidate=1 dir_relinval_clean=1`, build D1DD1926 (later 23FE6715, which adds
a gated `dir_flush_lockwait` default-0). All NEW levers default 0 = behaviorally == keeper
C1B4BFC0.

### sess29: pass rate is ~85%, NOT 100% (corrected)

An initial `drc_passrate2.sh 4 → 4/4` was a LUCKY STREAK (0.85^4≈0.52). Combined across
builds D1DD1926 (5 pass) + 23FE6715 (1 pass / 1 fail, round1 readdir=799/800) = **6 PASS /
1 FAIL ≈ 85%** [[sess29-CORRECTED-state-dir_reuse-85pct-not-100-flush-lockwait-harmful]].
The residual ~15% is the IN-TENURE xfsaild destage TOCTOU: relinval_clean fixes the
HANDOFF (release→reacquire cold-read) but not an xfsaild destage of our dirty dir block on
a base that went stale DURING our tenure (peer adds after our last refresh, before our
async destage). Read-side invalidation fundamentally cannot close it. Closing it needs a
write-side transactional RE-APPLY (re-log the delta onto the fresh disk base), NOT the
chokepoint byte-merge (cross-block dup) and NOT a bail (breaks Invariant 1).

### sess29: full 8/tcp suite = 11/17, remaining walls are separate bugs

Full `./run.sh 8 tcp` with the winning config = **11 PASS, then the tail cascades**
[[sess29-full8tcp-11of17-crashconsist-insuite-hang-is-last-wall]]
[[sess29-CORRECTION-cache-coherency-fine-fullsuite-11of17-tail-flaky-dabuf-hole]].
PASS (8/8): precond_readiness, cache_coherency, strong_consistency, posix_multi,
mmap_coherency, dlm_fairness, dlm_membership, scaling_curve, dlm_scaling, rsync_paired,
plus zero_silent_loss OR crash_consistency depending on run (both flaky). The tail walls:

1. **dir_reuse in-suite = DABUF_MAP_HOLE_OK SHUTDOWN** (`xfs_da_btree.c:2876` → Metadata
   I/O Error → Shutdown), distinct from the standalone dirent loss. It is EXTENT-MAP
   staleness (sess20/54 family): a cached `i_df` extent map references peer-freed dir
   blocks so a leaf walk maps bno=1..4 → a hole. release_invalidate+relinval_clean fix
   dirent loss + leaf CONTENT but NOT the extent-MAP, which recurs under accumulated
   in-suite state. Fix dir: rebuild the extent map on EX reacquire
   (`mxfs_dlm_reload_inode` / `dir_ex_stale_refresh` exists — find why it doesn't prevent
   the hole). `dir_postread_reread=1` drove DABUF_HOLE 60→0 in sess20 but TEARS (all nodes
   shutdown round 1, FUA leaf re-read) — REFUTED, do not use.
2. **crash_consistency in-suite HANG** (PRE-EXISTING, sess21's primary blocker; passes
   STANDALONE 8/8 in 30s with the same modargs — proven NOT caused by the dir fixes). ABBA:
   `mxfs_dir_flush_data_blocks` calls a BLOCKING `xfs_buf_incore(...,0,...)` at
   `xfs/xfs_mxfs_dlm.c:1600` while holding `dp->i_lock(read)`; a crash-recovery/peer/BAST
   context holds the dir buffer and needs `i_lock(write)`. Hung-task: two D-state threads
   >491s (BAST kworker `mxfs_dlm_bast_work_fn` + a user bash syscall) both in
   `mxfs_dir_flush_data_blocks+0x39f → xfs_buf_get_map → xfs_buf_find_lock → xfs_buf_lock`.
   Fix STRUCTURALLY: snapshot daddrs under i_lock, flush WITHOUT holding i_lock (like
   `mxfs_dir_drain_evict_data_blocks`); or serialize per-dir flush; NOT a trylock-bail.
3. **zero_silent_loss 0/8** (isolated, new, uninvestigated — check if it's another
   DABUF_HOLE/shutdown or a real silent loss).

`dir_flush_lockwait>0` (bounded trylock-bail in the release flush, meant to break the ABBA)
was REFUTED HARD: bailing a release flush releases stale → violates Invariant 1 →
cache_coherency/strong_consistency/posix_multi 0/8. Code kept, DEFAULT 0, never set >0.

METHODOLOGY BUG (cost ~1hr): `full8.sh` writes stdout to a FIXED path
`tests/tcp/drc_cap/full8_run.log`; polling it during a new run's ~2min reset window reads
the PREVIOUS run's content — a "cache_coherency 0/8 ×4" was ONE genuine
flush_lockwait-run failure re-read 3×. Always `grep run_id= full8_run.log` matches the
current launch before trusting poll results. cache_coherency is FINE with the winning
config (PASS 8/8 standalone and in a clean full suite).

### Net progress and next steps

The 130-session dir_reuse DIRENT-loss blocker is SOLVED standalone (~85%, was ~0%) via
read-side release-invalidation. cache_coherency and crash_consistency both pass standalone.
Full suite 11/17. Remaining to hit `./run.sh {1,2,4,8} tcp` 100%:
(a) close the residual ~15% in-tenure TOCTOU with a reacquire-time transactional re-apply;
(b) fix the dir_reuse in-suite DABUF_MAP_HOLE via extent-map rebuild on reacquire;
(c) fix the crash_consistency ABBA structurally (drop i_lock across the buffer get);
(d) investigate zero_silent_loss; (e) make the 4 levers module DEFAULTS and re-verify
1/2/4/8 tcp full suites. GPT's #3 (AG-EX lifetime through `xfs_defer_finish`, GFS2/OCFS2
rgrp model) is the direction for the `xfs_defer 0x8` double-alloc shutdown family.

Tools (tests/tcp/): `drc_passrate2.sh N "MODARGS"` (dir_reuse reliability),
`full8.sh N "MODARGS"` (full suite), `drc_one.sh` / `drc_diag.sh` / `drc_platter.sh` with
`DRC_STREAM=1` (NFS stream beats dmesg ring rotation on long runs). Always confirm a clean
baseline (drc_passrate2 dir_reuse PASS) and no surviving background driver before trusting
any 8-node result.
