---
name: compiled-posix-multi16-dir-corruption-early
description: Compiled sess51-58: multi16 shared-dir shutdown faces — stale extent/di_size, block/leaf self-skip lost-update, AGI stale-head.
metadata:
  type: project
tags: [compiled, posix-multi16, dir-coherency, lost-update, agi-iunlink, bnobt-double-alloc, shutdown]
---

# Early posix_semantics_multi16 shared-dir corruption faces (sess51–58)

Central topic: the sole failing ship criterion through this arc is
`posix_semantics_multi16` (`elapsed>600s`, hard 600s cap in
tests/criteria/posix_semantics.sh). The 600s timeout is a *symptom*: FS
**shutdowns** under a 16-node concurrent shared-dir storm → every test barrier
hangs 120s → budget blown. Across sessions the storm exposed *multiple
independent shutdown faces*, all in the shared-directory coherency + AG-metadata
paths, plus a durable dirent lost-update that produces silent loss with no
shutdown at all. `.criteria_results.json` is source of truth (18–19/19 PASS,
this is the lone hold-out); the `p` prompt file was repeatedly STALE (kept
naming `cache_coherency`, which PASSES — 4-node load rarely frees+reuses chunks
fast enough to trip these).

## Repro harnesses (KEEP)
- `tests/repro_agi_unlink_storm.sh 16 [ROUNDS]` — 16 nodes create + rm-rf
  40 dirs/node × 8 files across 4 shared parents (inodes 128/131–136); shutdown
  in round 1–3. HIGH VARIANCE: different runs hit different faces. MUCH faster
  than the full cluster phase. Requires `tests/reset4.sh 16` first. Introduced
  [[sess53-agi-insert-stale-head-shutdown-fix]].
- `tests/criteria/zero_silent_loss.sh --iters 1 --dpn 100 --mode 1` (~90s
  single-iter storm) — the reliable durable-lost-update repro (silent=11..1600
  pre-fix). `tests/repro_dirent_loss.sh` / `_heavy.sh` are TOO LIGHT (1 file or
  K/node), rarely fire — use the single-iter storm. [[sess58-durable-lostupdate-selfskip-blockleaf-dir-rootfix]]
- Cluster phase: `INSMOD_OPTS="dirwr=1" POSIX_PHASE=cluster bash tests/criteria/posix_phase_timing.sh --nodes 16`; standard opts `fua_disable=1 instr=0`.

## CRITICAL INFRA LESSON — dmesg staleness (learned the hard way, sess58)
`tests/reset4.sh 16` only virsh-reboots WEDGED nodes; the other ~10 keep
prior-session dmesg. **Always `dmesg -C` on ALL 16 nodes (or full
`virsh destroy+start` all 16) before trusting any shutdown signature.** This
directly caused a wrong diagnosis (below). Disambiguate builds by symbol offset
(`xfs_dir2_format+0x1f2` old vs `+0x340` new) + srcversion.
[[sess58-dir2-corruption-was-stale-dmesg-artifact]]

## Chronology of faces + fixes

### sess51 — multi16 cluster phase now progresses; cross_write_read FIXED
Build **5D6E7445** (sess50 phantom-EX waiter-recompute fix + P-WRBUF-DIRTORN
write-side probe in pal/linux/xfs_buf.c ~2574). The old sess50 torn-dir-444
EUCLEAN blocker on cross_write_read is GONE on clean infra + phantom-EX fix;
P-WRBUF-DIRTORN / P-IFLUSH-DIRTORN (xfs_inode.c iflush ~4265) did NOT fire — torn
dinode theory moot. cluster phase now runs ~13 tests; new blockers surfaced:
test_dir_stress (19 fails / 80 assertions, 30s = real correctness not slow),
test_discovery (~125s/node ≈ 2× lease_timeout — itself a RULE-0 fail),
test_rename_vis_dbg (stalled >200s). [[sess51-multi16-state-cwr-fixed-dirstress-discovery-blockers]]

### sess53 — two FS-shutdown roots isolated
Build **9C3D67D7** (UNVERIFIED).
- ROOT 1 (FIXED in 9C3D67D7): rmdir AGI-insert stale head. xfs_remove(rmdir) →
  xfs_droplink → xfs_iunlink → xfs_iunlink_insert_inode chains onto an AGI
  unlinked bucket head naming an inode FREE on disk → reload ENOENT → dirty
  xfs_trans_cancel (line 1060) → shutdown. Fix in
  xfs/libxfs/xfs_inode_util.c xfs_iunlink_insert_inode: on
  `error==-ENOENT && next_agino!=NULLAGINO`, FUA-read disk bucket head
  (mxfs_agi_disk_bucket_head), adopt if stale else self-heal. Logs `P-INS-STALE`
  (did NOT fire — ROOT 2 shut nodes first).
- ROOT 2 (deep, UNFIXED here): inode-chunk-free → block-reuse DOUBLE-ALLOC. rm-rf
  frees an all-64-free inode chunk → its 8 inode-cluster blocks return to bnobt →
  reallocated as dir-data for new dirs → stale cached inode/AG view clobbers a
  still-referenced inode cluster. Signature: ino 135's on-disk inode cluster
  OVERWRITTEN with a dirent (`\`n5_r1_d`); `from_disk FAILED ino=135 rc=-117`,
  `xfs_iformat_extents(2)` Bmap BTree corruption. Detectors fired: P103-CHUNKFREE,
  P117-AGMETA-STALE-CLEAN bnobt daddr=8. This is the sess24/39/42/43/81/90 AG
  double-alloc family at 16 nodes. Proposed class-eliminating fix: `ikeep` — don't
  free inode chunks in multi-node mode (gate xfs_ialloc.c:2442 chunk-removal
  branch). [[sess53-agi-insert-stale-head-shutdown-fix]]

### sess54 — ≥2 independent faces; Face A (stale dir extent map) FIXED
Confirms multiple faces; criterion needs ALL fixed → 0 shutdowns.
- **Face A — STALE DIR EXTENT MAP (FIXED, KEEP, 3 changes).** Symptom:
  `!(flags & XFS_DABUF_MAP_HOLE_OK) at xfs_da_btree.c:2814`, `xfs_dabuf_map bno
  8388608` (=0x800000 dir2 LEAF offset), `xfs_dir3_block_verify`. A peer grows a
  shared dir (shortform→block→leaf); the DIR_MODIFY evict-ring only refreshed DATA
  blocks and only armed MXFS_IF_DIR_RELOAD for LOCAL dirs → block/leaf dirs kept a
  stale extent fork → xfs_bmapi_read maps to a HOLE/freed block → shutdown. Fixes
  in xfs/xfs_mxfs_dlm.c: (1) mxfs_dlm_evict_inode_cb (~8564) arm
  MXFS_IF_DIR_RELOAD for EVERY dir format (`EVICT-RING-DIRMOD ... reload=1`);
  (2) mxfs_dlm_dir_consumer_refresh (~1177) consume the flag on LOOKUP path via
  mxfs_dlm_reload_inode; (3) ilock_begin fast-path dir_ex_stale_refresh (~5487)
  also calls mxfs_dlm_reload_inode (was data-blocks-only). Verified firing; pushed
  repro round-1→round-3. NOT sufficient alone.
- **Face B — bnobt DOUBLE-ALLOCATION (deep blocker, UNFIXED).** `DLM inode reload
  imap_to_bp failed ino=134 rc=-5` — a LIVE shared-parent inode's cluster
  unreadable; dir-data block allocated OVER it. Present in original 9C3D67D7 too.
- **ikeep applied (xfs_ialloc.c xfs_difree_inobt ~2442 + xfs_difree_finobt ~2613,
  gated `!(m_mxfs_dlm && !single_node)`) — did NOT fix Face B** (Face B is at
  chunk-ALLOC bnobt staleness, not chunk-free), KEPT as low-risk class elimination.
- Added P54-DIRBLK-PROBE (xfs_da_btree.c ~3260): on retry-exhausted dir-block
  EFSCORRUPTED, plain-reads disk daddr, reports magic/owner/crc — disambiguates
  cache-torn vs durable vs extent-map-aliasing. [[sess54-dir-coherency-and-bnobt-dblalloc-faces]]

### sess55 — Face B: allocator (M1) and dir-buffer-get (M2) DECISIVELY ruled out
Proven signature every run: ino 135's on-disk cluster = dirent bytes
(`xn13_r1_`, node13 storm filename); `xfs_iformat_extents(2)` + `from_disk FAILED
rc=-117` + `imap_to_bp rc=-5`. Round-1 runs on a FRESH fs (creates only) yet shut
down → NOT free→realloc aliasing. Four ungated detectors, ALL 0× while shutdowns
persisted:
- P55-ALLOC-OVER-INODE (per-AG 256-ring of node's inode-chunk extents) — 0×
- P55-ALLOC-OVER-CACHEDINODE (xfs_buf_incore trylock) — 0×
- P55-ALLOC-OVER-DISKINODE (plain-bio read of allocated block, di_magic 0x494e;
  SCST cache coherent under fua_disable=1) — 0× on all 16 nodes. DECISIVE: the
  allocator NEVER hands a DATA request a block holding a live inode cluster.
  REMOVED after proving (512B read/alloc slowed storm past 360s budget).
- P55-DIRWRITE-OVER-INODE (xfs_da_get_buf write buffer di_magic) — 0×.
Conclusion: neither M1 nor M2 targets an inode cluster → M3 (writeback-time
clobber) is the leading hypothesis: a stale cached dir-data buffer flushed by
xfsaild/BAST drain onto a daddr now backing an inode cluster; the bad daddr is
held by the BUFFER, not re-derived from the (fixed) extent fork. Next proposed:
instrument bio submission in pal/linux/xfs_buf.c (dir-block ops → inode-cluster
daddr, and inverse xfs_ialloc_inode_init). Builds: D9BA766C → 75F63922 →
069E6432 → 5C7F0742 → 3D83E2B2 → **26D4F790**. P55-STUCKMETA (force-release
Invariant#1 hole, xfs_mxfs_dlm.c ~10976) is real but fired 0× on shutdown rounds.
[[sess55-faceB-is-M2-stale-bmap-not-allocator]]

### sess56 — the "on-disk clobber" framing was a RED HERRING; format-coherency FIXED
P56-DIRWR-OVER-DISKINODE fired 0× like M1/M2. Real signature: P54-DIRBLK-PROBE
shows the ON-DISK dir block VALID (XDB3, owner+crc ok), shutdown is `Corruption of
in-memory data` at xfs_buf_verify_write / xfs_dir3_block_verify / xfs_dabuf_map
HOLE — an IN-CORE staleness, not on-disk clobber. **PROVEN root**
(P56-FMT-BLOCK-RELOAD-PENDING): a dir grows block→leaf (block 0 XDB3→XDD3, nextents
1→2). The evict-ring (`note_dir_modified`, ~8633) arms MXFS_IF_DIR_RELOAD but does
NOT bump i_dlm_dir_gen when gen==0 (the `gen != 0` guard); the dir-EX FAST-path
refresh (dir_ex_stale_refresh, ~5429) keyed ONLY on
`i_dlm_dir_gen > i_dlm_dir_loaded_gen`, ignoring the flag → fast-path mkdir/remove
reaches xfs_dir2_format with a stale 1-extent map, decides FMT_BLOCK, reads block 0
with block ops → XDD3-vs-XDB3 verify fail → trans_cancel → SHUTDOWN_CORRUPT_INCORE.
Slow path always reloads (was fine). **FIX build 0273A7EB (KEEP)**, xfs_mxfs_dlm.c
~5429/~5511: set dir_ex_stale_refresh ALSO when `MXFS_IF_DIR_RELOAD` set (bypasses
gen check AND self_created gate); clear the flag before reload, re-arm if
i_dlm_stale still set. Result: P56-BLKREAD/FMT-BLOCK-TORN 0×, no more
dir3_block_verify/HOLE/FMT shutdowns; repro ran full 300s. Residual: only test1 shut
down with `xfs_iunlink+0x27c xfs_agi block 0x2` → the remove-side AGI unlinked-bucket
head coherency residual (sess53 fixed insert-side; remove-side stale head remains,
likely needs AGI FUA-reread on AG re-acquire). Builds: 26D4F790 → B8E5254C →
CDEDB37B → 7BCAA93A → **0273A7EB** (FIX) → 421AC395 → A1F53770.
[[sess56-dir-format-coherency-fix-and-agi-residual]]

### sess57 — di_size corruption named as "dominant root" (LATER REFUTED)
Claimed the dominant clean-gate root was `dp->i_disk_size != geo->blksize` at
xfs/libxfs/xfs_dir2.c:287 (xfs_dir2_format ← xfs_create): 6 nodes shut down within
1s during a create storm; breaks zero_silent_loss (#13) + posix_semantics_multi16
(#19). Proposed mechanism: MODIFY paths (create/remove/rename) call
mxfs_dlm_dir_modify_refresh (xfs_mxfs_dlm.c:1248) which ONLY evicts DATA blocks —
does NOT rebuild the extent map or refresh di_size (full mxfs_dlm_reload_inode
self-deadlocks on down_write(i_lock) under held ILOCK_EXCL). So di_size (stale ~67)
and extent map (fresh cold-read, eof==1 block) come from different incarnations →
EFSCORRUPTED. Caller sites of modify_refresh: xfs_inode.c:1323, 3388, 3775/3777.
sess56's A1F53770 fixed LOOKUP/READDIR reload but the MODIFY-path gap remained.
[[sess57-dir2format-disize-corruption-modify-gap]] — **NOTE: this root was refuted
in sess58 (below).**

### sess58 — di_size root REFUTED (stale dmesg); real blocker is durable dirent lost-update
Added an always-on probe INSIDE the exact line-287 `XFS_IS_CORRUPT` block
(`P58-FMT-DISIZE-CORRUPT`, build **E78F3B4A**), ran the zero_silent_loss
16×100dpn×3 storm THREE times: **fired ZERO times**, no line-287 / shutdown /
corruption on the new build. sess57's line-287 errors were OLD-BUILD dmesg
(`xfs_dir2_format+0x1f2`) left by reset4 not clearing non-wedged nodes. Hence the
dmesg-`-C`-all-nodes lesson above. [[sess58-dir2-corruption-was-stale-dmesg-artifact]]

The REAL zero_silent_loss failure (build E78F3B4A, clean): pure **durable dirent
lost-update, NO shutdown**. iter1 expected=1600 silent=11; `MISSING node14_dir1
creator=test14` with no create error — durably absent from the shared parent even
to the creator. A peer's concurrent mkdir RMW'd the shared parent dir block from a
STALE cached base and wrote it back, erasing committed dirents. Long-standing
lost-update family (sess79–92/100/122). iter2/3 "node0 find non-numeric" / "mount
failed" were INFRA contamination from back-to-back storms.

**PROVEN root + FIX** [[sess58-durable-lostupdate-selfskip-blockleaf-dir-rootfix]]
(probes always-on, build 8E707B59):
- P58-STALE-BASE-ADD (xfs_dir2.c, xfs_dir_createname_args, fires when
  `i_dlm_dir_gen > i_dlm_dir_loaded_gen`): `pino=131 fmt=2 dir_gen=109
  loaded_gen=12` — in-core blocks loaded at gen 12 while peers advanced to 109;
  the RMW + release-drain writes the 97-gen-stale base back, durably erasing peer
  dirents.
- P58-SELFSKIP-STALE-DIR (P36-RELOAD-SELFSKIP branch of mxfs_dlm_reload_inode):
  `ino=131 fmt=3 dir_gen=379 loaded_gen=323 ... pin=1` — reload SELF-SKIPPED
  because the dir had own log mods in flight, keeping the stale base; loaded_gen
  frozen (only advances on a COMPLETE refresh, which the self-skip prevents).
- The sess49 "skip-the-skip" fix was scoped to SHORTFORM/LOCAL dirs only;
  BLOCK/LEAF dirs fell through → kept stale base → clobber. The storm dir grows to
  block/leaf, hitting the gap.
- **FIX build 6657565C**: mxfs_dlm_reload_inode gained `bool post_release`
  (xfs_mxfs_dlm.h:194); self-skip guard now
  `mxfs_dir_disk_superset = S_ISDIR && (if_format==LOCAL || post_release)`, skip
  only when `!superset && own-mods-in-flight`. Rationale: a POST-RELEASE reacquire
  drained our blocks at release (Invariant 1) → on-disk is a strict SUPERSET →
  reload cannot lose our work. sess36 regression was a SAME-TENURE FASTEX refresh
  (post_release=false → keeps skip → no regression). Call sites:
  xfs_mxfs_dlm.c:1196 consumer=true, :5579 fastex=FALSE, :5942 slow-path
  acquire=TRUE; xfs_dir2_readdir.c:558 reader=true; xfs_inode.c:875,1010 iget=false;
  xfs_icache.c ×5 =false.

**FIX 6657565C is INSUFFICIENT** [[sess58-postrelease-fix-insufficient-fastex-selfskip]]:
after deploy, single-iter storm still FAIL; P58-SELFSKIP-STALE-DIR fired **99×**,
P58-STALE-BASE-ADD **26×**. Because the fix makes post_release=true SKIP the
self-skip branch (where the probe lives), every one of those 99 fires is a
post_release=FALSE caller — so the clobbering self-skip is NOT the slow-path
EX-acquire (:5942) but one of: :5579 FASTEX same-tenure refresh (kept false to
avoid sess36 rollback), xfs_inode.c:875/1010 iget recycle/cache-miss, or
xfs_icache.c ×5. The create-storm hot path is the FASTEX (cached-EX) refresh, not
the from-NL slow path — dir_gen>>loaded_gen while holding cached EX means EITHER
(a) phantom dual-EX (mutual-exclusion violation, sess107/128 territory) so a peer
modified while we "held" EX, OR (b) loaded_gen never advances on the slow path
(it's advanced ONLY in the FASTEX evict block ~5541 `if gen==want_gen && left==0`;
the slow-path reload at :5942 may not advance it → gap persists forever → possible
probe false-positive). Next: tag P58-SELFSKIP with post_release + caller-site;
audit whether loaded_gen advances on slow-path reload; re-check sess128 phantom-EX
rearm (probe on-disk holder mxfs_v5_dlm_inode_held at the FASTEX self-skip).

Separate measurement blocker: zero_silent_loss verify phase ends "node0 find
returned non-numeric — counting as loss (=1600)" — node0's verify `find` over
/mnt/shared returns non-numeric (likely traversal EIO/ESTALE into a subdir, or an
error to stdout), MASKING the true silent count. Make verify robust (capture find
stderr, retry) or diagnose — may itself be a real cluster-wide inaccessibility bug.
Check scripts/sess88_workload_a_modeN_baseline.sh.

## Standing lessons / recurring failure modes
- The multi16 storm has MULTIPLE distinct faces sharing one symptom (600s
  timeout via shutdown). Fix one, the next surfaces. Don't declare victory on a
  single fix — run the storm 3× on a fully clean slate.
- IN-CORE staleness masquerades as on-disk clobber: on-disk dir block was VALID
  every time detectors checked (M1/M2/M3 write-submit all 0×). The bug lives in
  stale cached bases / stale extent maps / frozen loaded_gen bookkeeping.
- Dir coherency reload has THREE distinct entry paths, each fixed separately:
  LOOKUP/READDIR (consumer_refresh), fast-path EX-acquire (dir_ex_stale_refresh),
  MODIFY (dir_modify_refresh). A gap in any one bites. `MXFS_IF_DIR_RELOAD` +
  i_dlm_dir_gen/loaded_gen is the machinery; the `gen==0` guard and the
  self_created gate (sess24) are repeat sources of missed refreshes.
- `loaded_gen` advancing ONLY on a complete FASTEX-evict refresh is fragile —
  self-skips freeze it, making dir_gen>loaded_gen a permanent (possibly false)
  stale signal.
- AG double-alloc family (sess24/39/42/43/81/90) persists at 16 nodes via
  inode-chunk-free→dir-data-reuse; ikeep addresses the free side but the
  chunk-ALLOC bnobt-staleness sibling was still open here.
- AGI unlinked-list coherency: insert-side fixed sess53 (9C3D67D7); remove-side
  stale bucket head (xfs_iunlink+0x27c, agi block 0x2) remained open at sess56.
- RULE-0 timing failures also present in the phase (test_discovery ~125s/node).
- Secondary open criteria carried alongside: fence_during_write lost=400,
  rsync_paired 148%.

Build progression: 5D6E7445 → 9C3D67D7 → [D9BA766C…] → 26D4F790 → B8E5254C →
CDEDB37B → 7BCAA93A → 0273A7EB(dir-format FIX) → 421AC395 → A1F53770 → E78F3B4A →
8E707B59 → D82E4FB9 → 6657565C(post_release FIX, insufficient).
