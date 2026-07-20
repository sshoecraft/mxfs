---
name: compiled-zsl-run14d-torn-dinode-dir-fence
description: Compiled run14d zero_silent_loss saga: torn BTREE dinode/bmbt, dir eviction-fence btree bail, relflush stale-write, LSN destage, probe-gating.
metadata:
  type: project
tags: [compiled, zero_silent_loss, run14d, btree-dir, torn-dinode, dir-coherency, probe-gating]
---

# Compiled: run14d `zero_silent_loss` — torn BTREE dinode, dir eviction-fence, relflush stale-write, LSN destage, probe-gating

Single investigation thread across ccloop **14d31183** sess31→sess39. Ship gate is
`SUCCESS_CRITERIA.md` / `tests/criteria/`; through the whole arc **17-18 of the other
criteria PASS and `zero_silent_loss` (zsl) is the sole/recurring blocker**. zsl =
16-node, dpn=100 (`~100 dirs/node`) concurrent `mkdir` storm into ONE shared dir
(**ino 131**), target 1600/1600 dirents, `--mode 1`. The shared dir grows past EXTENTS
into **BTREE format**, and every root cause below is a coherency hole that only opens
once that dir is BTREE and under full-speed concurrency. Two failure signatures recur,
**same root**: *quiet loss* (26-109 dirents silently vanish, no corruption) and *storm*
(~1590/1600 lost, `corrupt dinode 131, (btree extents)` at `xfs_iread_bmbt_block` →
`xfs_trans_cancel` EUCLEAN → cluster-wide shutdown).

## Build progression (all KEEP unless noted)
- `DB81AF92F7D9A57B9415CF7` — sess31, **cache_coherency FIXED** (P31 relflush self-skip retry). First build to re-run zsl since sess17; exposed the zsl blocker.
- `DC5E59F421EBE405D06350E` — sess31 instrument build (P133-DIRINO-REVERT accepts BTREE dinodes under `mxfs.dirwr=1`).
- `70926D6B` — sess32 fence-fix v1, **WEDGED cluster, discarded** (O(whole buffer cache) owner-walk in dir-modify hot path → dir-EX tenures balloon → SESS50-STARVE).
- `FF401F225E7B0BA351296AE` — sess32 fence-gate fix (extents-loaded not fork-format). Built, carried forward.
- `6AB6018CB94AD2646492DBF` — sess33, **release-flush stale-write war FIXED** (`!XBF_DONE` bug). Carries FF401F22.
- `90A647F4` — sess34 ROOT#1 fix (P34D-RELOAD-FRESHSRC), in tree.
- `91BB755E51C3E88E7F5C058` — sess34 ROOT#2 fix (P119 relflush-flag-before-NL). Built, carried.
- `FCDB684890D2284C2C4BC92` — sess35 ROOT#3 fix (stale-retry loop). Built, NOT verified.
- `DE7F1BDA` — sess38 recovery baseline, zsl PASS 3/3 (355s, 480s budget).
- `9683085C` — sess38 first probe-gated build, zsl 3/3 PASS *before* the agent sweep.
- `4450524B39BD9FF35494E07` — sess38 full probe-gating sweep. Regressed zsl on gated build; sess39 proved that FAIL was **cluster contamination**, not the gating — on a clean cluster 4450524B passes 3/3.
- `5D2D50C8B691678F0A60D19` — sess39, **dmesg_clean FIXED** (gated P20-BIO-READ-LOGGED + P29-INSTR).

## Root causes, chronological

### sess31 — torn dinode/bmbt pair identified; cache_coherency fixed en route
[[sess31-run14d-rename-loss-fixed-zsl-torn-dinode]] first fixed the **cache_coherency**
rename-batch loss (`DB81AF92`): `xfs_iflush_cluster` rc==0 means "≥1 inode in cluster
flushed", NOT "THIS inode flushed" — victim dir ino 131 was ILOCK-trylock-skipped during
a concurrent local stat, so the release loop bwrote the cluster **without** the new
shortform dirent, set flushed=true, unlocked; peer's FUA read got the stale fork.
**Fix (xfs_mxfs_dlm.c release loop ~L2634): after rc==0 bwrite, verify
`!XFS_LI_IN_AIL(ip->i_itemp)`; if still in AIL the inode was skipped → retry
(`P31-RELFLUSH-SELF-SKIPPED`).** Verified 4× PASS (old MTBF 2-5 attempts). This
`iflush_cluster` trylock-skip is the seed of the torn-dinode family that dominates the
rest of the arc.

zsl storm forensics (raw disk): storm dir ino 131 BTREE, bmbt leaf at daddr 39659208.
Victim read fresh FUA dinode `nextents=22`, re-read bmbt → **valid BMA3 block, owner=131,
numrecs=23** → `xfs_iread_bmbt_block` fails `loaded+numrecs > if_nextents` (23>22).
**TORN PAIR: bmbt leaf durable@23, dinode durable@22.** Suspects: redundant
`P106-EXREL ×3` per tenure (trailing releases re-run the full drain AFTER slot unlocked =
unlocked write-after-release), or a stale inode-cluster write (hot cluster daddr 0x80,
inos 128-159) reverting 23→22.

### sess32 — the dir eviction fences all lie on BTREE dirs (the master root)
[[sess32-run14d-zsl-btree-dir-fence-root]]: once ino 131 is BTREE, **all three dir
coherency fences silently turned off** because they bailed on fork *format*:
- `mxfs_dir_evict_data_blocks`: `if (format != EXTENTS) return true;` — **returns
  true = "all evicted" LIE** → callers (`mxfs_dlm_dir_modify_refresh`/`consumer_refresh`)
  advance `i_dlm_dir_evicted_gen` → `P106-MR-SKIP` fast-paths every modify onto the stale
  base.
- `mxfs_dir_drain_evict_data_blocks`: same bail (`return 0`).
- Evidence: `DIR-STALE-SKIP ino=131 blk=45 buf_gen=0 inode_gen=365 pin=1` — one block
  never refreshed across 365 reloads. Both zsl modes follow: quiet dirent loss and the
  `corrupt dinode 131 (btree extents)` storm (`P133-BMBT-STALE-SKIP in_ail=1 delwri=1`
  right before all 16 nodes shut down).

**Fix (`FF401F22`): gate on extents-loaded, not format.** `for_each_xfs_iext` works on
BTREE forks once extents are in-core. Fences now: if BTREE + `xfs_need_iread_extents` →
return false/skipped (do NOT advance gen); else run the normal iext snapshot.
`MXFS_DIR_DRAIN_MAX` 32→64 with per-entry `lens[]`. **CRITICAL TRAP:** the v1 attempt
(`70926D6B`) enumerated blocks via an O(whole-buffer-cache) per-AG owner-walk — correct
but catastrophic in the hot path (gen never advances mid-storm → full rewalk per create →
tenure balloon → SESS50-STARVE → verify hung). **Never put a cache walk in the dir-modify
hot path.** Also added `P134-BMBT-WR/-REVERT`. INFRA: `INSMOD_OPTS` passthrough was
silently dropped (`prep_tcm_node.sh` insmods param-less first) — script now rmmods before
`insmod $MODULE $INSMOD_OPTS`; verify `cat /sys/module/mxfs/parameters/dirwr`.

### sess33 — release-flush stale-write war fixed; extent-REPLACEMENT double-map proven
[[sess33-run14d-zsl-relflush-stale-write-root]]: `6AB6018C` drops losses 261→~80-109 and
kills the cross-node stale-write war. **Root fixed:** `mxfs_dir_flush_data_blocks`,
`mxfs_dir_data_durable`, and `mxfs_dir_bmbt_scan` all treated `!(b_flags & XBF_DONE)` as
"not yet landed" — but a clean !DONE buffer is one the **eviction fence deliberately
invalidated** (cleared XBF_DONE to force re-read of the peer's image). The release path
then bwrote the invalidated STALE content over the peer's newer durable block. Proof:
P-DIRRD/P-DIRWR crc lineage — 27 flagged stale writes, all `done=0 dirty=0 in_ail=0
pin=0 comm=kworker/u*` (BAST release ctx), wcrc == already-superseded image, incl.
test10↔test7 verbatim re-push ping-pong. **Fix: drop `!XBF_DONE` from all three
disjunctions** (genuinely unlanded buffers are dirty/in-AIL/pinned/delwri). Side effect:
P133-DIRINO-REVERT stopped firing entirely.

**Remaining root PROVEN (raw disk, not fixed here):** ~80 dirents/iter vanish with zero
stale writes, zero revert, monotone dinode timeline. `grep -abo node10_dir28 /dev/sda`
hits inside a VALID XDD3 block at daddr 20873324, but the parsed on-disk BTREE bmbt of
ino 131 (`scripts/sess33_bmbt_dump.py`) does **not** map that daddr. → **extent-REPLACEMENT
double-map**: two growing nodes allocate different fsblocks for the same dir offset (stale
extent/leaf view during grow); the loser's block, full of committed dirents, is orphaned.
Size/nx stay monotone so all write-side revert probes are blind. The storm-mode
`xfs_dabuf_map HOLE` internal error (`xfs_da_btree.c:2765`) + EUCLEAN is the same mapping
inconsistency from the read side, triggered after `P131-WAITLONG 30.5s` EX starvation.

### sess34 — two stale-extent-map producers proven; bmbt-child staleness REFUTED
[[sess34-run14d-zsl-p119-consume-skip-race]] (`91BB755E`, built not run). **P34B refuted
sess33's prime suspect**: FUA-compare of consumed bmbt child vs platter = 0 STALEREAD
ever, so bmbt-child-buffer staleness is NOT the mechanism. Two real producers of the
double-map:
- **ROOT#1 — P91-RELOAD-PROTECT stale adoption:** when `mxfs_buf_has_uncheckpointed_mods`
  is true (BLI attached from own logged timestamp mods), reload REFUSES the inode-cluster
  invalidate and **adopts the STALE cached cluster** (nx=2 while disk nx=3); the next
  release-drain iflush writes nx=2 over disk nx=3 → durable revert → grow collision.
  **Fix (`90A647F4`): in `mxfs_dlm_reload_inode`, when kept_protected, FUA-read the
  cluster privately, verify, memcpy the fresh dinode into the snapshot (buffer untouched)
  — `P34D-RELOAD-FRESHSRC`.** Unverified: the next run had 0 P91 fires so P34D never
  exercised.
- **ROOT#2 — P119 consume-skip races the release window:** `mxfs_dlm_bast_process` sets
  `i_dlm_mode=NL` EARLY; a concurrent xfsaild iflush hits `P119-NONEX-FLUSH-SKIP`
  (`xfs_inode.c:4048`, mode!=EX && !MXFS_IF_DLM_RELFLUSH) whose `error=0; goto flush_out`
  **CONSUMES ili_fields without copy-in** → buffer written with old payload (size 28672
  instead of committed 36864); drain finds nothing dirty → -EAGAIN → flushed=true →
  release; next acquire reloads disk 28672 (**disk went backward**) → in-core map loses
  the offsets → re-grow → own committed blocks orphaned. **Fix (`91BB755E`): set
  `MXFS_IF_DLM_RELFLUSH` (REG||DIR) BEFORE the `i_dlm_mode=NL` clear** so release-window
  flushes write real in-core state (safe: tenure owns until on-disk unlock). Flag still
  cleared at reg_durable_done. Other NL-clear sites (`xfs_mxfs_dlm.c ~4664/6309/6396/
  6419/11556`) may open the same window.

### sess35 — LSN-destage + pinned-drain fixed and VERIFIED; stale-retry built
[[sess35-run14d-zsl-lsn-destage-and-stale-retry]]: losses 84/iter → ~1 durable loss per
lossy iter; iter walls 166s→102-123s (beats the sess17 record).
- **FIX 1 (VERIFIED, KEEP) — cross-node LSN compares are meaningless.** P35A proved every
  false "destaged" verdict had `li_lsn < payload_lsn`, impossible locally → the payload
  LSN was stamped by a PEER's journal. Misjudged buffers got `P133-INAIL-REFRESH` (disk
  re-read over own committed-unwritten dirents, killing entries within 7ms of mkdir).
  **Fix: node-local seq pair on xfs_buf — `b_mxfs_logged_seq` (bumped in
  `xfs_trans_log_buf`) + `b_mxfs_written_seq` (snapshot in `xfs_buf_submit` after
  verify_write); `is_undestaged := pinned || logged!=written`. Removed
  `mxfs_dir_buf_payload_lsn`.** After: 0 P133, 1600/1600. NOTE: the AG-meta version
  `mxfs_buf_is_undestaged` (~L6650) has the **same cross-node flaw** — not yet fixed.
- **FIX 2 (VERIFIED, KEEP) — pinned-buffer drain stalls 23-29s.** `xfs_bwrite`'s
  wait_unpin sleeps without driving the CIL; unpin only at the ~30s log-worker tick (one
  node stalled the whole cluster 23.8s → SESS50-STARVE). **Fix: `if
  (xfs_buf_ispinned()) xfs_log_force(mp, 0)` before `xfs_bwrite` in
  `mxfs_dir_flush_data_blocks` AND the `P133-BMBT-RELFLUSH` loop.** Max drain 29137ms→135ms.
- **ROOT 3 (PROVEN, fix `FCDB6848` built NOT tested) — fast-path EX re-dirty during
  BAST drain.** Residual ~1 durable `CREATOR_MISSING` loss/iter. P35E proved writes ARE
  serialized under DLM (~0 out-of-hold); P35C/P35D proved **multiple simultaneous
  divergent in-core copies** across nodes (superseded-image RMW, not SCST cache lag).
  Mechanism: `P-DIRFASTEX` creates keep re-dirtying dir blocks during the drain;
  single-shot `mxfs_dir_stale_data_blocks` then SKIPS them (189 `P99-STALE-SKIP`/iter
  cluster-wide) → lock handed off with committed-unwritten dirents → peer RMWs stale
  image / late writeback clobbers → durable loss. **Fix: `mxfs_dir_stale_data_blocks`
  returns nskip; call site loops flush→`log_force(SYNC)`→stale up to 500× w/ msleep(1)
  until nskip==0 (`P35F-STALE-RETRY-EXHAUSTED` on give-up).**

### sess38 — recovery, probe-gating sweep, and the gating-exposes-races scare
Two memories. [[sess38-run14d-recovery-and-probe-gating]]: recovered from the 2026-06-12
**manual host reset** (RULE 2 territory — user-only host recovery). Key discovery: the
`@reboot clyde_boot_recover.sh` self-disarms and does NOT run on a user manual reset; and
**`virsh start test1..16` fails "Cannot access storage file" until the HOST is
iscsiadm-logged-in to ALL 16 targets** (passthrough `/dev/disk/by-path/ip-127.0.0.1:3260-
iscsi-...disk1{,n2..n16}-lun-0`). Working sequence: login 16 targets → copy pass →
`cluster_reset_n.sh 16` → zsl PASS 3/3 on `DE7F1BDA` (confirms sess37's iter-3 join
failure was the SCST wedge, not mxfs). **Probe-gating sweep** for ship cleanliness: a
PASSING zsl run still emitted ~9000 `mxfs: P*` lines per node (~36k cluster-wide) incl.
`dump_stack()` from `P124-ALLOC-REVERT` (would trip dmesg_clean's `Call Trace` grep).
Approach: gate every routine marker behind `unlikely(mxfs_dirwr_enabled ||
mxfs_instr_enabled)` (dlm/ uses `caw_instr_on()`), **print-only — side effects like
nskip++/all_evicted stay ungated**. `9683085C` passed zsl 3/3 before the agent sweep;
`*.c.backup` left in tree for diff review (no git).

[[sess38-probe-gating-exposed-races]]: the full-sweep build `4450524B` **FAILED** zsl
(iter2 silent=1 `node11_dir84` created-then-lost = the sess15 silent-1 class; then iter1
catastrophic EUCLEAN storm, `corrupt dinode 131 (btree extents)`). Hypothesis (RULE 4
step 1): the ~36k printk/run were acting as serializers/throttles in the dir
reload/release/writeback hot paths; gating them = full-speed concurrency = the latent race
classes reopened — **same lesson as instr=1-hides-races, one level down. These are REAL
bugs; DO NOT un-gate prints to "fix" it, do NOT widen timeouts.** (sess39 later reclassified
this specific FAIL as cluster contamination, but the throttle-masking lesson stands.)

### sess39 — zsl GREEN on clean state; dmesg_clean fixed; latent race documented
[[sess39-run14d-zsl-cleanstate-pass-dmesgclean-p20-gate]]: on a fresh
`cluster_reset_n.sh 16`, `4450524B` passed zsl **1/1 then 3/3, 0 silent loss, ~110s/iter**.
The 19:12Z JSON FAIL (1590 loss, completed=1/3) was on a cluster left **CONTAMINATED** by
sess38's mid-work sweep — the recurring "contaminated cluster → catastrophic failure"
lesson. Non-perturbing proof the bug didn't fire clean: `P-REG-DURABLE-FAIL`,
`corrupt dinode`, `P133-DIRINO-REVERT`, `P31-RELFLUSH-SELF-SKIP` = **0 across all 16
nodes** during the 3/3 run.

**LATENT torn-dinode race still in code (unreproducible on clean state, NOT patched):**
`mxfs_dlm_bast_process` release loop (`xfs_mxfs_dlm.c ~3045`) — when the 8-try self-flush
fails (`flushed==false`) AND the dir dinode is still `XFS_LI_IN_AIL`, it logs
`P-REG-DURABLE-FAIL` and **RELEASES ANYWAY** (Architectural Invariant #1 gap). Peer grows
the BTREE dir to nextents=23 (dinode+bmbt durable@23); this node's stale xfsaild push of
the still-dirty dinode (nextents=22) reverts it → `corrupt dinode (btree extents)` →
shutdown → ~1590 loss. **WHY the 8-try loop fails:** `xfs_iflush_cluster` uses
`xfs_ilock_nowait(SHARED)` and trylock-SKIPS the dir inode whenever a local create holds
its ILOCK — constant during the dpn=100 storm (the same seed as sess31). Fix candidate for
a future deterministic repro: **single-inode flush holding ip's ILOCK (bounded), NOT
trylock-skip.** Not patched (RULE 4: unreproducible on clean state; release-path changes
have repeatedly regressed — see sess32 v1).

**dmesg_clean FIXED (`5D2D50C8`):** test1 hit 8 "Call Trace:" lines = ungated
`P20-BIO-READ-LOGGED` (`pal/linux/xfs_buf.c ~3213`, fires on any plain-bio read of a
buffer with log items attached; the sess38 sweep gated P20-CLUSTER-INVAL but MISSED
P20-BIO-READ-LOGGED). Also gated the flooding `P29-INSTR` bunmapi probe
(`xfs/libxfs/xfs_bmap.c ~5287`, every unlink). Both log-only → gated. dmesg_clean now
PASS hits=0 ×2. **KEPT ungated (real-anomaly detectors, once-guarded, did not fire):**
PROBE-A AG-META-WRITE-NOT-HELD (2056), P125-AG-DIVERGE (2110), P88-CLOBBER-PRODUCER
(2253), upstream xfs_buf_verify_write "no buf ops" (1743).

**Separate real bug seen, not fixed:** `WARNING xfs_assert_ilocked` at
`xfs_iread_extents` via `xfs_dir2_format ← xfs_dir_lookup ← mxfs_drevalidate` during the
storm — `xfs_ilock_data_map_shared` picks SHARED (extents look loaded), the MXFS DLM
reload hook inside acquire resets `dp->i_df` to need-iread, then `xfs_iread_extents` needs
EXCL but only SHARED held. Only matters for dmesg_clean (dmesg_test dir stays BLOCK/LEAF,
not BTREE, so it didn't fire there). Latent risk.

## Recurring failure modes / hard-won lessons
- **dmesg ring on the VMs (~2278 lines) WRAPS under probe storms → "0 in dmesg" is a
  trap.** ALWAYS cross-check `journalctl -k --since '<UTC>' --utc` (`-o short-precise` →
  field $3 is the time). Struck repeatedly (sess31 explicitly the 3rd occurrence).
- **Contaminated cluster → catastrophic failure.** A clean `cluster_reset_n.sh 16` (or
  full `virsh destroy/start test1..16`) is mandatory before trusting any zsl result;
  storm iters leave D-state umounts pinning the module → teardown INFRA-fails mkfs. Every
  sess power-cycled between failing runs.
- **Probe prints throttle races; gating exposes them.** Same family as instr=1-hides-races
  and generous-timeout-hides-slowness. The FS must be correct at full silent speed.
- **Never widen the zsl timeout** (RULE 0): slowness correlates with the storm mode. 1-iter
  ≈110s (200s budget); 3-iter uses 480s. Iter walls 139-286s under verify storms; the 480s
  cap kills iter3 of slow runs — that is a signal, not a reason to widen.
- **`xfs_iflush_cluster` rc==0 / trylock-SHARED-skip is the master seed** of the whole
  torn-dinode family (sess31 cache_coherency, sess39 latent release-anyway).
- **Cross-node LSN/li_lsn comparisons are meaningless** — a peer's journal stamps the LSN;
  use node-local logged/written seq pairs (sess35).
- **Never put an O(cache) owner-walk in the dir-modify hot path** (sess32 v1 wedge).
- **Release-path changes have repeatedly regressed** — treat with RULE-4 discipline;
  don't patch a torn-dinode fix you can't reproduce.
- Architectural **Invariant #1** (no on-disk unlock without a completed drain) is
  currently *violated* by the sess39 release-anyway path — the last known real zsl bug.

## Standing NEXT (per sess39 handoff)
zsl is GREEN on clean state (`4450524B`/`5D2D50C8`); the latent release-anyway torn-dinode
race is unpatched but only fires on contaminated/perturbed clusters. Ship-gate status on
`5D2D50C8`: **9/19 PASS** (mkfs_timing, chk_clean, dkms_install, online_resize,
cluster_ops_timing, wedged_unmount, online_membership, dmesg_clean, cache_caps).
Remaining: posix_semantics(1), cache_coherency(4), strong_consistency(4), zero_silent_loss,
crash_consistency(2), fence_during_write(4), single_node_paired(1), rsync_paired(4),
scaling_curve(16), posix_semantics(16) — run `verify_ship.sh` foreground criterion-by-
criterion (~52 min total; FOREGROUND-wait, no bg+poll). Remove `*.c.backup` once the
gating sweep is final. Separate: harness count-extraction bug in
`scripts/sess88_workload_a_modeN_baseline.sh` (find|wc|tr concatenates garbage → nonsense
silent counts; take the LAST numeric line).
