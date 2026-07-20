---
name: compiled-tcp-ladder-sess1-5-barriers-drc
description: Compiled ccloop a9a03929 sess1-5: TCP 8-node dir_reuse_coherency ladder — barriers-off pace, iunlink/nest/suppression root fixes.
metadata:
  type: project
tags: [compiled, tcp-dlm, dir_reuse_coherency, ccloop-a9a03929, barriers-off, cache-coherency]
---

# TCP 8-node dir_reuse_coherency ladder — ccloop a9a03929, sess1-5

Central thread across all five sessions: getting `dir_reuse_coherency` (drc) to PASS
on the **TCP DLM transport** at 8 nodes, then holding it clean ×5 consecutive, then
laddering down to 4/2/1 and running the full `./run.sh N tcp` suite. drc runs 24 rounds
of concurrent same-dir create/rm/verify with per-round md5 checks; RDMISS / readdir<800 /
shutdown / EFSCORRUPTED = FAIL. Marker (ccloop DONE) written only after all N∈{8,4,2,1}
pass. As of sess5 end the marker is **NOT written** — best streak was run72/73 (×2) then
run79 got 7/8; still chasing a suppression-family tail-loss.

## Build progression (chronological)
- `D03537C9` (sess1) — gen-aware DLM release + dwork strand re-arm. run47 baseline: 21 rounds, 0 fails, PACE-ONLY blocker.
- `1429D909` (sess1) — = D03537C9 + per-dirop durability barriers gated OFF on TCP. run48: pace SOLVED (8-14s/rd) but iunlink shutdown r7.
- `391F2F21` (sess2) — B5 iunlink-leak fix + noatime + reg_clean_release_fast. runs 60/61 FAIL (silent -EIO + format tear).
- `754883887E` (sess3) — four root fixes. **run67 = FIRST clean 8/tcp drc PASS** (8/8, 24 rounds, 0 corruption).
- `75F70CA40` (sess4) — FIX-1 nest-deadlock + FIX-2 enforcing pre-unlock audit. run72/73 PASS (×2 consecutive), run74 FAIL (ILOCK leak).
- `BD1480DB → 6DE9540D → 15A8C8D6 → A9DBB70085` (sess5, =FIX-8) — write-suppression family.
- `70C8C23F` (sess5, FIX-9), `BA67B6309C` (sess5, FIX-3..10, FIX-10 UNTESTED) — CIL-window fix, not yet deployed at relay.

---

## sess1 — gen-aware release + barriers-off pace solve
[[sess1-a9a03929-gen-aware-unlock-fix-wedge-fixed]] [[sess1-END-barriers-off-pace-solved-iunlink-shutdown-blocker]]

**Gen-aware release fix chain (`D03537C9`, all RULE-4 proven):**
1. `mxfs_dlm_unlock_gen(ctx,res,expected_gen)` (dlm.c; wrapper gen 0; `mxfs_v5_dlm_inode_unlock_gen`). bast_process captures `p_rel_gen` via `mxfs_v5_dlm_inode_grant_gen` BEFORE the NL-set; unlock releases ONLY that tenure; newer-gen entry → -ESTALE. Kills run42-t4 root: a stale queued release ate the fresh EX mirror, echoed the CURRENT gen → master accepted → CONCURRENT EX (invisible to P-DOUBLEGRANT) → stale-base RMW → durable dirent loss.
2. Local-immediate grant gen stamping (dlm.c ~1497) — the one grant path leaving grant_gen=0; masters' own tenures had gen 0 → capture read 0 → releases skipped → run44 total wedge (readdir=0). Stamp `dlm_next_gen(ctx)`.
3. P6Z skip: TCP + capture==0 → skip unlock entirely.
4. Strand re-arm via `i_dlm_bast_dwork` — first ESTALE version set state=BAST with holders==0, nothing consumes BAST, blocking fast-path admits (P47-FILEBLOCK) → 117s getattr wedge broken only by blockgc at mount+300s. Fix: on ESTALE set bast_pending, state=NONE, arm dwork (+4ms); dwork samples till quiescent then runs a FRESH bast_process. run47: 21 rounds, 0 drc-FAIL; P6G=68-92/node (race is HOT).

**Barriers-off pace solve (`1429D909`):** new modparam `mxfs_dirop_durable_tcp` (default 0) + `mxfs_dirop_durable_needed(mp)` (xfs_mxfs_dlm.c ~316) gate INSIDE `mxfs_dlm_dir_durable_signal` (~18904) and `mxfs_dlm_dir_inode_durable` (~3723). Release-path drain untouched. run48: all 24 rounds at 8-14s/rd (was 21-28), pace SOLVED.

**BLOCKER exposed:** rank1 SHUTDOWN r7 rm — `Found unrecovered unlinked inode 0xad in AG 0x6` → droplink rc=-117 (EFSCORRUPTED) → dirty trans_cancel. Root: with barriers off the platter iunlink chain lags; rm's `xfs_iunlink` insert hits stale on-disk unlinked-chain state, `xfs_iunlink_reload_next` (xfs_inode.c:3358) iget UNTRUSTED → recovery mangles the LIVE reused inode's nlink to 0. Fix direction: iunlink reads must not adopt stale platter over same-node logged state (extend the CIL/uncheckpointed-mods guard family — sess43 `BB54A138`, sess91 `BD2A94BA` — to the AGI/iunlink FUA-reload path).

---

## sess2 — Road B locked in; two barrier-off families open
[[sess2-END-road-b-barriers-off-t6-silent-eio-blocker]]

**`391F2F21`, KEEP items:**
- **B5-leak FIX (VERIFIED):** xfs_inactive ~2989, on -EDEADLK from the one-shot EX do an inline demote (`i_dlm_demoter=current; mxfs_dlm_bast_process(ip)`) then re-acquire. run49: P2I×7 rc=0, P2L-INACT-LEAK=0 (run48 had 5 leaks → its r7 shutdown).
- **Road B decided:** `dirop_durable_tcp` STAYS 0. Barriers-ON floor is STRUCTURAL — P137-IFREE ~10-15ms/unlink, P128-INACT-EXREL 14.5ms, P138 file-bast 10-13ms → best 21.2s/rd vs <20 needed. DO NOT flip back; fix release-path holes instead.
- noatime (SB_NOATIME in fill_super) + stale-BAST recycle reset — both UNVERIFIED SUSPECTS for the run60/61 regression.

**Two open FAIL families (runs 60/61, barriers off):**
1. **Silent -EIO sweeps (run61 t6 r5):** `DLM inode reload imap_to_bp failed rc=-5` on consecutive inos, persisting forever, NO corruption print, NO block-layer error → -EIO generated INSIDE the read path. t6 diverged (empty stat, ENOENT lookups, EIO storm, cluster wipe). (→ root-caused sess5 FIX / run76.)
2. **Format tear (both runs, r8 all-node):** `xfs_dir3_block_verify` daddr 0x48 — platter block has XDD3 (multi-block) while readers expect XDB3 (single-block) = dinode-fork vs dir-block-content tear at block↔leaf transition (sess135 family). imap is ino-derived so stale-imap theory REFUTED.

---

## sess3 — FIRST clean 8/tcp drc PASS (run67)
[[sess3-END-first-8tcp-drc-PASS-four-root-fixes]]

`754883887E` — run67 = 8/8, 24 rounds, 435s wall incl prep, ZERO corruption/shutdown. Four RULE-4 proven root fixes:
1. **-EEXIST wait-out** (dlm/v5_mount.c `mxfs_v5_dlm_inode_lock`): run61 t6 shutdown root was a local EX hitting its own in-flight PR's WAITING entry (dlm.c:1270 EEXIST); ilock_begin's 3×50ms retry gave up. sess2's "silent imap_to_bp rc=-5 sweeps" were POST-SHUTDOWN fallout (xfs_is_shutdown → -EIO, alert suppressed) — sess2 MISSED the 119.7s shutdown line. Fix: retry EEXIST every 20ms up to ~60s.
2. **Release-path dir-INODE-cluster destage:** sess1's Road-B gate `mxfs_dirop_durable_needed()` was INSIDE `mxfs_dlm_dir_inode_durable`, so it no-op'd the bast_process sd-stage call too → dir blocks landed but the DINODE never did → run60/61 `xfs_dir3_block_verify daddr 0x48` tear. Fix: split `__mxfs_dlm_dir_inode_durable` (ungated, called at release) from the gated per-op wrapper. Format-tear family: 0 since.
3. **!DONE+undestaged re-land** (`mxfs_dir_data_durable` + `mxfs_dir_flush_one_daddr`): run62/64 dir blocks whose extent was in the durable dinode but content NEVER submitted → platter = prior-life garbage → EFSBADCRC kills. Insight: lseq>wseq means NEVER-LANDED (sess47's undestaged term was DONE-gated = only evict-invalidated stale). Fix: undestaged unconditional in both predicates; before bwrite of a !DONE buf validate magic+owner (P3F-UNLANDED-LOST) then set XBF_DONE (P3R-RELAND). CRC-garbage family: 0 since.
4. **MAPDIVERGE dirty-inode guard** (xfs_mxfs_dlm.c ~6106): run65 t2 died 13ms after its own block→leaf convert — the no-ILOCK P68-MAPDIVERGE hook adopted the stale disk map over the in-flight grow. Fix: skip adopt when own inode item is dirty/pinned/in-AIL (in-core authoritative).

Key probes added (all always-on, capped, keep): P3W-DIRWR (write-lineage), P3B-UNLOCK-UNDESTAGED, P3D-RELINVAL, P3L-DIRLOG-BIRTH, P34C-DIRGROW/SHRINK.

---

## sess4 — nest-deadlock + enforcing pre-unlock audit; then ILOCK leak
[[sess4-TWO-ROOT-FIXES-nest-deadlock-preunlock-audit]] [[sess4-END-run74-dp-ilock-leak-and-fix2-wedge]]

`75F70CA40` — run72 PASS (consecutive #1), run73 PASS (#2), run74 FAIL.

**ROOT 1 (runs 68/69/71 — the 0/8 480s cluster-kill wedge): nested-hold DLM self-deadlock.** `xfs_ilock` maps IOLOCK **and** ILOCK onto the ONE per-inode DLM lock (single holder count). Every buffered write nests IOLOCK_EXCL(EX) → write_checks → file_remove_privs(PR)/file_update_time(EX). If a BAST/demote window opens between outer and inner acquire, the inner waits for a release that needs holders==0 — its own outer hold. Permanent because bast_notify's DEMOTING arm swallows every re-BAST with no liveness check (work_busy==0 = swallowed forever). Proven twice live (run68 t8 ino=6293428, run69 t3 ino=8388765). **FIX-1** (xfs_mxfs_dlm.c, two arms at `state==BAST && holders>0 && demoter!=current`): consult v5 mirror (`mxfs_v5_dlm_inode_granted_mode`) — mirror≥request → ADMIT + restore i_dlm_mode (P79-NESTADMIT); mirror<request → state=NONE + wake, take real slow path (P79-STALEBAST-CLEAR). run72: 4× STALEBAST-CLEAR self-recovered.

**ROOT 2 (run70 — round-1 readdir=799, node7_f45.md5 durably lost): unlock before land.** A fast-path-admitted create landed AFTER the release durability pass but BEFORE the unlock; a peer acquired EX in the gap, cold-read the pre-add platter, placed a different md5 at the SAME aoff, and durably dropped f45. Contributors: `mxfs_dir_data_durable` returns VACUOUS-TRUE for BTREE forks with unread extents (P42-VACUOUS-DURABLE); clean_skip/self-demote trusted `xfs_inode_clean`, blind to dirty dir DATA buffers (node-format add doesn't dirty the inode item). **FIX-2** (P3B site): pre-unlock audit now ENFORCING — loop {dir_data_durable + !in_AIL + pin==0 else log_force(SYNC)+ail_push_ag_sync+flush_data_blocks_relsafe+msleep(2)}, bounded 5000 tries then SHUTDOWN (Invariant #1 — never release stale).

**run74 FAIL (NOT fixed in sess4): leaked dir ILOCK write-hold by an EXITED create.** test3 held dir ino=131 EX **417s** (7 peers queued, EIO). `P132-ILOCK-STUCK ino=131 cnt=-510 wr_last=xfs_create+0x4e1 pid=2747` even though pid 2747 (bash) had EXITED with the rwsem still WRITE-HELD. The bast kworker was stuck in `mxfs_drain_ilock_read → msleep` — likely INSIDE FIX-2's enforcing loop, whose first step is drain_ilock_read which retries FOREVER internally → FIX-2's 5000-try counter never advances → shutdown backstop never fires → dir held EX forever = convoy. Two follow-ups handed forward: (a) bound drain_ilock_read so a leaked ILOCK degrades to shutdown, (b) find which xfs_create early-return path leaks the write-hold when unlock_dp_on_error isn't honored.

---

## sess5 — the write-suppression family + CIL-window
[[sess5-FIVE-ROOT-FIXES-suppression-family-and-probes]] [[sess5-END-run80-p28c-cil-window-fix10-built]]

Builds `BD1480DB → 6DE9540D → 15A8C8D6 → A9DBB70085` (FIX-8) → `70C8C23F` (FIX-9) → `BA67B6309C` (FIX-3..10, FIX-10 UNTESTED). Ladder this session: run74→78 all 0/8, **run79 = 7/8** (only transient), run80 0/8.

**FIX-3 (run74 root, PROVEN):** P3B relsafe-without-hold rwsem underflow. `cnt=-510` decodes to readers −2 + waiters (NOT a leaked write hold — corrects sess4's read). FIX-2's P3B loop called `mxfs_dir_flush_data_blocks_relsafe` (a lock-CONSUMING fn, up_reads every path) at xfs_mxfs_dlm.c:11149 WITHOUT holding the read → each non-clean iter = one unmatched up_read → −2 → rwsem permanently unacquirable → 400s+ convoy. Fix: take `mxfs_drain_ilock_read` before relsafe (mirror sites 10212/10575).

**FIX-4:** `mxfs_drain_ilock_read` bounded (180s → force shutdown, return false); all callers treat false as shutdown = fence+replay, never a live convoy. (This is the sess4 follow-up (a).)

**FIX-5 (run75 root #1, PROVEN by uuid): `dir_wseq_at_completion` default 1.** wseq was stamped at SUBMIT (xfs_buf_submit ~4683) BEFORE the skip gate (submit_bio ~3268), so `mxfs_dir_buf_is_undestaged`=false at the gate → NL-window suppressors (P3W nl_released skip + P12-DIR-EXGUARD) dropped a grown block's ONLY write; platter kept a PRIOR-MKFS image (same layout every run → same daddrs). Detected as **uuid mismatch** — `xfs_dir3_data_verify:327 EFSCORRUPTED(-117=EUCLEAN, NOT a crc failure)`; P54's crc_ok=1 misled because it doesn't check uuid. (errno key: EFSBADCRC=-74, EFSCORRUPTED=-117.)

**FIX-6/7:** undestaged buffers never suppressed (P12 ex_guard arm xfs_buf.c ~3880) / never clean-evicted (P3D relinval xfs_mxfs_dlm.c ~2284).

**run76 root (FIXED): FUA READ(16) silent-EIO storm → mount-root sick-poisoning** — this is the sess2 open family #1. Storm-time `scsi_execute_cmd` failures (non-ILLEGAL_REQUEST) returned silent -EIO (kern.c ~630); reload imap_to_bp EIO'd for the whole storm; root got sick-marked → node lost the mount until remount (readdir=0 rounds 16-24). FIX: bounded retry ×20 with backoff inside `mxfs_pal_scsi_read_fua_bdev` (P-FUA-READ-RETRY/ERR). run77: 0 EIOs.

**FIX-8 (run77 root, CAPTURED LIVE): reload adopt reverts own in-flight grow.** Under held EX, dd grew dir 131 (leaf split nx6→7); 4ms later a reload FUA-read the platter and ADOPTED pre-grow nx=6 (P133-DINO-READSTALE, P33-FROMDISK-DIRSHRINK) while the inode item was in AIL → da-btree inconsistent → "Corruption detected" (a DIFFERENT string than "Metadata corruption" — grep BOTH). FIX: P34E-FRESHSRC-SELFAHEAD-SKIP — skip adopt if pincount>0 || ili_fields || IN_AIL (platter is behind us by definition).

**FIX-9 (`70C8C23F`):** `mxfs_dlm_reload_inode` ENTRY guard — skip whole reload when pin>0 || ili_fields || IN_AIL (P34F-RELOAD-SELFAHEAD-SKIP; clears i_dlm_stale). run78's revert went through a non-P34D arm, hence entry-level.

**FIX-10 (`BA67B6309C`, UNTESTED): CIL-window keep-guard.** run80 r1: node2_f47-50.md5 durably lost cluster-wide. The xfs_dir2_data.c ~2061 keep-guard checked `b_inail && is_undestaged`; CIL-window blocks (in_cil=1 in_ail=0 pin-dropped dirty=0 DONE-restored) fell through → FUA-platter-compare diff (normal pre-destage!) → P28C-STALE invalidate+reread DISCARDED the wave-tail adds. Full chain: P3L-BIRTH → P68-EVDECIDE in_cil=1 → P-DE-BLK SKIP → done=0 → P5-UNDEST-SALVAGE → P60-GENMATCH-STALE → P28C-STALE. Fix: unconditional `mxfs_dir_buf_is_undestaged(dbp)`.

**Remaining known issues at sess5 relay (priority order):**
1. **P60-GENMATCH-STALE (xfs_da_btree.c:3738)** — sibling disk-compare guard printed in the run80 chain; check whether its ACTION path also lacks an undestaged guard.
2. **run79-style transient:** rank1 round-7 readdir 788/800 healed <2s (also r7 rank1 in run80 — r7+rank1 TWICE is a suspicious ring/format-transition pattern). Candidate: clean_skip PR-release handing off with unlanded blocks (`xfs_inode_clean` blind to dir DATA bufs) IF that path bypasses the P3B fence.
3. **test1(rank1) EDEADLK storm: 10380× rc=-35/run77** vs ~70 on peers — PR→EX upgrade denial livelock (CONVBLK-DENY dlm.c:3445). TCP has NO writer-priority/defer_for_waiter (unlike sess50's CAW fix). Main slowness/desync amplifier. Suspect: master defers PR re-grants when an EX waiter is queued.
4. **P74 ABSORB arm (dlm.c:3683)** — mirror-update-without-reject desync hole, open since sess4.
5. Console capture unreliable (6/8 files 0 bytes run77; test4 run78 PANIC lost) — restart per cycle or rely on pstore.

**Next step at relay:** deploy `BA67B6309C` (built on host, NOT deployed), cycle cluster, `./run.sh 8 tcp dir_reuse_coherency` (run81). Marker only after 8/tcp ×5 clean then N∈{4,2,1} then full suites.

---

## Recurring failure modes (cross-session, deduplicated)
- **Unlock-before-land / stale-platter adopt** — the dominant durable-lost-update class: a peer reads the pre-add platter in a release/BAST gap (sess4 ROOT 2), or a reload adopts a platter image behind the in-core in-flight grow (sess3 fix4 MAPDIVERGE, sess5 FIX-8/9/10). Repeated cure: "in-core (pin>0 || ili_fields || IN_AIL) is authoritative — never adopt/suppress it."
- **Undestaged/never-landed dir blocks** — lseq>wseq = NEVER-LANDED, distinct from DONE-gated evict-stale (sess3 fix3; sess5 FIX-5/6/7/10 honest wseq). Prior-mkfs platter images share daddrs across runs, so a dropped write reads as valid-CRC-but-wrong-uuid garbage.
- **DLM self-deadlock from IOLOCK+ILOCK sharing one per-inode lock** (sess4 ROOT 1) and rwsem underflow from lock-consuming helpers called without the hold (sess5 FIX-3).
- **Silent -EIO with no print** — either post-shutdown fallout (sess3 fix1; the shutdown line is the real event) or FUA READ(16) storm sick-poisoning (sess5 run76). Always grep for the shutdown line first.
- **Barriers-on pace floor is structural** (~14.5ms/unlink); Road B keeps `dirop_durable_tcp=0` and fixes release-path holes instead.

## Infra / diagnostic conventions (carry forward)
- Cross-node dmesg `[ts]` are BOOT-RELATIVE (~0.6s/node stagger) — NEVER compare raw; align via `realns=` fields or btime.
- Grep BOTH "Metadata corruption" AND "Corruption detected" (different xfs_error_report variants).
- errno: EFSBADCRC=-74, EFSCORRUPTED=-117(=EUCLEAN). A crc_ok=1 check does NOT catch a uuid mismatch.
- Envelope data offset = u64 @ byte 88 of sector 0; LBA = daddr + off/512. `fua_verify` reads only 512B — use `sg_dd iflag=fua` for full blocks; plain guest dd hits guest page cache.
- Probes are capped, NOT ratelimited (ratelimiting cost the decisive datum twice). Main ring rotates in ~5s under probe load — drc saves per-round `/root/drc_create_rN_rankR.dmesg`. `/root/drc_failrounds.txt` is CUMULATIVE across runs.
- Per-run cycle: virsh destroy×8 → start×8 → SSH-ready ~30-36s → restart console_capture per cycle → `timeout -k 15 700 ./run.sh 8 tcp dir_reuse_coherency` detached + foreground until-loop poll (~450s healthy). Map node-ids from the CURRENT mount's "DLM init: node_id=" line only.
- Storage restore after clyde reboot: `scripts/lio_tcm_setup.sh setup` + `echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass` (fileio backstore /home/steve/disk.img → tcm_loop → /dev/mxfs-shared). run.sh preserves FAIL logs at `/tmp/run_dir_reuse_coherency_<RUNID>/`.
