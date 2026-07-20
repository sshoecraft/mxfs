---
name: compiled-tcp-dlm-doublegrant-gentoken-fix
description: Compiled: TCP-DLM dir-EX double-grant heisenbug + gen-token fix, cc dir-evict in-AIL discriminator, residual stale-readdir root.
metadata:
  type: project
tags: [compiled, tcp-dlm, double-grant, gen-token, crash-consistency, dir-coherency, heisenbug]
---

# TCP-DLM dir-EX double-grant, gen-token fix, and residual dir-coherency

Scope: the early TCP-DLM port (`force_transport=1`, 2-node test1/test2) fighting the
`tcp_dlm_scaling` / `crash_consistency` / `dlm_fairness` / `cache_coherency` family toward a
reliable 16/16. Test method throughout: `./run.sh 2 tcp` (full suite ~5min) or standalone
`./run.sh 2 tcp <test>`; a `tcp_dlm_scaling` fail wedges the FS → reboot + reset between attempts
(`tests/reboot_cluster.sh 2`, virsh destroy+start test1/test2 to recover a wedge).

## Build progression (chronological)
- **73B0809D5381454A7F9B070** — B4 inode guard + P-RDDIAG (mxfs_instr-gated). 15/16;
  `tcp_dlm_scaling` ~50% flaky (F,F,P,P,F,F). [[sess-tcp-tcp-dlm-scaling-flaky-dir-lostupdate-root]]
- **F053F523...** — B4 broadened to `!=EX`. 15/16; sole fail `tcp_dlm_scaling` stale-readdir
  (nlink=0 leftover). [[sess-tcp-15of16-tcp-dlm-scaling-stale-readdir-root]]
- **98EC6332DCE76B24C5E1038** — B4 + THREE dormant diagnostic gates (mxfs.instr/dirwr/lockwr, all
  OFF; behaviorally == 73B0809D). Double-grant PROVEN. [[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]]
- **30D3C28E** — B4 + dormant traces, 15/16. Canonical pre-fix fallback.
  [[sess-tcp-double-grant-instrumentation-impossible]] [[sess-tcp-double-grant-mechanism-refinement]]
- **1ED7A5FD7AA0DD081826A62** — cc dir-evict in-AIL discriminator (KEEP). 15/16.
  [[sess-tcp-cc-FIXED-dir-evict-inail-discriminator]]
- **404BC55CA1AF4A73317C3DA** — BOTH landed fixes (cc dir-evict + DLM gen-token). Achieved multiple
  clean 16/16 back-to-back. Best build. [[sess-tcp-STATE-two-fixes-landed-residual-dir-drain]]
  [[sess-tcp-DLM-double-grant-FIXED-gen-token]]
- **4886CEC9 / BEA13E27** — heartbeat-interval experiments, both REVERTED (see below).
  [[sess-tcp-heartbeat-reduction-insufficient]]
- **E8BF16B2** — later stable build; cross-DLM-tenure shortform-rename root proven.
  0E611CA4 was a bad interim (6 FAIL / test2 FS shutdown), REVERTED.
  [[sess-tcp-ROOT-dir-ex-release-handsoff-stale-disk]]

Fallback chain: 404BC55C (both fixes) → 1ED7A5FD (cc only) → 30D3C28E (neither).

## Blocker #1: TCP DLM dir-EX DOUBLE-GRANT (fixed by gen-token)

**Proven root.** `tcp_dlm_scaling` (each node 150× `create+rename(.done)+rm` of its OWN files in
ONE shared dir; node1 checks `ls` drained==0) leaks 1 dirent ~50% of runs — always reproducible
enough to bisect. The leftover is a NODE2 file, both nodes agree, persistent across drop_caches =
genuine ON-DISK dangling dirent, either nlink=1 (rename+rm reverted) or nlink=0 (inode freed,
dirent resurrected). P-REG-DURABLE-FAIL=0: releases ARE durable — the node durably wrote the WRONG
content because a peer concurrently RMW'd the same dir block. P106 cross-node EXGRANT/EXREL
timeline proved it: one node held dir-EX ~6.2s while the OTHER acquired+released EX TWICE inside
that window → BOTH hold dir-EX → concurrent RMW → durable revert.
[[sess-tcp-tcp-dlm-scaling-DOUBLE-GRANT-proven]]

**Mechanism narrowed.** The holder NEVER RELEASED (test2 EXGRANT at ...482023, next EXREL ~6.2s
later at ...488247; test1 acquired EX at ...482400/...482456 with no intervening test2 EXREL). So
it is NOT a stale/duplicate LOCK_RELEASE and NOT the -ETIMEDOUT retry re-firing a release — those
fix classes are DISPROVEN, do not pursue. It is a NON-release removal of the holder's master-table
entry while the holder still holds it cached: the Bug-51 stale-removal paths in `dlm/dlm.c`
(remote master ~2081-2134 "stale re-request conflicts with other holder" → removes entry →
`promote_waiters` ~2116 grants the waiting peer; local equiv ~890-911). The HOLE Bug-51 left:
"holder re-requests/converts while a waiter exists" (a PR→EX conversion, or a re-acquire where
`i_dlm_mode` transiently != EX so the XFS fast-path is missed) — master removes+promotes without
BASTing the holder, holder was never recalled and still believes it holds EX cached. The 6.2s hold
≈ `MXFS_LOCK_ACQUIRE_WAIT_MS` (6s -ETIMEDOUT retry interval) implicates the retry as the trigger
that exposes the race. [[sess-tcp-double-grant-mechanism-refinement]]

**HEISENBUG — un-instrumentable in-band.** TWO independent in-kernel trace mechanisms BOTH make
`tcp_dlm_scaling` go 6/6 PASS: (1) printk per-lock-op (mxfs.lockwr=1 → P-LKT), and (2) a
LOCK-FREE, NO-printk per-CPU event ring (a few struct-field writes under the already-held
table_rwlock, post-mortem dump via `lktdump` param). The race window is sub-microsecond; any
in-band recording at the DLM lock sites shifts timing enough to close it. RULE 4's "instrumented
proof before patch" is PHYSICALLY IMPOSSIBLE in-band here. Observation alternatives noted but
untested: ftrace function tracer (~100ns/event, might be low enough), Intel PT, post-hoc lock-table
crash-dump; a single-node counter detector CAN'T see it (divergence is master-table 1-holder vs the
OTHER node's cached i_dlm_mode=EX, not locally visible; TCP has no shared EX-holder bitmap, unlike
CAW's `mxfs_v5_dlm_inode_ex_count`). [[sess-tcp-double-grant-instrumentation-impossible]]

**Validation is ALSO unreliable — the critical trap.** Adding even the lock-free no-printk ring
made it 6/6 PASS = a tiny timing perturbation closes the race WITHOUT fixing root. Therefore ANY
code "fix" that adds instructions in the DLM acquire/grant/release path also perturbs timing and
can show 15-20/20 standalone passes as a pure TIMING ARTIFACT, falsely reading as fixed while root
is untouched (would resurface under any future timing shift). You CANNOT trust a pass-rate
improvement as proof, and you CANNOT instrument to prove the mechanism. The fix MUST be PROVEN
CORRECT BY CONSTRUCTION (protocol reasoning), not by running the test. Empirical bar if used
anyway: ≥15-20 CONSECUTIVE standalone passes (0.5^15 ≈ 3e-5) then full suite ×2-3 for regressions.
[[sess-tcp-double-grant-validation-also-unreliable]] [[sess-tcp-gen-token-fix-impl-notes]]

**Refuted fix classes:** eviction / cold re-read (both holders' blocks are dirty — refuted);
gen-bump-on-release (REVERTED, regressed crash_consistency); RELEASE-only fencing token (holder
sent no release — patches a disproven hypothesis).

### THE FIX — grant-generation token (build 404BC55C, KEEP)
Grant-generation protocol; re-affirm not remove+promote. [[sess-tcp-DLM-double-grant-FIXED-gen-token]]

Wire/struct (include/mxfs/mxfs_dlm.h; single-version cluster so wire growth OK — but the original
`pad[3]`/`pad[2]` spares were too small, fields had to be ADDED; verify recv-path length handling
does not reject the larger message):
- `mxfs_dlm_lock_resp += uint32_t grant_gen`; `mxfs_dlm_lock_release += uint32_t grant_gen (+pad)`.
  8192B peer buffer; CAW unaffected (doesn't use these structs).
- `struct mxfs_lock += uint32_t grant_gen`; `mxfs_dlm_ctx += uint32_t grant_gen_next` (init 1);
  `dlm_next_gen(ctx)` monotonic, never 0, under table_rwlock. (dlm/dlm.h, dlm.c)
- `process_remote_grant`/`process_remote_release` signatures += grant_gen; both dispatchers
  (v5_mount.c, mount.c) extract resp->grant_gen / rel->grant_gen.

Protocol (dlm/dlm.c):
1. Every GRANTED transition stamps `entry->grant_gen = dlm_next_gen` (promote_waiters, immediate
   grant, re-affirm, conversion); the GRANT echoes it.
2. `process_remote_request`, sender already GRANTED with mode>=req: ALWAYS RE-AFFIRM — keep entry,
   bump gen, re-send grant, NEVER remove+promote a waiter. (Deleted the Bug-51 still_safe block AND
   the stale-removal+promote branch = the proven double-grant site.)
3. `process_remote_release`: ignore a STALE release (grant_gen != entry->grant_gen, both nonzero) —
   holder re-acquired since; keeps Bug-51 fixed without remove+promote. gen==0 → old unconditional
   remove (liveness fallback).
4. `process_remote_grant` (client): UPDATE existing mirror in place (no dup); if !mirror &&
   !matched → UNSOLICITED grant (re-affirm arrived after we released) → REJECT: send gen-stamped
   RELEASE so master drops the phantom + promotes the real waiter (prevents phantom-EX hang).
5. `mxfs_dlm_unlock` echoes the mirror's grant_gen in its RELEASE.

Validation: `tcp_dlm_scaling` PASS 2/2 (was ~50% flaky); durable-wrong-content GONE; no
regression (dlm_fairness passes 4/4 standalone; crash_consistency + cache_coherency + posix_multi +
all DLM tests PASS). CAUTION: the gen guard changes the SAME stale-removal logic the Bug-51
-ETIMEDOUT-retry fix added (which made posix_multi pass) — regression-test posix_multi + cache_coherency.

## Blocker #2: crash_consistency dir-entry visibility (fixed by in-AIL discriminator)

**Proven root.** `crash_consistency` (each node writes 50 data files oflag=sync then 50 `.md5`
sidecars, barrier "cc_written", drop_caches, then every node md5-verifies every node's files)
reliably FAILS in the full suite (cumulative-state dependent — passes standalone / 2-test). Fail
line `node2_fNN(exp= got=<hash>)` with exp EMPTY. Forensics (tests/suite/crash_consistency.sh,
fires on FAIL): `stat -c%i` returns EMPTY = node2's `.md5` file is ENOENT/not-visible on test1, NOT
empty content. The DATA file IS visible; only node2's LATER-created `.md5` dirents (f31..f50)
missing, f1..f30 visible (dir grew to block/leaf; test1 has some dir blocks fresh, the block with
the latest entries stale). A 2nd drop_caches+reread still empty; minutes later test1 sees all.
TRANSIENT shared-directory entry-visibility lag. `xfs_lookup` igets with lock_flags=0 → test1
performs NO dir-DLM acquire → reads its stale cached dir blocks (sess127 gap, on TCP).
[[sess-tcp-cc-ROOT-dir-entry-visibility-lag]]

### THE FIX — reader-path evictor in-AIL discriminator (build 1ED7A5FD, KEEP)
Root site `mxfs_dir_evict_data_blocks` (xfs/xfs_mxfs_dlm.c ~L1864), the reader-path eager
dir-block evictor called by `mxfs_dlm_dir_consumer_refresh` (top of xfs_lookup/readdir). It
computed `undurable` with a COARSE `XFS_LI_IN_AIL`→undurable term and SKIPPED any in-AIL block
(P-EVICT-SKIP) — but a block whose last local mods are already write-submitted merely LINGERS in
AIL until the log tail advances, so skipping left this node serving its own stale base, missing a
peer's newer dirents. The MODIFY-path sibling (~L2447, sess101/v0.5.2) and the lazy xfs_da_read_buf
hook (sess133) already used the cross-node-safe discriminator `mxfs_dir_buf_is_undestaged(bp)` (=
`b_mxfs_logged_seq != b_mxfs_written_seq`, plus pinned); the reader path was left behind. FIX:
`undurable = dirty || pinned || _XBF_DELWRI_Q || !XBF_DONE || (in_ail &&
mxfs_dir_buf_is_undestaged(dbp))` — an in-AIL-but-destaged block is now EVICTED (force FUA-refetch
of the peer's superset) instead of skipped; mirrors the modify path. Genuinely committed-unwritten
work (logged!=written) still kept → low regression risk. Validation: crash_consistency 2/2 in-suite
(was reliable FAIL). [[sess-tcp-cc-FIXED-dir-evict-inail-discriminator]]

## Residual on 404BC55C: intermittent shared-dir READDIR staleness

With both fixes landed, the ONLY thing between 404BC55C and reliable 16/16 (~33-50% of runs, 1-2
tests): `<t> shared dir drained exp=0 got=1` (tcp_dlm_scaling, dlm_fairness) and cache_coherency
cross_visibility. PROVEN reader-stale: after a barrier, rank1's `ls`/readdir shows 1 leftover
dirent already removed on disk; resolves on its own seconds later.
[[sess-tcp-STATE-two-fixes-landed-residual-dir-drain]]

**Root.** `i_dlm_dir_gen` (dir-data-block coherency epoch) advances ONLY by (a) a peer's commit
notify via the disklock EVICTION-RING, consumed by the heartbeat thread once per
`MXFS_DISKLOCK_HB_INTERVAL_MS` = 2000ms (dlm/disklock.c), or (b) the reader's OWN slow-path DLM
reacquire (xfs_mxfs_dlm.c:6925 `i_dlm_dir_gen++`). Stale window: reader HOLDS the dir lock cached
(fast-path, no reacquire → no gen bump), a peer modified the dir, and the 2s heartbeat hasn't yet
delivered DIR_MODIFY → consumer_refresh sees gen unchanged → doesn't evict → stale dirent. Narrow
race against the 2s heartbeat. The earlier (build F053F523) framing: `xfs_readdir`
(xfs/xfs_dir2_readdir.c:554-561) reloads only when `MXFS_IF_DIR_RELOAD` is armed by a peer's
DIR_MODIFY evict-ring event; SHORTFORM dirs (line 563) bypass even i_dlm_dir_gen block-invalidation
in xfs_da_read_buf; when the FINAL DIR_MODIFY is lost/not-delivered (intermittent on TCP; sess82
evict-ring-never-delivered) node1 never arms reload and serves stale, persistently.
[[sess-tcp-15of16-tcp-dlm-scaling-stale-readdir-root]]

**Earlier same-root finding (build 73B0809D):** dirwr=1 at a real failure showed P106-MR-SKIP
476/447, P106-MR-EVICT 1/4, P-DIRBAST 4/6, DIR-STALE-SKIP=0 — the gen-keyed dir modify-refresh
(`mxfs_dlm_dir_modify_refresh`) almost never evicts because the acquire-side gen bump
(xfs_mxfs_dlm.c:6902) is slow-path only and doesn't fire on cached fast-path reacquires
(releases 4-6 >> evicts 1). REFUTED (build E4DFA811, REVERTED): bumping i_dlm_dir_gen on the dir-EX
BAST RELEASE (xfs_mxfs_dlm.c:4118) — tcp_dlm_scaling STILL failed AND crash_consistency regressed
(over-eager eviction exposed non-durable peer reads). KEY LEARNING: forcing eviction (cold re-read)
does NOT fix resurrection → the stale data is ON DISK, not stale clean cache → a node releases the
dir grant with final dir-block/nlink state not yet durable (drain-pipeline incompleteness at
release; Architectural Invariant 1). [[sess-tcp-tcp-dlm-scaling-flaky-dir-lostupdate-root]]

**Heartbeat tuning is a DEAD END.** Reducing `MXFS_DISKLOCK_HB_INTERVAL_MS` (with scaled DEAD/LIVE
thresholds to hold the 62s/4s wall windows): 500ms/4x (build 4886CEC9) WEDGED the cluster
(posix_multi 0/2, mkfs failed runs 2-5, virsh destroy+start to recover) — 4x FUA-write +
eviction-dispatch load tips into stall→barrier-desync→wedge, DO NOT use. 1000ms/2x (build BEA13E27)
STABLE but clean rate ~1/3 = no improvement over 2000ms's ~1/4 (cc sleeps ~1s, a 1s window still
races). Both REVERTED to 404BC55C. Faster polling doesn't close the race.
[[sess-tcp-heartbeat-reduction-insufficient]]

**Safe fix direction (untested):** the reason gen is NOT advanced on fast-path is WRITER
lost-update (RMW from stale base). A READDIR is READ-ONLY → forcing a coherent dir-block refresh
cannot lose data. GFS2 pattern: in multi-node readdir when the node holds NO current grant
(`dp->i_dlm_mode == MXFS_LOCK_NL` → a peer could have modified since release), force a coherent
reload instead of relying on the async event (sound: if we held PR/EX no peer could have modified).
MUST verify readdir actually acquires a PR grant (NL→PR) so repeated readdirs of a hot dir don't
reload every time (the sess38/91 per-readdir-poll 100x regression). Alternatively decouple
eviction-ring consumption from the HB write cadence (read peers' rings ~250ms, write HB + dead-count
every 2s, scale the dead threshold). SCOPE it — do not force on every readdir/lookup (root+parent
dirs are hit constantly by rsync_paired; RULE 0 barrier-desync). INSTRUMENT FIRST (RULE 4):
P-EVICT-SKIP / P104-CONSUMER-REFRESH / P-DIR-SEQ / P-RDDIAG to confirm fast-path-hold-no-evict fires
before patching.

## Deeper residual root (build E8BF16B2): cross-DLM-tenure shortform-rename lost-update

Beyond the readdir-refresh gap, the shared-dir-coherency family (crash_consistency / dlm_fairness /
cache_coherency / tcp_dlm_scaling) flakes on a distinct PROVEN root. Test: each node 150×
`echo r>f; mv f f.done; rm f.done` in ONE shared dir. The leaking round's `create` and `mv`
STRADDLE a dir-EX handoff: node creates n_rN (holding EX), is BAST'd before its `mv`, releases,
re-acquires EX for the `mv`. At the mv's re-acquire, `mxfs_dlm_reload_inode` rebuilds the SHORTFORM
fork from the on-disk dinode — which is MISSING n_rN because n_rN's create was only LOGGED (CIL),
not checkpointed to the inode cluster on the platter. So `xfs_dir_removename(src=n_rN)`
(xfs/libxfs/xfs_dir2.c:1647) returns -ENOENT (proven P-RENAME-SRCDEL rc=-2). Two manifestations:
(1) durable LOST-UPDATE — target n_rN.done added+rm'd, source n_rN never removed, leftover nlink=1
survives drop_caches; (2) FS SHUTDOWN — removename -ENOENT after the rename dirtied the txn →
xfs_rename → xfs_trans_cancel(dirty) → xfs_error_report → shutdown (proven trace on test2), which
is why a bad run shows many tests 0/2 (a node's FS shut down).
[[sess-tcp-ROOT-dir-ex-release-handsoff-stale-disk]]

Why release-side durability fails (P-ICD probe in `mxfs_inode_cluster_durable`): at dir-EX BAST
release the dir inode is `clean=1 rerr=-EAGAIN` (iflushed into its cluster buffer, nothing to
flush) but `delwri_q=1 in_ail=1 pin=0` — the cluster buffer is still DELWRI-QUEUED / log item still
in AIL: the buffer write was never submitted. Committed dir image sits in a delwri buffer (→ target
write-cache), NOT on the platter; peers FUA-read the platter (pierces SCST cache) → stale.
P-SFREL-VERIFY: loopexit_size==incore_size but disk(FUA platter) differs (not a concurrent-mod
race). `mxfs_inode_cluster_durable`'s -EAGAIN path just msleep'd hoping xfsaild submits within 16ms;
under churn it doesn't → returns false having never landed the buffer.

Fix attempts this session (E8BF16B2 line): (1) BAST-release shortform cluster flush
(`mxfs_dlm_dir_inode_durable` in mxfs_dlm_bast_process ~3608) — KEPT (correct direction, harmless)
but INSUFFICIENT (the -EAGAIN gap means it doesn't land the buffer). (2) -EAGAIN "drive the delwri
buffer" — BOTH variants BAD, REVERTED: (a) `xfs_ail_push_ag_sync`(whole AG) STALLED cluster
(cache_coherency 0/2; sess82 warns whole-AG sync push stalls multi-node) — DO NOT re-add whole-AG
push in this hot path; (b) surgical `xfs_buf_delwri_submit` / `mxfs_dlm_ag_drain_alloc_buflist` on
the cluster buffer → test2 still shut down (build 0E611CA4, 6 FAIL). `mxfs_inode_cluster_durable`
back to proven-safe original. (3) reload self-skip for dirty shortform — REVERTED (Gemini: acquire
must blindly reload). Gemini verdict (RULE 5): release MUST make committed dir state durable to
PLATTER before dropping dir-EX, then acquire blindly reloads; the release must DRIVE the
delwri-queued inode-cluster buffer (submit + wait + blkdev_issue_flush) WITHOUT a whole-AG stall.
Next directions (untested): (a) make n_rN's create durable to the inode cluster BEFORE the dir lock
can be released — the create-side barrier `mxfs_dlm_dir_inode_durable` EXISTS but is SKIPPED for
self-created parents (creates BEFORE the first BAST on the shared dir are unprotected); (b) make
xfs_rename robust to removename -ENOENT on the source (re-lookup / don't dirty-cancel → avoid the
shutdown); (c) a reliable non-stalling per-buffer destage in the -EAGAIN path. Verify each `./run.sh
2 tcp` ×3 back-to-back: 16/16 every time AND no FS shutdown (watch dmesg for xfs_trans_cancel /
Call Trace).

## Cross-cutting lessons
- **A pass-rate is not a proof.** For a sub-µs Heisenbug both instrumentation AND code-fix timing
  perturbations can fake a pass. Prove protocol fixes by construction; treat pass-rate only as a
  weak regression signal (≥15-20 consecutive standalone).
- **Forcing eviction / cold re-read does NOT cure durable staleness** — repeatedly refuted
  (E4DFA811 crash_consistency regression). If cold re-read still shows the bad value, the bad value
  is ON DISK → the bug is a drain/durability-at-release problem (Invariant 1), not a cache problem.
- **Whole-AG sync push in a hot release path stalls the cluster** (sess82); never re-add.
- **Two coupled coherency epochs:** DLM inode grant (mutual exclusion) is decoupled from dir-DATA
  block writeback lifecycle and from the `i_dlm_dir_gen` refresh epoch — holding the inode PR does
  NOT refresh separately-cached dir data blocks; the gen bump is slow-path-only, so cached
  fast-path reacquires never advance it.
- **Diagnostics (all gated OFF by default, harmless dormant):** mxfs.instr (100x heavy), mxfs.dirwr
  (dir coherency: P-ICD, P-SFREL-VERIFY, P-RENAME-SRCDEL — P-ICD unratelimited + per-release FUA
  HEAVILY perturbs, targeted capture only), mxfs.lockwr (P-LKT lock-table ring, dumped via `lktdump`
  param), P-RDDIAG (readdir grant mode). B4 inode guard is KEEP across all builds.
- **B4 inode guard** (xfs/xfs_inode.c ~2763, KEEP): `mxfs_b4_no_authority = !local_unlink &&
  i_dlm_mode != MXFS_LOCK_EX && coh_nlink==0 && !xlog_recovery_needed(mp->m_log)` — a node with no
  local-unlink intent and not holding EX has no authority to destructively free a coh_nlink==0
  inode; cleared the rename-storm shutdown cascade.
