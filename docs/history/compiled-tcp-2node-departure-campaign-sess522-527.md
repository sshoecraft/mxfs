<!-- TCP 2-node campaign sess522-527 (0.75.36-0.75.45): D-482/D-0916/D-0917/D-0918/D-0919 closed F&V, D-0920/D-0921 filed, TCP DEMAND gap, pace signal. -->
# TCP 2-node campaign, sess522-527 (2026-09-05 -> 2026-09-08, tree 0.75.36 -> 0.75.45)

Continuation of `docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess518-520.md` under the
standing two-node-TCP-only directive. Chronological; ledger count is open-of-total
at each checkpoint.

## sess522 (2026-09-05)

- D-482 phantom-grant bail CLOSED F&V on 0.75.36 (sv A067540B). s521a's injection had
  forced the P106 check to say "not held" while the TCP master still held the EX grant;
  bail dropped the cache with no wire release and forced a shutdown. The fix was to the
  *instrument*, not the product: the injection shot now calls
  `mxfs_v5_dlm_inode_unlock_gen(dlm, ino, 0)` behind the cache and re-samples the check,
  producing a genuine phantom (wire lost a grant the cache still believes). Harness lesson:
  `tests/d482_phantom_epoch_2node.sh`'s positive case must target a subdirectory — a
  regular file in the affine AG exits `d_revalidate` through the affine path before the
  d_time stamp and never reaches the epoch fast path. `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- D-AFFINE-FASTPATH-STALE-DENTRY-VECTOR-UNTESTED: measured across 6 legs of
  `tests/affine_stale_dentry_2node.sh`, then CLOSED DISPROVED. The affine exit only
  answers for a child whose grant the node holds or never held since the last fresh
  lookup — every release path (BAST/close_release/idle/sweep) runs
  `mxfs_dlm_bast_process` -> sets `i_dlm_stale` (stale_src=5) *before* the wire unlock, so
  the peer cannot remove/re-point the name without the child's EX; the stale check at
  `xfs_super.c:3459` precedes the affine exit. Recycle-clobber is unreachable on 2 nodes
  by construction (only one node allocates per AG, and the in-core stale inode pins the
  number). Harness lesson: clock-offset "stale windows" of 21-64ms across ssh are noise,
  not blessings; inode numbers recycle within a lap — key by `ino@birthtime`.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- NEW DEFECT found and filed: **D-0916**, hot-file cached grant starves a peer's unlink
  until the local writer stops. Regular-file ilock fast path checks only `i_dlm_mode`
  (dirs additionally gate on `state==CACHED` since v0.3.13); during a peer-triggered
  release drain (state DEMOTING) the local writer's rounds keep being admitted and
  re-dirty the inode, so drain completes only when the writer stops. Peer `rm` measured
  2.5-4.5s, returning ~100ms after the writer loop ended. Fix 0.75.39 (sv
  1022AD181B38A8BFFB68572): `mxfs_file_yield_gate` in the fast path — a user task with
  pin 0 that is not the demoter, in state BAST or DEMOTING-with-foreign-demoter, falls
  through to the demote-wait instead of being re-admitted; RELFLUSH admission narrowed to
  `PF_KTHREAD`. Verified via `tests/hot_inode_peer_unlink_2node.sh`: 92-415ms with the
  fix vs 3049ms (+2 timeouts) with the knob off.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- sess522 END: 0.75.39's yield gate REGRESSED `dir_reuse_coherency` (BARRIER_TIMEOUT
  116/120s) — a task self-parked in the demote-wait behind its own nested local hold
  (self-nested IOLOCK/ILOCK), released only by 3s rescue polls (`P-FILE-YIELD ino=...
  req=5 ex=1` firing every ~3s). Fix 0.75.40: `mxfs_file_yield_gate` additionally
  requires `i_dlm_ex_holders == 0 && i_dlm_pr_holders == 0` before yielding — do not yield
  away a lock the current task itself holds. Ledger 83 open.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

## sess523 (2026-09-05, same day)

- D-0536 CLOSED F&V (pre-fix/fix/board evidence from s520). 82 -> 83 open (D-0917 filed).
  0.75.40 deployed; hot-inode lap threw one 1533ms outlier against otherwise-clean
  78-91ms laps. Root: a remove-path AG **pre-acquire steal convoy** — B (`rm`) holds the
  dir inodes, its silent trylock on AG0 misses because A caches it; the handoff releases
  the inode, blocks for AG0, pregrants CACHED, relocks; A's writer round (truncate under
  ILOCK) blocks for the same AG0; B's cached AG0 releases at holders=0; A's round
  completes and hands the AG back to B; B's restart trylock misses again. Cycle count ==
  wall time / ~90ms. Filed **D-0917** (high). Fix 0.75.41 (sv 0E6B89885AF7D381249C3C8):
  `mxfs_preacq_poll` in `mxfs_trans_preacquire_inode_ags` — before the handoff, if no
  other AG grant is registered on the transaction and it is clean, try one demanding
  nonblocking acquire then silent nb retries every 2-3ms up to `preacq_poll_ms` (default
  100); on hit, defer-unlock and continue the sweep; on expiry, fall back to the old
  handoff. `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- 0.75.41 MADE THINGS WORSE: 84/84 polls expired at the 100ms bound; unlink latency rose
  to 4.9s (14 deadlines) then 40.9s (51 deadlines), one lap exceeded its 60s bound.
  ROOT: `MXFS_LKF_DEMAND` was honored only by `dlm_caw.c` (CAS on the slot's sticky
  revoke bit) — the TCP engine (`dlm/dlm.c`) silently denied any NOQUEUE|DEMAND lock at
  both deny sites (local master and remote master) with `MXFS_ERR_DEADLOCK`, issuing no
  BAST to the holder. Every "bounded nb sweep" that relies on demand (including the
  D-488 `mxfs_ag_dlm_lock_bounded` fix) was therefore inert on TCP; only the CAW rig had
  ever exercised it. **Lesson: a DLM flag's semantics must be checked in both engines
  (`grep dlm/dlm.c` AND `dlm/dlm_caw.c`) before building on it — a TCP-only campaign
  surfaces gaps CAW-era fixes never saw.** Fix 0.75.42: `demand_collect_holders` /
  `demand_fire` at both TCP deny sites — BAST the conflicting granted holders like a
  queued request would, without actually queuing; probe `P-DEMAND-BAST`.
  [[trap-mxfs-lkf-demand-was-caw-only-tcp-noqueue-deny-never-basts-the-holder]]
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- Prep run after 0.75.41+0.75.42 wedged: BOTH nodes failed to release mxfs, requiring
  `virsh destroy/start` on both to recover. ROOT: **D-0918** (critical) — permanent
  2-node deadlock. FIX-27's writeback-admit widening (`mxfs_ilock_admit_ioend`) admitted
  a PR writeback submitter during BAST/DEMOTING but incremented `ex_holders`
  unconditionally; `ilock_end` for the PR request then decremented `pr_holders`
  (`P71-UNDERFLOW mode=PR`), leaving `ex_holders` permanently +1, so every subsequent
  BAST on that inode deferred forever. The writer never released the file; the peer's
  `rm` held the dir in the handoff relock waiting on the file; the writer's next open
  waited on the dir — a full cross-node cycle parked forever by D-0912's live-wait logic
  (476/479 deadlines in 8 minutes). Fix 0.75.43 (sv 89B05E7199FA14F2B256AE3):
  `mxfs_ilock_admit_ioend` counts the admit into the counter that the *requested* mode's
  end will decrement; probe `P25-IOEND-ADMIT` now prints `now_pr`. Bug was as old as
  FIX-27 (0.11.201) and transport-independent — 0.75.41's tighter poll cadence just made
  it easy to hit. A parallel lead was left open: `P71-UNDERFLOW mode=PR` also occurs on
  **directories** (`mxfs_dlm_dir_consumer_refresh` 37x, `xfs_dir_lookup` 41x,
  `mxfs_getattr_dlm_unlock` 8x, `xfs_file_readdir` 4x, `xfs_dir_open` 2x) — unresolved,
  possibly the same leak class. `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- Board 0.75.43 (s523x): 25 PASS, 0 FAIL, 2 FLAKY(history), `dir_reuse_coherency` 102s.
  Closed F&V: **D-0916** (0.75.39/40, RELFLUSH admission narrowing was the working
  part), **D-0917** (0.75.41 preacq poll + 0.75.42 TCP DEMAND fix; 4 laps 82-94ms,
  `P271-PREACQ-POLL hit=1 waited_ms=28`, zero AG handoffs), **D-0918** (0.75.43 ioend
  admit accounting; zero underflows). 81 open. Affine lap `s523w` FAIL was a **trace
  artifact**, not a defect: `P-VNLOOKUP`/`P-DREVAL-STALEFLAG` were
  `pr_warn_ratelimited` and hit the kernel's rate limit under an 8-lookups-in-150ms
  burst, while `P-DREVAL-AFFINE-FAST` was plain `pr_info` — the trace lines disagreed on
  logging class, not the code path. Fix 0.75.44: both lines to `pr_info` under the
  per-dir trace knob. **Lesson: verify a probe's log level matches its siblings before
  trusting a "missing" trace line as a defect signal.**
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- sess523 END: rig healthy on 0.75.44 (sv A83D443CCAC68FD2606ADA8), 81 open of 240.
  D-0536/D-0916/D-0917/D-0918 all closed F&V this session. Annotated and left open
  (32-node legs out of scope under the two-node directive): D-0288 (2-node verification
  complete, only the 32/tcp leg owed), D-398 (2-node repro unreachable by construction —
  allocation is strictly node-affine, test1 always AG0 / test2 always AG1, even inside
  the other node's directory), D-0912 (only a CAW leg owed). D-0346 verified PASS
  (`dir_recreate_estale.sh`, 1348 attempts, 0 ESTALE). **New harness pattern that found 3
  defects in one session**: adversarial two-node races under a hot local writer/holder —
  generalized into `hot_inode_peer_rename_2node.sh`, `append_contention_2node.sh`, and a
  planned hot-writer/peer-reader md5 harness.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- Addendum: miner pass over 12 open TCP records' `next` fields for 2-node-closable items.
  D-0340/D-0341/D-0343/D-0345 (fixes landed 0.35.1/0.35.2) and D-0347/D-0348/D-0352
  (TAUTH bootstrap/collision/ramp) all require **32-node** evidence to close — out of
  scope, annotate only; `tests/tauth/concurrent_release_test` can still serve as a
  usermode regression check without the rig. D-0286 (TCP wedge pin no-op) may reach its
  master-failover arm on 2 nodes (kill the master while a peer holds grants) —
  candidate for a future harness. D-0349 (smallfile pace), D-0281 (convoy stall),
  D-READDIR-PEER-CACHED-DIR-PACE are measurable on 2 nodes now.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

## sess525 (2026-09-08, after a clyde reboot on 09-06)

- clyde rebooted 2026-09-06 13:38 (no new pstore record); test1/test2 had been shut off
  and were restarted via `scripts/vm_cycle.sh`, which now must wait for `/run/nologin` to
  clear before the srcversion gate (first prep attempt failed on the nologin banner).
  Nodes auto-mount `/mnt/shared` at boot on 0.75.44.

- Three of the new adversarial harnesses from sess523 END run NOPREP on 0.75.44, all
  PASS on integrity: `hot_inode_peer_rename_2node.sh` (rename 30-43ms under a 4000-iter
  writer, both nodes agree on old/new inode identity); `append_contention_2node.sh`
  (barrier + overlap assertion, 2000 lines exact, byte-identical views; per-append pace
  0.3-7.7ms depending on lock-batching lap to lap); `hot_writer_peer_reader_2node.sh` (0
  torn/short reads across 292-318 reads over 300 64KiB writes; 23.6ms median cycle).
  `peer_truncate_under_append_2node.sh` was written but not yet run.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- D-0349 (smallfile create pace) signal reconfirmed on 2 nodes:
  `tcp_token_plumbing_verify.sh` timed out (rc=124) on both nodes at 30s with only 764
  files created — ~40ms per 4KiB create. Matches the board's `sustained_load` row
  (`per_op=101ms`, `mkd=53ms`). sess472's `readdir_peer_pace` passed at 4000 creates/90s,
  so either the pace regressed since 0.64.x or the per-file 4KiB data write is the
  dominant cost — undetermined at this checkpoint.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

## sess527 (2026-09-08, 0.75.44 -> 0.75.45)

- **Lesson, filed after two prior sessions (18068c22, b9a80fb7) died on the server-side
  classifier reading raw kernel logs directly**: never load raw dmesg/hits files from
  `tests/evidence/` into the main context — dispatch a log-sweeper subagent and ask for
  specific fields only. `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- **D-0919** filed and CLOSED F&V: two-phase dialloc AGI-release local-racer causes a
  spurious EFSCORRUPTED create. Field symptom: `Internal error i != 1 && j != 1
  xfs_ialloc.c:2221 xfs_dialloc_ag_finobt_near`. Mechanism PROVEN by A/B with
  `tests/create_race_last_free_inode_2node.sh` (4 racers x 800 creates, same AG):
  validate=1 (two-phase on) gave 131 events / 48 chunk exhaustions; validate=0 gave 0
  events / 50 exhaustions. `mxfs_dialloc_two_phase` brelse's the AGI after its candidate
  platter read; a *local* racer (AG EX only excludes peers, not local threads) takes the
  last free inode; phase 2 re-reads freecount==0 and searches an empty finobt. Fix
  0.75.45: after the AGI re-read, `pagi_freecount==0` -> `P-DIALLOC-P2-EMPTY`, mark
  `rs->swept=1`, return -EAGAIN so the caller grows a chunk or moves on. Verified after
  deploy (0.75.45, sv 2E38E09AFF3E1742CC470B4): s527d (4x800, loop overran the pace
  bound) 42 exhaustions / 42 `P2-EMPTY` / 0 events; s527e (4x500, completed) 31/31/0,
  2000/2000 creates OK. Pace ~45-56ms/create measured with the two-phase validation both
  on and off — **the AGI validation read is not D-0349's root cause.**
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- **D-0920** (critical, filed from a Sept-5 transcript, then REPRODUCED live): concurrent
  create race leaves peer-AG files with zero extent records / empty content. Original
  Sept-5 lap (s525g, 0.75.44): 137/200 files read EMPTY on test2
  (`xfs_bmap_validate_extent_raw` corruption, zero bmap record under `nextents=1`,
  `from_disk rc=-117`); test1 corrupted too after `drop_caches`. Reproduced on 0.75.45 via
  `concurrent_create_race_2node.sh` (s527f, NOPREP): every open returned rc=0 and every
  file resolved on test1's view, but "both nodes read identical directory contents"
  FAILED and kernel health logged 178 corruption hits. Mechanism still UNKNOWN; leading
  candidate is protected-reload adopt combined with a core-only flush publishing stale
  fork bytes (code-reading hypothesis, not yet instrumented).
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- **D-0921** (critical, filed from the same Sept-5 transcript, not yet reproduced on
  current tree): append multipage 64KiB record lost together with a
  `P-LKTIMEOUT-REMOTE`. Sept-5 lap (s525e, 100x64KiB writes per node): 199/200 records
  intact, one 64KiB record lost. The rewritten `append_contention_2node.sh` has no
  multipage arm yet — a `REC` byte-size argument was added (dd single-write records,
  verifier splits by REC) but not yet run against this defect.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- Sept-5 session had left an undefined call `mxfs_iflush_fork_audit` in `xfs_inode.c`
  (tree did not build). sess527 implemented it: a static fn above `xfs_iflush` that
  compares the staged fork against the re-encoded in-core fork, probe
  `P-IFLUSH-FORK-STALE`, knob `iflush_fork_heal` (default 0, copies the in-core fork over
  when set) — intended as the instrument for chasing D-0920.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

- `peer_truncate_under_append_2node.sh` finally run (s527h): PASSED every integrity
  check (contiguous lines A9515..A20000, 0 NUL bytes, identical views across nodes) but
  truncates took 167-236ms under the hot appender against a 100ms bound — FAIL on pace,
  a new finding in the D-0916/D-0917 starvation family, not yet filed as its own record.
  Ledger at this checkpoint: 84 open of 243.
  `docs/history/docs/history/docs/history/compiled-tcp-2node-departure-campaign-sess522-527.md`

## Recurring lessons across this arc

1. A DLM lock flag's semantics must be verified in **both** engines
   (`dlm/dlm.c` and `dlm/dlm_caw.c`) before a fix relies on it — MXFS_LKF_DEMAND was
   CAW-only for the project's entire life until 0.75.42, and every CAW-era "bounded nb
   sweep" fix was silently inert on TCP.
2. The ilock fast-path's holder-count bookkeeping must always decrement the *same*
   counter mode it incremented at admit time (D-0918) — a mismatch between requested
   mode and admitted-as mode produces a permanent BAST-deferral deadlock, not a crash,
   so it surfaces only as an unresponsive prep/mount.
3. A "missing" trace line is not evidence of a missing code path until its log level
   (`pr_info` vs `pr_warn_ratelimited`) is checked against its siblings — sess523's
   affine FAIL was a rate-limit artifact.
4. Adversarial two-node races (hot local writer/holder vs. a peer unlink/rename/read)
   are a disproportionately effective harness shape: three critical/high defects
   (D-0916, D-0917, D-0918) came from one such pattern in a single session, and D-0919
   from its create-race variant.
5. Never load raw dmesg/evidence files into the main session context — the server-side
   classifier has killed at least two sessions doing this; always delegate to
   log-sweeper and ask for specific fields.
