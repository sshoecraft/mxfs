<!-- sess197-204: GPT ruling on tenure-release invariant (F1-F4), gate build-order steps 1-3 landed 0.11.469-471, LIVESKEW fix 0.11.472, Mode B EDEADLK fo… -->
# Tenure-release gate campaign (sess197-204, 0.11.469-472)

D-FOREIGN-REPLAY-UNGATED-IMAGES item 2 build-out: instrument then gate the
peer-claimable release predicate for AG/inode/ICLUS/dir tenures, per the
sess197 GPT ruling. Continues after `docs/history/docs/history/compiled-tenure-token-shadow-eval-lineage-campaign.md`
(sess162-178); D-IUNL-LIVESKEW work in sess203-204 is a side branch hit while
soaking the same fs.

## sess197 — GPT ruling on the release invariant (RULE-5)

`docs/rulings/tenure-release-hard-barriers-f1-f4.md`

Unified predicate: a resource becomes peer-claimable only after local
mutation quiesced, every home-write obligation of the retiring tenure
completed, the required persistence barrier covers those completions, and an
immediate pre-CAS recheck shows none of those facts changed.

Four hazards, all ruled HARD release-blocking barriers except F2:
- **F1** (xfs_mxfs_dlm.c ICLUS `make_durable` 250ms "releasing anyway" on
  timeout): never unlock on timeout — deferred-release state machine
  (DEMOTING → block admissions → retain grant → self-rescheduling drain
  worker, never depend on BAST redelivery → retry proof → unlock only on
  proven predicate → bounded no-progress escalates to wedge/shutdown).
- **F2** (`fua_disable=1`, no real flush at tenure boundary): HARD whenever
  target power loss is in scope — "single shared target" reasoning is
  UNSOUND, volatile cache loss can persist arbitrary subsets. Needs
  `mxfs_blkdev_flush_durable` after the last home completion, before any
  peer-claimable CAS, for all classes including AG. Two supported modes:
  crash-durable gate mode, or volatile-target/coherence-only mode gated by a
  SEPARATE domain knob (`mxfs_target_cache_protected`) — never overload
  `fua_disable`.
- **F3** (FUA-mode check-to-CAS window): proof must be completion-driven —
  quiesce, drain all, verify zero obligations/inflight, capture `dirty_seq`,
  flush, recheck unchanged, final pre-CAS tripwire.
- **F4** (dir committed-never-submitted): per-tenure obligation registry,
  created once per dirty generation on commit, retired only when home iodone
  covers the latest committed generation, cancelled on trans abort.

Build order fixed for the whole campaign: gate stays DISABLED through steps
1-8 (prereq knobs → certs/counters/fault-hooks → common release-proof helper
→ F4 registry → F3 into ICLUS → F1 deferred worker → F2 crash-durable mode →
audit-mode boundary boards), enabled per class only at step 9, global enable
only at zero invalid certificates and zero oracle mismatch (step 10).

## sess198 — steps 1+2 landed, 0.11.469 (not yet the deploy)

`docs/history/docs/history/docs/history/compiled-tenure-release-gate-sess197-204.md`

Observation-only, behavior unchanged. Step 1: fail-closed gate-enable
prerequisites (`mxfs_target_cache_protected`, `mxfs_replay_gate_enforce`
per-class bitmask whose setter REFUSES until F1/F3/F4 readiness consts flip).
Step 2: `struct mxfs_release_cert`, 18 stable fault-injection stage IDs from
the ruling, counters split into `cas_dirty` (F1 signal) vs `cas_noticket`
(F2 signal), P280/P281/P282 probes. Wired into the ICLUS choke point
(`mxfs_iclus_make_durable`, `mxfs_iclus_disk_release`) — this is the only
class instrumented so far. Under default `fua_disable=1`,
`cas_noticket≈attempts` is the expected shape, not a regression.

## sess199 — 0.11.469 deployed; vacuity root found

`docs/history/docs/history/docs/history/compiled-tenure-release-gate-sess197-204.md`

`make clean` also deletes `tools/` binaries — run `make tools` before
`prep_cluster` (recorded standalone as [[trap-make-clean-removes-userspace-tools-run-make-tools]]).

Both knob=0 and knob=1 (`icluster_dlm=1`) boards 27/27 PASS. One
`dir_reuse_coherency` FAIL at knob=0 attributed to the known marginal
dir-pace family (#23/#24) — disproven as a .469 regression because
`release_cert` attempts were 0 fleet-wide during that run.

**Vacuity root**: `icluster_dlm=0` (shipped default) makes the whole ICLUS
layer inert scaffolding — `mxfs_iclus_disk_release` can never execute, so
step-2's cert instrumentation is unverifiable in the default config. Cert
machinery verified live only at knob=1 (23.2k attempts, `cas_dirty=0`,
`cas_noticket==attempts` exactly as F2 predicted, zero defers/wedges).
Conclusion for the campaign: step 3 must convert the per-inode release path
first, since that's where default-config releases actually happen.

## sess200 — step 3 first increment, 0.11.470

`docs/history/docs/history/docs/history/compiled-tenure-release-gate-sess197-204.md`

`mxfs_relbar_close_or_defer` becomes the common per-inode release-proof body,
optionally filling a cert; both wire-unlock arms in `mxfs_dlm_bast_process`
(anchored/noanchor) now emit class-1 certs. Deployed at knob=0 (restoring
shipped default after sess199's knob=1 excursion); smoke test shows the
exact ruled F2-domain shape (`cas_noticket==attempts`, zero wedges) — the
sess199 knob=0 vacuity is closed. Confirms `VERSION` file does not reach
`mxfs.ko` (no Kbuild -D plumbing) — srcversion is the only deploy identity.
`run.sh` accepts multiple test names for chunking a board into <10min
foreground calls.

## sess201 — .470 board green, release-state machine lands as .471

`docs/history/docs/history/docs/history/compiled-tenure-release-gate-sess197-204.md`

0.11.470 knob=0 full board: 27/27 PASS, no dir-pace marginality this run;
cert telemetry across the fleet all zero on the hazard signals
(`cas_dirty`, `tripwire_retries`, `drain_timeouts`, `wedges`).

0.11.471 (not yet deployed) adds the per-resource release state machine:
`enum mxfs_release_state` (ACTIVE/DEMOTING/DRAINING/PROVED/RELEASING/WEDGED),
`i_mxfs_rel_state` per-inode (telemetry-only, races not prevented), new
`cas_unproved` counter/P283 probe. Invariant for later gate-enable: 0 before
steps 9-10 — `cas_unproved>0` means the proof body was skipped, raced, or
timed out (an ICLUS settle timeout shows in both `cas_dirty` and
`cas_unproved`).

## sess203 — LIVESKEW fix lands as 0.11.472 (side branch)

`docs/history/docs/history/docs/history/compiled-tenure-release-gate-sess197-204.md`

Separate defect surfaced while soaking on the campaign's fs:
D-IUNL-LIVESKEW-REFUSES-PENDING-WINDOW-GRAFT-471. GPT ruling adopted (c)
strengthened: per-inode pending-transition certificate
`{old, next, valid}` published at iunlink item creation (release-ordered
before `i_next_unlinked` advances), overlay decision on skew: cert
explains it → graft; image already at cert.next → accept; unexplained →
refuse (kept). Plus narrow precommit backstop repairing a fossil match under
the cluster buf lock instead of an EFSCORRUPTED shutdown.

0.11.472 (sv 9EF804271D01AA283D14131) landed and deployed: 4 rsync_paired
laps all PASS vs 0.11.471's cadence of 2-3 fails/lap. Caveat noted at the
time: the cert machinery never actually fired in that window — this is
no-recurrence, not mechanism-exercised proof.

Also opened: D-RSYNC-OVERWRITE-LAP-USERSPACE-FAIL-ERRNO-UNKNOWN (rsync
rc!=0, no kernel probes, errno uncaptured) — resolved next session.

## sess204 — Mode B errno captured; #17 soak lesson; two board timeouts

`docs/history/docs/history/docs/history/compiled-tenure-release-gate-sess197-204.md`

**#17 soak lesson**: 20 consecutive rsync_paired laps (4 from sess203 + 16
here) all PASS, zero firings of PENDGRAFT/POSTSTATE/FOSSILFIX/CERT-STACKED/
LIVESKEW/OVERLAY/GENSKEW. `OVERLAY=0` is decisive: the store-record-live +
stale-platter-image collision never occurs on a fresh fs — the 0.11.471
failure cadence was measured on an fs *aged* by prior board chunks.
Widening the timing window would not help; the missing ingredient is
precondition (an aged fs), not timing. Reproduction route: run board chunks
(dir_reuse, cache_coherency, crash_consistency churn) THEN rsync laps.
Grep trap: `P53` alone matches rsync temp filenames
(`.file26.A5nP53`) causing false positives — grep `P53-` or the full probe
name.

**Mode B captured**: rsync_paired FAIL on test19, `mkstemp` EIO (rc=23),
concurrent with kernel `DLM inode lock failed ... rc=-35` (EDEADLK) bursts on
sequential fresh-create inode ranges. None of the known EDEADLK probes
(`P109-CAW-EDEADLK`, `P-SELF-STALE-EDEADLK`, `P-CONVBLK-DENY`) fired — the
actual print site is `dlm/v5_mount.c:4756`
(`mxfs_v5_dlm_inode_lock`), an unprobed EDEADLK return path. Next step (open
at session end): trace EDEADLK→EIO in the create path and instrument it.

Two board chunks on .472 hit `NO_TERMINAL_RECORD` timeouts
(`zero_silent_loss` at 60s, `crash_consistency` at 90s) as apparent
first-run-after-marathon slowdown; both reconverged 32/32 on retry, left as
open RULE-0 observations, not diagnosed.

Ops facts recorded: `tools/mxfs_sshpass.sh testN "cmd"` takes no `root@`
prefix (auth fails with it); `run.sh` preserves fail logs at
`/tmp/run_<name>_<RUNID>` even though the printed tmp dir is deleted.

## Campaign state at sess204 end

Deployed: 0.11.472 (sv 9EF804271D01AA283D14131), fleet-verified, knob=0.
Gate steps 1-3 (prereqs, certs, per-inode common release-proof body) landed
and board-verified; step 3's release-state machine (0.11.471) landed but
folded into .472's deploy without a dedicated board pass. Outstanding: step 4
(F4 obligation registry, dir first), the unprobed EDEADLK→EIO source, board
chunks 3-5 on .472, and confirming `cas_unproved=0` post-.471/.472 merge.
