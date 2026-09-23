<!-- sess310-319: INODE-class release-defer containment (step-6 F1), 0.11.511-513: fault-inject blocked on ICLUS-only sites, GPT rulings, zsl regression r… -->
# INODE-class release-defer containment: step-6 F1, 0.11.511→0.11.513 (sess310-319)

Campaign to close ledger item step-6 F1: give the INODE release-defer class the
same bounded-containment guarantees sess307 built for ICLUS, verify both
classes with deterministic fault injection, and qualify the result. Chain runs
straight into the D-513 foreign-replay-refusal campaign (`docs/history/docs/history/compiled-d513-foreign-replay-refusal.md`)
that starts sess320.

## sess310 — 0.11.511 baseline: both boards green, defer machinery works under real load
`docs/history/docs/history/docs/history/compiled-inode-reldefer-containment.md`
0.11.511 (sv EB44E6A843CF082A799AF9D) deployed 32/caw. knob=1
(`release_proof_enforce=1`, default) FULL board 24 PASS/0 FAIL; knob=0
regression board matches 0.11.510. `cas_noproof_v2=0` fleet-wide both runs —
the step-9/10 gating invariant holds. `defer_oblig` fired naturally 5× across
4 nodes and every episode resolved via the retry worker: no wedge, admission
reopened, subsequent tests passed. Two anomalies both attributed to the
pre-existing pace family, not to .511: `crash_consistency` intermittent
NO_TERMINAL_RECORD under post-load hostload spikes, `ag_strand_repair`
marginal timing after `dirent_durability` churn.

Fault-inject engine already exists: `mxfs.relgate_fault_stage` (stage number,
0=disarm), `_res`, `_delay_ms`, `_oneshot`; hits logged as
`P282-RELGATE-FAULT`. 8 stage sites identified in the ICLUS release path
(`xfs_mxfs_dlm.c`, stages 1/3/7/9/10/11/13). No `tests/` driver existed yet.

## sess311 — fault-inject leg blocked: all 8 sites are ICLUS-only, ICLUS is off in production
`docs/history/docs/history/docs/history/compiled-inode-reldefer-containment.md`
Wrote `tests/relgate_fault_inject.sh` (defer + wedge modes, the source-tree rule). Two churn
variants (private per-node create/rm, then cross-node same-inode EX
ping-pong) produced **zero** `fault_hits` — only class=1 (INODE) certs, never
class=2 (ICLUS). Root cause proven by code reading + counters: all 8
`mxfs_relgate_fault()` sites live in the ICLUS release path and only fire
under `mxfs_icluster_dlm=1`, which defaults 0 (load-time-only, 0444) and was
never exercised by the sess309 step-6 machinery on any board. The second
churn variant did naturally exercise 18 defer_oblig + 19 tripwire_retries
(INODE-class), all resolved cleanly, `cas_noproof_v2=0` throughout — proves
INODE-class retry/enforcement holds under contention, but is not
fault-verified. A stale-looking code comment claimed two ICLUS prerequisites
(BAST fan-out, call-site routing) were still missing; sess312 found both had
actually landed already.

## sess312 — two GPT rulings: containment design, and why F1 stays open
`docs/rulings/inode-reldefer-containment-design.md`
`docs/rulings/step6-f1-option-c-dual-class-fault-coverage.md`

**Ruling 1 — INODE containment design** approves mirroring the ICLUS sess307
machinery (60s no-progress / 300s total → wedge: pin + WEDGE cert +
`P-INODE-WEDGE` + shutdown) onto the INODE class, with 10 required changes.
The load-bearing ones, in order of consequence:
1. **Defer-time admission containment is mandatory, not optional** — without
   diverting/waiting new proof-invalidating local admissions (EX at minimum)
   once a defer episode opens, the 300s cumulative bound is unsound because
   local churn can reopen obligations forever. GPT explicitly withheld
   approval of the bounds without this.
2. Explicit `WEDGED` admission gate in `ilock_begin` — mount-shutdown checks
   alone leave a visibility window and teardown has no shutdown.
3. Episode reset ONLY on a proved-complete CAS, never on reacquire/BAST/cause
   change — cause changes are progress evidence (refresh `prog_j`), never
   episode boundaries, because oscillating causes are exactly why the 300s
   total bound exists.
4. Episode deadlines must be checked at every dwork re-entry, BUSY branch
   included, or a reacquired holder parks in strikes-land for ~30min.
5. Freeze episode state on wedge (it's evidence); reset only after proved
   completion.
6. Teardown with retry disabled: immediate pin-only wedge, not a stripped
   slot — the same latent hole ICLUS pin already closed for class 2.
7. Fault sites need a `force` param (forced still-dirty / forced
   ticket-stale / forced proof-fail) — delay-only hooks give non-deterministic
   outcomes.

**Ruling 2 — F1 closure ruling**: stays OPEN until option (c): both classes
need deterministic fault coverage, not just INODE's natural-load evidence.
Corrects sess311's "ICLUS never enabled" claim — `icluster_dlm=1` had been
board-green twice before (0.11.290, 0.11.469) — and confirms the two
prerequisites the stale 46910 comment demanded had both landed (gated
release publication + admission gate + probe-based B6, sess41 refusal
lifted per sess46). Flipping the *default* still needs a `MXFS_PROTO_GEN`
bump; per-rig modarg enablement doesn't. Required before closure: (1) add
controlled INODE fault sites (proof failure, still-dirty, CAS interference);
(2) define the INODE persistent-failure policy explicitly rather than
inferring it from current code behavior; (3) qualify current build with
`icluster_dlm=1 release_proof_enforce=1` FULL board (27/27) — prior green
boards on old builds don't qualify .511; (4) run ICLUS fault legs (defer +
wedge, 300s bound); (5) run INODE forced transient/persistent cases under
production routing (`icluster_dlm=0`).

## sess315 — INODE containment landed, 0.11.512
`docs/history/docs/history/docs/history/compiled-inode-reldefer-containment.md`
All 10 sess312 ruling items implemented in one build (sv
DF5630A9C55F783FB6B8E56, NOT yet deployed). Key shapes: episode
enter/extend at both relbar arm sites via `mxfs_inode_defer_arm`, no
dedicated worker — the existing stranded re-arm/dwork owns retries with
episode-aware clamped backoff; close only on `cas_result==0` in
`mxfs_inode_relcert_finish`; wedge (`mxfs_inode_wedge`) is one-shot,
pins, certs, shuts down unless teardown+pin-ok; pre-CAS WEDGED re-check
added to both arms; new `P-INODE-WEDGE-FENCE` terminal admission gate in
`ilock_begin` diverts new EX admissions into the existing wait loop once an
episode is open (P79 nested-admit arms deliberately left ungated — a proven
self-deadlock breaker, bounded by the 300s wedge anyway); fault legs added
at stages 7/9/10 with a `fault_forced` cert field.

## sess316 — 0.11.512 knob-on regression: test1 serves a stale inode
`docs/history/docs/history/docs/history/compiled-inode-reldefer-containment.md`
Deployed knob-on, `zero_silent_loss` FAILED 2/2: test1 alone served ino=136
with size=14 (stale) instead of 262144, first 14 bytes matching the
*current* run's expected md5 prefix — i.e. test1's stale bmap pointed at disk
blocks now reallocated to a different file's data (cross-file leak). test1's
inode kept a stale incarnation (size+bmap) across a DLM grant re-acquisition;
no reload ran. .511 had passed zsl repeatedly the same day, so the
regression window is the sess315 surgery alone. Hypothesis at session end
(later refuted, see sess317): a sess315 `ilock_begin` edit admits a
re-acquire without going through the reload/FUA-fresh chokepoint. Defect was
left UNLEDGERED at session end.

## sess317 — mechanism proven; sess316 hypothesis refuted
`docs/history/docs/history/docs/history/compiled-inode-reldefer-containment.md`
Live dmesg on test1 shows the protective reload DID run and DID detect
reuse: `P34H-INCARN-POISON` fired correctly (`incore_gen` vs `fresh_gen`
mismatch → poisoning with ESTALE intent). The sess316 hypothesis is dead —
sess315's wait-loop edits only *narrow* admission, they cannot admit more
than .511 already did. Real mechanism, proven from live counters:
1. The poisoned-shell **retirement** path fails: the bounded-retry evict arm
   (`xfs_inode.c:1534-1548`) cache-hits the same shell every time
   (`inew=0 tries=6`) — `retry_iget` returns the poisoned inode instead of a
   fresh one.
2. **File reads were never gated** on `MXFS_IF_INCARN_STALE` — only
   lookup/create/unlink/rename/readdir checked it. Nothing on
   open/read_iter/mmap for regular files, so `md5sum` happily read the stale
   bmap: silent loss plus a genuine cross-file data leak.
3. Root of the cache-hit: the retire loop never calls
   `d_mark_dontcache()`, so `xfs_fs_drop_inode` keeps the hashed clean inode
   in icache — last `iput` never becomes an evict, and
   `MXFS_IF_INCARN_STALE` only clears on IRECLAIM recycle, which never
   happens.
4. What test1 actually served was a *second* stale incarnation (poisoned
   again after the first), hidden because `P34H` prints are
   rate-limited — a second silent reuse under the same repro window.

This session's finding directly produced the sess318 fix shape: the bug is
"failure mode after a correctly-detected poison," not "detection failure."

## sess318 — fix shape ruling + landed as 0.11.513
`docs/rulings/incarn-stale-fix-shape.md`
`docs/history/docs/history/docs/history/compiled-inode-reldefer-containment.md`
Ledgered as `D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512` (#89, critical).
design-consult ruling required set, landed whole in one build (0.11.513, sv
C774FEA614A2BB1AE74286F, NOT deployed at session end):
1. `d_mark_dontcache()` in the retire arm BEFORE `xfs_irele` — this is the
   actual root fix (last iput now evicts the hashed shell).
2. **Fail closed**: after the retry budget is exhausted, lookup returns
   `-ESTALE` — never hand a poisoned inode to the VFS. GPT's framing: "a
   retry budget must never become a safety budget after which stale data is
   allowed."
3. Central `mxfs_inode_incarn_estale()` gate applied to
   open/read_iter/write_iter/mmap-entry/fault/page_mkwrite/getattr/statx —
   `-ESTALE` not `-EIO` (NFS/cluster precedent); mmap faults get SIGBUS via
   a failed fault handler.
4. `d_revalidate` must reject a poisoned positive dentry
   (`-ECHILD` in RCU walk) — `d_prune_aliases` alone is insufficient because
   busy dentries survive it.
5. Existing mmaps can read page cache without re-entering the FS — pages
   must be unmapped/invalidated (`invalidate_inode_pages2`) and faults
   gated, so no dirty page can write back through a stale bmap.
6. `I_DONTCACHE` surviving a racing non-reclaimable cache hit is desired
   (last iput still evicts); a fresh/recycled inode must NOT inherit poison
   or DONTCACHE.
7. Accepted liveness caveat: a long-lived stale FD pins the shell — new
   incarnation unavailable until close; acceptable because all ops on the
   pinned shell now ESTALE.

## sess319 — 0.11.513 deployed; fix path unverified by natural repro; new critical corruption found
`docs/history/docs/history/docs/history/compiled-inode-reldefer-containment.md`
`zero_silent_loss` PASS 3/3, but `P34H-INCARN-POISON/-EVICT/-UNRETIRED`
fired **zero** times fleet-wide on this run — the retire/gate path was never
exercised, so D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512 remains
**functionally unverified** despite the green board (suspected cause:
lower hostload than the sess316 repro missed the eviction-ring race
window). Knob-on board batches 1-2 fully green (batch2 includes
`dlm_fairness` 28s, correcting an earlier capture-only red tally); batch3
had the pre-existing `dir_reuse_coherency` pace family FAIL plus two
NO_TERMINAL_RECORD captures.

**New unledgered critical** found live on test1 at session end (left live
for forensics, not yet ledgered): `XFS (dm-1): Corruption of in-memory data
(0x8) at mxfs_dlm_ilock_begin+0x3c53 (xfs_mxfs_dlm.c:30684)` → shutdown →
`P-WITHDRAW` → `P163-WITHDRAW-STAMP slot=0`, co-occurring with a
`P71-UNDERFLOW` on a `run.sh` marker-probe stat call. Line 30684 sits
inside/near the sess315 INODE-containment surgery region — prime suspect,
but uninstrumented at handoff (the instrument-first loop open). Noted but unproven: the
`read_iter` ESTALE gate in `xfs_file.c:349` runs *before*
`mxfs_read_coherency_envelope` at :362 where freshsrc poison actually
fires, so the very first read that triggers a poison could still consume
one stale bmap before any gate sees the flag — flagged as a possible
residual, explicitly not to be patched without a proving repro.

## Net state at handoff (end of sess319)
- Step-6 F1 still open pending the sess312-ruling (c) fault-coverage matrix
  (INODE forced-fault legs, ICLUS fault legs, dual production-config
  boards) — none of that matrix had run yet.
- D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512 (#89): fix landed (0.11.513)
  but not fault-verified — natural repro rate is load-sensitive and didn't
  fire on the .513 board.
- New unledgered critical: test1 `xfs_mxfs_dlm.c:30684` in-memory corruption
  shutdown, suspected in the sess315 surgery region, needs ledgering and
  the instrument-first loop investigation.
- This chain continues directly into the D-513
  foreign-replay-refusal campaign starting sess320
  (`docs/history/docs/history/compiled-d513-foreign-replay-refusal.md`).
