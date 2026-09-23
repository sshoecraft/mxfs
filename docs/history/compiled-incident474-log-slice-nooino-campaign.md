<!-- sess205-224: incident474 arc — #17 closed, #18 NL-setter+ILOCK-over-CAW-poll live-proven, #20 shared-log-slice root+fix, #27 ctx-lock starvation fixe… -->
# incident474 campaign: NL-setter hunt, log-slice sharing root cause, recovery ctx-lock starvation (ccloop c7ee71c6 sess205-224, 0.11.472→0.11.480)

One continuous arc: chasing #18's stray EIO led to a near-miss classification pass, which
led to a decisive corruption capture, which led to the incident474 cascade, whose root
turned out to be a completely separate defect (#20 shared log slices) hiding underneath it.
Closed along the way: #17, #20, #27. Still open at the end: #18 (arm A landed no fix yet,
just full live characterization), incident474 arm B (fix designed, not landed), #28.

## #17/#18 — Mode B EIO and the P95-OPEN-PROTECT-FAIL NL-setter hunt

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: sess204's theory
(EDEADLK bursts cause the rsync_paired test19 EIO) REFUTED by timing — the bursts sit
outside the failing rsync's window and all resolve via the P109 void-loop. Actual source:
`P95-OPEN-PROTECT-FAIL` (xfs_mxfs_dlm.c:36886) — the C3 open-protect hook fails closed
(-EIO) when `i_dlm_mode==NL` on re-read after the ilock ride, even though ILOCK_SHARED is
still held (not a post-iunlock race). One event explains the EIO, the leftover dotfile,
and the content-sum mismatch. Open question: why does the ilock ride ever exit with NL on
a live inode?

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: fleet sweep
shows the failure is single-shot (1 occurrence in 32 kernlogs) — not systemic. Every
candidate NL-exit path in `mxfs_dlm_ilock_begin` audited and ruled out by code
(admit_ioend gate, bounded-tries timeout, rc!=0 shutdown path, EDEADLK restart path — none
match). Found the chokepoint: all 26 real `i_dlm_mode` assignment sites transit
`mxfs_dlmtr_rec()`, watch_ino-gated for the ring but unconditional otherwise. Designed
instrumentation: stamp `i_dlm_nl_{line,pid,ns,comm,om}` on every granted→NL transition
before the watch gate, snapshot them (not re-read post-print) into the P95 print.

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: 0.11.473 lands the
instrumentation. TRAP: `make clean` wipes `tools/` binaries — run `make tools` before prep
or prep fails on missing mkfs_mxfs. Full board 27/27 green. #17
D-IUNL-LIVESKEW-REFUSES-PENDING-WINDOW-GRAFT-471 VERIFY criterion MET: 38 overwrite laps
clean, PENDGRAFT observed once (expected, benign), zero LIVESKEW. #18 probe armed but
silent across all 38 laps — plain lapping doesn't reproduce it.

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: #17 marked
FIXED AND VERIFIED (ledger idx71, 29→28 open). 54 total clean laps, zero P95 fleet-wide,
including 6 laps right after heavy DLM-churn chunks. Built 0.11.474
`P95-NL-UNDER-HOLD`: a near-miss probe that fires on ANY granted→NL lowering while
ex/pr holders are present, independent of the exact microsecond race. New tool
`module_swap_deploy.sh` (swap `mxfs.ko` fleet-wide without mkfs, preserving an aged fs) —
TRAP: `pkill -f 'rsync|fio'` over ssh matches the remote shell's own cmdline and kills the
session (rc=255); use `pkill -x`. **Using this tool to reform the cluster on the aged fs
triggered incident474**: 8/32 nodes wedged and shut down within ~2 min
(`P-NOINO-DRAIN-STUCK` → `P-NOINO-RELFENCE-WEDGE` → shutdown+withdraw), survivors showed
`P5N-AG-ORPHAN-NAK` and post-withdraw reservation conflicts. Event ordering not yet
established at handoff — this is where incident474 begins as an open incident.

## incident474 — ledgering, near-miss triage, decisive corruption capture

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: incident474
ledgered as two arms — `D-NOINO-RELFENCE-AIL-FREEZE-474` (arm A) and
`D-WITHDRAWN-NODE-CASCADE-NONCONTAINMENT-474` (arm B), critical, evidence moved off
volatile scratchpad to `tests/evidence/incident474/*.klog.gz`. Built 0.11.475/476: a
self-latching `ailstuck_probe` that arms at stall==2 so `P129-CLSKIP` names the frozen
item's skip reason in-incident. Measured baseline: pre-arming the probe fleet-wide is
counterproductive — healthy laps fire all four P129-CLSKIP reasons ~100+/lap/node, burning
ratelimit and stack-dump budget before any real wedge; the self-latch is the right trigger.
Captured but unanalyzed near-miss: test31 hit stall==2 on an inode-CLUSTER **BUF** item (not
INODE like the incident) — flagged for next-session triage.

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: the near-miss
classified NOT arm A — a benign, `P-NOINO-LISTDRAIN`-repairable class: a 5-node cascading
fence chain, each node stalling ~2s on its own local inode-cluster BUF item parked on
`pag_mxfs_alloc_buflist` (the documented `_XBF_DELWRI_Q`/`_XBF_MXFS_ALLOC_QUEUED` tension —
xfsaild can't write it), self-clears at stall==3. Discriminator vs arm A: P-AILMIN item
type BUF (benign, LISTDRAIN-repairable) vs INODE (arm A — ILOCK owner blocked in DLM,
LISTDRAIN can't repair that class). Found the stall==2 self-latch from sess211 was
**permanent** and accumulating fleet-wide noise (9/32 nodes latched within a day). Fixed in
0.11.477: fence-scoped latch (`mxfs_ailstuck_probe_fence_arm/disarm`), armed per-fence with
refcount, disarmed on fence success or min-advance, deliberately never auto-clears on
DRAIN-STUCK/shutdown (kept for post-mortem).

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: same session,
decisive capture — an rsync overwrite lap on 0.11.477 hit `xfs_iunlink_item_precommit`
metadata corruption on test6: dinode decode shows `di_next_unlinked=0x00081df6`, not
NULLAGINO — a fossil unlinked-list pointer from a prior tenancy. A rename displaced the
target inode onto the AGI unlinked list; precommit found the cluster-buf dinode already
chained → EFSCORRUPTED → shutdown. Classified as family #30
D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN / the P53 fossil-di_next_unlinked campaign — the
kernel-loud counterpart of #17's silent-EIO mode (do not merge the two without more
evidence; #17's next-steps 1-2, stderr capture + errno read, are now done for the loud
mode via this capture).

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: incident474 hole
(b) — the terminal cascade step — PROVEN: the elected replayer's own recovery kworker
(P97-SWEEP adopted-bucket path) blocked needing EX on an inode whose CAW slot was held by
a wedged victim; that victim's purge is deferred until ITS OWN slice replays, but the one
replayer is the one blocked here. 3×120s base timeouts then `P34-ACQ-SLOW` (dur_ms=360605)
→ fatal escalation to the **replayer's own shutdown**. The earlier "480s liveness-extension
cap" framing was wrong — it's base timeouts plus fatal escalation, no extension involved.
Hole (a) reclassified as-designed: UDP lease renewals deliberately keep running post-withdraw
(sess11 decision) so mastership doesn't migrate pre-replay; survivors just ignore them via
P164-DEAD-NOTE — log noise only. Hole (c) located: `P-WAIT-EXTEND` asks the in-memory
disklock HB tracker "alive?", which is true even for a wedged-but-not-yet-shut-down victim
— feeds pre-withdraw waits only. Single-victim containment verified clean; cascade requires
multi-victim cross-holding.

`docs/rulings/incident474-fix-set.md`: design-consult ruling (gpt-5.6-sol) on
the full containment fix set, to ship as packages, priority order:
1. **Hole (b)** — b2 (PRIMARY) strict phase split: fence+certify all victims → recovery
   barrier/epoch → replay ALL pending victim slices (pure buffer-level replay only, no
   lock-taking sweeps between slices) → mark each replay-complete durably → purge grants →
   THEN run deferred sweeps → leave barrier. b3 (MANDATORY backstop, ships WITH b2 not
   separately): elected replayer NEVER self-withdraws on lock timeout while victim
   recoveries are pending — classify the blocking holder instead (fenced+pending → redirect
   to recovery ordering; fenced+complete → purge stale grant + retry; live-unserviceable →
   serviceability policy; live+progressing → bounded retry; unknown gen → stop epoch,
   reconcile). b1 (general lock steal) REJECTED — fencing proves no future writes, not
   crash-consistency of grant-protected metadata pre-replay; only a narrow
   recovery-context-only, buffer-level-only, RECOVERY_BLOCKED-tagged bypass is safe.
2. **Arm A** — a1 authority-epoch state machine: AUTH_EX_OPEN → AUTH_CLOSING → AUTH_NL +
   epoch counter + active_auth_txns count; ifree after authority loss is never defensible
   (dlm_locked=1 is a reference, not authority); BAST release must drain active auth-txns
   before going NL. a2: hard rule, no blocking remote DLM acquire/CAW poll while holding
   ILOCK (inspect → drop ILOCK → acquire DLM → re-ILOCK → revalidate → restart). a3:
   containment only valid while EX stays held.
3. **Hole (c)** — c3 (=c1 serviceability states in the HB record, advisory-only, +c2
   per-holder/per-grant-incarnation progress cookies, anti-ABA on slot reuse; HB thread beat
   alone is NOT progress), staged rollout: telemetry first, then gate extension.

## #20 — the log-slice sharing root cause (the thing incident474 was actually hitting)

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: ROOT CAUSE of the
incident474 slot-30 forever-retry found. `mkfs_mxfs` defaults `log_node_count=4`;
`prep_fs.sh` mkfs's with no `-n`; at 32 nodes, `slice = slot % log_node_count` means **8
nodes concurrently write each of only 4 log slices**. The slot30_slice "two inconsistent
chains" seen in earlier incidents were two different nodes' interleaved streams, each
internally self-consistent — the soup produces a deterministic -EIO at
xfs_log_recover.c:1091 (empty search window). Confirmed: uniform uuid across all 1529 slice
headers with zero lsn-vs-block skew (H-A stale-residue theory refuted); corruption present
on the replayer's FIRST attempt, predating any post-death rewrite. Every prior 32-node
"victim slice" analysis assumed per-node slices — wrong premise; crash_consistency and
fence-replay tests had been replaying 8-writer soup all along. Collateral finding:
`xlog_clear_stale_blocks` is gated only on `!xfs_readonly_buftarg`, so foreign replay can
write into a victim's slice contrary to the documented no-touch intent.

`docs/rulings/log-slice-fix-shape.md`: design-consult ruling (gpt-5.6-sol) on
fix shape for D-LOG-SLICE-SHARED-MULTIWRITER: dual-layer guard (userspace: disklock slot
admission constrained to `[0, log_node_count)`; kernel: re-check `slot < log_node_count` at
slice selection AND at foreign replay, release the claimed slot on every mount-fail path);
remove `%` entirely from every log-addressing path, replace with one checked helper
(`slice = slot` after an explicit bounds check); validate geometry in the kernel too, don't
trust mkfs alone; mkfs must size the log for `count*16384` blocks + overhead and fail loud
rather than clamp/shrink; foreign replay order = fence → recovery ownership → read-only
scan/validate → replay → stale-clear, and NEVER stale-clear after a find_tail
corruption/-EIO (preserve the slice as evidence); legacy filesystems formatted 32-on-4 are
corrupt-by-construction in ALL slices — reformat is the only defensible disposition;
mixed-version gate still owed (an old kernel would still modulo-map). Central invariant
carried forward: "a filesystem slot has exactly one identically-numbered log slice, and no
node may participate unless that slice exists." Bounded retry/escalation for an
unreplayable slice stays a separate defect (feeds back into incident474 arm B).

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: fix VERIFIED —
`incident474_load_kill.sh 32 test28 180` on 0.11.479 kills slot 30; replay log reads
"foreign replay of dead slot 30 (**slice 30/32**)" (identity mapping live), zero
`P238-FENCE-NOSLICE` fleet-wide, all 31 survivors mounted clean. Same run captured **#18
live for the first time**, fully instrumented: `rm` in `xfs_inactive_truncate` holds ILOCK,
blocks in `caw_wait_for_grant` on a victim-held AG0 grant — **PROVES the a2 "ILOCK held
across CAW poll" hypothesis live**. AIL min freezes on that INODE item
(`P129-CLSKIP ILOCK_NOWAIT_FAIL`); at +287s `P-NOINO-DRAIN-STUCK` try=8 →
`P-NOINO-RELFENCE-WEDGE` → forced shutdown — **17s before the in-flight purge would have
freed AG0 on its own**. The wedge detector isn't recovery-aware; it can't distinguish an
unbounded wedge from a bounded in-flight-recovery wait. Cascade contained: only the
recovery-owner node died, peers replayed clean. Same run surfaced a NEW unledgered defect:
the recovery path holds disklock `ctx->lock` for ~35s across recovery stage 3→5
(`P-HB-SLOW lockwait_ms=34978`), more than half the 62s lease — if purge ever exceeds the
lease, the recovery owner self-fences mid-recovery. Precedent: sess38 fixed the identical
pattern in `read_all` (disklock.c:2332, per-slot lock/unlock instead of held-across-I/O).

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: ledger
caught up to 32 open/20 critical. #20 fix+verify evidence recorded (owed for closure: full
board + GPT-ruling extras — mixed-version gate, slot-reuse race, no-stale-clear-after-fail).
#18's ILOCK-over-CAW-poll arm entered as proven-live. NEW
`D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION` (high) opened from sess221's finding. incident474
arm B folded in: b2+b3 landed 0.11.478, verified for single-victim and no-load
multi-victim; under-load multi-victim cascade reproduced on .478 but traced entirely to the
#20 shared-slice bug (now fixed) — remaining real holes: (i) an unreplayable slice still
retries forever with no classification/escalation, (ii) the b2 gate is coarse — one stuck
slot blocks ALL victims' sweeps/purges fleet-wide, should be per-slot, (iii) hole (c)'s
c1+c2 progress cookies not yet landed. First honest post-slice-fix board launched — every
PRIOR 32/caw crash_consistency PASS is now suspect, since it replayed 8-writer soup. Trap:
piping a backgrounded `run.sh` through `tail` buffers ALL output until EOF; the output file
stays empty while it's running — poll criteria.json mtime or `virsh` instead.

`docs/history/docs/history/docs/history/compiled-incident474-log-slice-nooino-campaign.md`: that board's
FAIL (rsync_paired + crash_consistency NO_TERMINAL_RECORD=32) diagnosed to completion: not
infra, not a degraded node, not the build — ledger #28
D-32NODE-SHARED-DIR-CREATE-PACE manifesting. Standalone isolation showed crash_consistency
on a virgin fs already rides ~90% of its 90s budget (80s) at the board's host-load level;
the board lap's extra jitter tips it over, harness kills mid-verify, producing
NO_TERMINAL_RECORD everywhere. Per the derived-budget rule, budgets stay as-is; the real fix routes through
#28's root (mount-global O(N) create term). Separately, `D-RECOVERY-CTXLOCK-HOLD-HB-STARVATION`
(#27) FIXED AND VERIFIED in 0.11.480: `purge_lock` now held across the whole
`mxfs_disklock_purge_node` scan (HB thread never takes it), `ctx->lock` taken per-I/O
instead (phase-0 reads, scan reads, each `purge_cas_zero`, retry re-reads, HB-scan) with
amortized ~2s mid-scan revalidation. Verified via the same load-kill harness: zero
`P-HB-SLOW` fleet-wide (was 34978ms on .479), zero P229/P234/P235.

## Net state at sess224 handoff

Closed FIXED AND VERIFIED: #17 (sess208), #20 log-slice sharing (sess221/222), #27
ctx-lock HB starvation (sess224). Still open: #18 (arm A live-characterized, a1/a2 fix
designed by sess214 ruling but not yet landed; NL-setter instrumentation never refired
after the initial single-shot), incident474 arm B (b2+b3 landed 0.11.478 but the coarse
per-fs gate and hole-c progress cookies are not), #28 create-pace (root-cause work
resumes via `tests/cc_stackprof.sh`), family #30 AGI-unlinked-crossnode / P53 fossil
(sess212's EUCLEAN capture is new decisive evidence, unresolved). Fleet on 0.11.480 at
32/caw with `MXFS_LOG_SLICES=32` prep.
