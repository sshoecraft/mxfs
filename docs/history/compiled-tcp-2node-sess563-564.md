<!-- TCP 2-node campaign sess563-564 (0.75.85-0.75.93): D-0930/0936/0928/0929/0931/0933/0940/0923/0927 closed F&V; D-0932/0939/0924 root-attributed, still… -->
# TCP 2-node campaign, sess563-564 (0.75.85 → 0.75.93)

Continues `docs/history/docs/history/compiled-tcp-2node-restart-campaign-sess561-562.md`. Ledger moved
93 → 85 open (66 → 58 critical) across the two sessions.

## Ledger-hygiene lesson that shaped both sessions

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`:
D-0930's fix had been in the tree since 0.75.72 (`xfs/xfs_icache.c:56-89,
:2288-2332`) with a harness (`tests/d0930_root_iget_bound.sh`) written and never
run. **Read the code a `next_step` names and check for an existing unrun harness
before designing new work from it** — running the existing one took 21s and
closed a critical. D-0936 closed the same session on
`tests/sole_survivor_gate_probe.sh` (positive arm) + `tests/tcp_death_replay.sh`
(negative arm, gate still certifies with no other registrant) — both arms
necessary, since the positive arm alone can't distinguish a correct conditional
refusal from a disabled gate. Trap avoided: s581a superficially satisfied
D-0930's bound but actually failed on a different path
(`lock request failed after 60 retries`, no `P-IMAP-UNTRUSTED-AGLOCK-*` line) —
a bounded failure is not evidence for a specific bound; always confirm the
fix's own named line fired.

**The shared-owed-list trap**
(`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`):
D-0928/0929/0931/0932/0933 all carried the identical owed list from prior
sessions ("run s567, cluster_restart_nomkfs x2, tcp_2node_death_chain, then
close"). Running it once and having it pass would have closed all five — but
measured per-record across both laps, only D-0928/0929/0931 actually fired
their signature lines (`P-HB-GHOST-DEAD eq=31`, `P236-FENCEKIND kind=21`,
`P-BARRIER-SLICE-PUBLISHED` both nodes). D-0932/D-0933(part 2) fired zero
`P238-FENCE-*` lines everywhere — same shape, same lap, but the fencing-takeover
path was never entered. **A shared owed-list is not shared evidence**; each
record needs its own fired-line check even when the harness run is identical.

## D-0932 / D-0933 — reaching fencing-takeover on a 2-node rig

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`:
new knob `dl_fence_postintent_pause_ms` (dlm/disklock.c, in
`mxfs_disklock_recovery_fence_intent`, right after the PREEMPT/ABORT log)
parks a prover with a durable intent laid and nothing issued under it — killing
it there leaves exactly what a prover dying mid-attempt leaves. 0644 so it can
be armed on one node at runtime without differing insmod args; interruptible,
so it can't park a D-state task. Probe: `tests/d0932_fence_takeover_probe.sh`.

D-0933 CLOSED both parts: the fence key passed is `mxfs_disklock_victim_key(...)`,
verified four ways (not the victim's node id; platter dump shows
`fence_key` == victim's own `pr_key`; recovery completed, which a key no target
holds cannot do).

D-0932 stays OPEN on its second gap: the fix path is
`v5_holder_slot_state` (v5_mount.c:10432-10456), a FALLBACK consulted only when
the primary view (`v5_incarnation_state`) returns UNKNOWN. It ran 118 times and
answered UNKNOWN every time — revocation always came from the view, never from
the fallback, so the fallback path itself stays unverified. The owed arm: reach
takeover with the holder's own slot already EMPTY/RETIRE_PENDING while its
attempt still stands, judged by a node that did not watch the death — and
assert `verdict=REVOKED` specifically, since `P238-FENCE-TAKEOVER` alone can't
tell which of the two routes fired (this is how it nearly got closed on the
wrong evidence).

## D-0936 — the prescribed arm was structurally vacuous

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`:
running the record's own prescribed arm (`fence_bootsucc_inject_refuse=1` on
`ghost_slot_restart_probe.sh`) hit `P238-FENCE-GATE-TRY=0` on both nodes — the
injection fired but the gate's guard (`nlive==1 && other_live<0`) was false on
both halves, because in a concurrent whole-cluster restart both nodes reach
`active_count=2` before either evaluates its fence. **Generalizes: the gate is
unreachable whenever the second node becomes a member on its own schedule —
the register-before-claim window closes on its own and must be held open
deliberately.**

New knob `mount_postregister_pause_ms` (v5_mount.c) holds a mount after its PR
key is registered/published/reserved but before slot-limit/bootstrap/claim —
logs `P238-POSTREG-PAUSE`/`RESUME`. New probe
`tests/sole_survivor_gate_probe.sh`. On this arm, A's mount is *expected* not to
complete (it has no route to prove exclusion with boot-succession injected
off) — that's the injection working, not a failure.

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`:
verified non-vacuously on 0.75.88 — `P238-FENCE-GATE-TRY=9` with `nlive=1
other_live=-1` (genuinely reached), `P-PR-GATE-NOTSOLE=9` naming a real
registrant (node B, held by the postregister pause) at a real gen, `ISSUE=0`.
B's mount completed cleanly (rc=0) with both pre-fix failure signatures (`log
recovery write I/O error`, `failed to locate log tail`) absent. Confirms why
the positive arm alone is insufficient: an unconditional refusal would pass
every one of these assertions too — the negative control (gate still certifies
with no other registrant) is what proves the refusal is conditional.

## D-0940 — intermittent two-node mount deadlock

Filed from
`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`,
which opens with a self-correction: the failure first looked COUNT-dependent
(COUNT=0 failed, COUNT=300 passed) but repeating COUNT=0 passed and COUNT=300
failed elsewhere — it's intermittent (1 of 4 laps/hour on 0.75.90), and
`COUNT` has no branch in the harness at all. The real defect: concurrent
no-mkfs remount of both nodes deadlocked past both the mount's 20s bound and
the harness's 60s ssh bound, no shutdown/BUG/error to userspace — test1 stuck
asking test2 for AG 0 (`P-LKTIMEOUT-HOLDER ag=0 holder=<test2>`), test2 stuck on
the root inode behind `holder=4294967295` (the D-0935 pre-fix blocker
signature, previously zero across twelve journals — back here on a sibling
path). Separately noted here: the harness's `FAIL ... got=` empty is a
truncated-capture artifact (`timeout 20 mount` doesn't kill a kernel-retry-loop
mount, so the outer `timeout 60` ssh bound fires first) — same failed-measurement
class as the `tcp_death_replay.sh` MXFS_DEV bug (see the trap note below). Also
noted: a separate, independent D-0927 finding, `pages_prepared=1 skipped=0
cand=2` violating that record's own `pages_prepared==cand` requirement.

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`:
fix landed 0.75.91 in `dlm/dlm.c`'s acquire-timeout path (~:5330) — an imported
shared holder with owner `MXFS_DLM_NODE_UNKNOWN` is re-asked against
`slot_node_cb`; if the slot now names a node the bit is attributed
(`P-TAUTH-IMPORT-RESOLVED-ONTIMEOUT`) and can be BASTed/released. New injection
knob `dl_inject_import_unresolvable` forces the race (natural rate ~1 lap in
4). Probe went VACUOUS twice: once because a clean unmount purges the shared
holder bits the defect needs (fixed by destroying VMs instead of unmounting),
once because whichever node wins the page-takeover race does the importing and
it's unpredictable (fixed by arming BOTH nodes and scoring across both
journals).

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`:
CLOSED FIXED AND VERIFIED, `tests/d0940_unknown_blocker_probe.sh` s587a,
non-vacuous on every gate (injection fired, precondition formed, fix's own
resolved-line fired, `UNRESOLVED-ONTIMEOUT=0`, both mounts rc=0). Both fixes
were needed together: destroy-not-unmount AND arm-both-nodes. Honest limit
recorded for reuse: the re-ask takes the slot's CURRENT `{node,inc}` — if the
slot was re-claimed by a different node than the bit's writer, the bit gets
attributed to the wrong node (no worse than the permanent UNKNOWN it replaces,
but it's attribution, not proof).

## D-0939 — root attribution without spending rig time

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`:
H-0939-B disproven by re-reading `coord_barrier`'s own source
(`tests/suite/coord.sh:61-105`). Retained MQTT markers mean a subscriber sees
any already-published rank immediately — so test2 clearing `drc_r2_wr` proves
test1's marker was ALREADY published, i.e. test1 arrived and published first.
The as-filed record's primary/consequence reading was backwards: test1 timed
out waiting for a peer that hadn't arrived yet, and test2's later failure is
the consequence, not the cause. The discriminator that would settle "no
reporting budget left" vs "peer genuinely late" exists in `coord_barrier`'s
stderr but `coord_barrier_or_abort` (coord.sh:221) redirects both streams to
`/dev/null` — every BARRIER_TIMEOUT this project has ever ledgered is an
undifferentiated symptom. Instrumented (CHANGELOG 0.75.87) before any fix per
the instrument-first loop; reproduction was still owed at session end.

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`
finishes the root-attribution: the failing run's own complete artifact
(`tests/evidence/run_dir_reuse_coherency_20260905T165217Z`) sat unopened through
**four sessions** while two separate hypotheses (H-0939-A, then the sess563
retained-marker inversion above) were built on the board's `reason` string
instead. The artifact's own third terminal record — never surfaced on the
board — shows the reporting budget was spent mid-round (round 2, elapsed 116s
of a 100s budget), `coord_eff_timeout` returned 0, and both nodes recorded
BARRIER_TIMEOUT without either side waiting on an absent peer. The barrier
timeouts are consequence; the primary event is round pace, and that pace event
is D-0923's mechanism (82 acquire timeouts/~1s each inside the 116s run,
directly accounting for the blowout). Chain: **D-0924 blocks D-0923 blocks
D-0939** — closing D-0924 unblocks three records. Also: H-DRAIN hypothesis
refuted by measurement (`P-DRAIN-PEAK` shows 0 pinned buffers on both nodes;
`drain_deferred` counts skipped submits, not retained buffers — don't read it
as a pin count).

## D-0924 — leak is real, H1 refuted, no rig time spent

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`:
H1 claimed the six leaked `mxfs_buf` objects were misattributed because test1
carried a stale BAD_PAGE taint from an unrelated scrolled-out event. Refuted
by three facts already on disk: (1) exhaustive sweep of all serial logs +
evidence dirs found zero `bad page state`/`BUG:`/`Oops` matching that claim;
(2) the taint is self-inflicted — SLUB's `slab_bug()` itself calls
`add_taint(TAINT_BAD_PAGE)`, and the record's own `found` field names an
earlier "Objects remaining" occurrence in the same boot that set the bit; (3)
MXFS's own tripwire (`WARN_ON_ONCE` at `xfs_mxfs_dlm.c`,
`mxfs_ag_meta_track`) fired 2532s earlier in that same boot, on a
bnobt/cntbt split inside a free-extent — the module detected the unreleased
agmeta hold live, in the same boot that later leaked six xfs_bufs at unload.

Method note for future closure attempts: **the 8-clean-laps evidence is
confounded** — those builds had neither the registry nor any probe added, so
"clean since instrumentation" conflates "fixed" with "timing window moved by
the instrumentation's own overhead" (16 bytes/struct + list add/del per
alloc/free). The discriminating measurement is whether the **tripwire still
fires**, scored via `/proc/sys/kernel/tainted` before/after (bit 5 BAD_PAGE=32,
bit 9 WARN=512; clean baseline on both nodes = 12288 OOT|UNSIGNED) — not via
unload object counts, and NOT via the `WARN_ON_ONCE` log line, since it fires
at most once per boot and a second same-boot occurrence reads as absence.
**This generalizes to any `WARN_ON_ONCE`-based tripwire in this tree.**

`docs/history/docs/history/docs/history/compiled-tcp-2node-sess563-564.md`
closes the session: D-0940, D-0923 (every AG release waiting the full 2s
Phase-3 bound after a btree block free — non-vacuous, `p3_max_us=0` vs pre-fix
2003040µs), and D-0927 (a page PREPARED to a previous-era target stranding
every mount — test2's join journal names 370 lines of a departed incarnation,
`pages_prepared=cand`, `P-TAUTH-PAGE-PARKED=0`) all close FIXED AND VERIFIED,
taking the ledger 88→85. New harness `tests/sole_survivor_restart.sh` (both
nodes destroyed mid-flight, one never restarted) PASSes: the survivor mounts
unassisted, recovers 60/60 of its own files AND 60/60 of the absent peer's via
foreign replay, zero parks/lock-failures. Incidental design finding: the
bootstrap orphan-sweep (`mxfs_dlm_takeover_orphans`) is dead code on two
nodes — a sole survivor is the strongest two-node candidate for it and still
proved exclusion via the fencing gate instead, because the sweep requires the
total-outage adoption path. Flagged as a design decision to make (an
unreachable recovery path is not a safety net), not a defect. D-0924 stays
open despite three clean legs — no CHANGELOG entry between 0.75.64 and 0.75.92
touches the agmeta hold, so the leak's disappearance has no proven cause; next
step is an audit of every path that frees an `xfs_buf_log_item` without
`xfs_buf_ioend`, not another lap. D-0939 also stays open on the residual
reporting-defect and 91-vs-0 unexplained remote-acquire-timeout asymmetry.

## Operational trap folded from the same window

[[trap-set-u-unbound-var-inside-a-conditional-arm-turns-into-two-false-fencing-FAILs]]:
`tests/tcp_death_replay.sh` documented a default for `MXFS_DEV` it never
actually set; because every use sits inside a conditional arm, `set -u` didn't
fail at the top — it died mid-arm at the one line reading PR state, and the
resulting empty comparison read as "reservation gone after restore," a
critical-looking fencing regression the run never observed. Generalizable
lesson: `ck "<claim>" "$(measurement)" "expected"` can't distinguish "broken"
from "couldn't be measured" — assert on emptiness first and report it as a
harness fault by name. Fixed in 0.75.89 with an explicit default plus a
refusal to compare an empty PR-state reading. Same failed-measurement class as
the `cluster_restart_nomkfs.sh` truncated-capture issue noted under D-0940
above — check any `set -u` harness whose env vars are read only inside
optional arms.

## State at end of sess564

Ledger 85 open / 58 critical. Build 0.75.93. Rig left mounted and healthy.
Open from this window: D-0924 (leak confirmed real, root cause still
unattributed — needs a static audit), D-0932 (fencing-takeover fallback path
unverified), D-0933 part 2 (same unreached path as D-0932), D-0939 (reporting
defect + unexplained timeout asymmetry).
