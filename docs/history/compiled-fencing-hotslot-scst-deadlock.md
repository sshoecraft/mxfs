<!-- Compiled sess378-380: SCSI-PR fencing hardening, hot-slot CAW probe-walk decomposition, and the SCST atomicity wait-for-cycle root cause (both 526B/3… -->
# Fencing hardening, hot-slot CAW contention, and the SCST wait-for cycle (sess378-380)

One continuous investigation: harden SCSI-PR fencing (sess378) → fencing gaps
surface plus a suspected hot-slot CAW serialization during mass unmount
(sess379) → the hot-slot hypothesis is measured down to its actual components
and the real 60s-quantum root turns out to live in the SCST target, not MXFS
(sess380). Builds 0.14.12 → 0.15.10, srcversion progression tracked per fix.

## sess378 — fencing correctness closes two gaps

Two independent fixes, both closing entries opened by the sess378 discovery
that dm silently drops the PR ABORT service-action bit (root-cause memory not
in this batch).

**Preempt-and-abort fix** `docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md`
(0.14.12): `mxfs_pal_scsi_pr_preempt()` now issues PERSISTENT RESERVE OUT /
PREEMPT AND ABORT as a raw CDB via `scsi_execute_cmd`, bypassing dm's
`ops->pr_preempt` which silently downgrades 0x05 to plain 0x04 preempt. No
resolvable `scsi_device` → `-EOPNOTSUPP`/`MXFS_FENCE_KIND_UNSUPPORTED`,
deliberately NOT falling back to the non-aborting path (would mint a false
exclusion certificate). Verified on the wire: target log line flips from
"Preempt:" to "Preempt and abort:", 0x05 count 0→1, 0x04 count 1→0, exact
inversion. Replay is gated on `mxfs_fence_kind_proves_exclusion()` at
`dlm/v5_mount.c:1328-1355` — only `PREEMPT_ABORT_DONE`/`SINGLE_NODE_EXCLUSIVE`
authorize clearing the block, so replay cannot proceed on an unproven fence.
Lesson: P302 markers are failure-only, absence doesn't confirm the path ran —
use target-side capture for positive proof. Cross-node event ordering from
`dmesg -T`+btime arithmetic is unreliable by ~5s; use each node's own
`realns=` (CLOCK_REALTIME ns) field to compute per-node boot_ns and convert.

**Admission-time capability check**
`docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md` (0.15.0): new
`mxfs_pal_scsi_pr_report_capabilities()` (PR IN/REPORT CAPABILITIES, kernel +
user mode) plus `mxfs_scsipr_validate_admission()` in `dlm/scsipr.c`, called
after register+reserve but BEFORE the disklock claim — a device that cannot
fence never becomes a member. Default: refuse mount;
`mxfs.fence_capability_override=1` is an explicit operator opt-in, logged as
`P303-FENCECAP-OVERRIDE`. Verified: a loop device with no PR at all — a config
that used to mount read-write silently — now gets refused with
`P303-FENCECAP-NOCAPS`. **Explicitly scoped to admission time only**: a
capability that disappears mid-mount (reservation released by a third party,
target reconfigured) is undetected until a fence is actually attempted — this
gap is exactly what sess379 hits next.

## sess379 — the capability gap fires, plus a hot-slot hypothesis

**Fencing disarmed cluster-wide by one departure**
`docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md`,
corrected by `docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md`: a 28-of-32
mass unmount left 28 nodes permanently unable to remount (`P236-CLAIM-UNCERTIFIED`,
recovery guard stuck at `stage=1` with a live, healthy owner that could never
advance). First hypothesis — the departing node's unconditional PR-key
retirement at `put_super` (`pal/linux/xfs_super.c:~1727`) leaves no key for a
survivor to preempt — was corrected by reading the recovery owner's own
journal: the fence actually failed with `kind=NO_RESERVATION(8)`, fired
*before* the key-absence check. **The LUN carried no WE-RO reservation at
all**, disarming fencing for every node, not just the victim. Normal operation
does hold a reservation (confirmed post-repair: `sg_persist --read-reservation`
→ WE-RO, 64 keys) — it was lost across the mass departure. The sess378
admission check validates "WE-RO held" only at mount time with no periodic
health check afterward, so this loss is invisible until a fence is attempted.
Chain: a stalled unmount (see 526B below) gets declared DEAD → fence proves
nothing (`NO_RESERVATION`) → recovery guard wedges with a live owner → PR key
also unconditionally retired at `put_super` → mounting node has no key to
preempt either → admission barrier refuses ALL new mounts (routes around
nothing) → only `mkfs_mxfs` recovers. Two secondary defects noted:
`chk_mxfs -Q`'s summary contradicts its own detail (claims quarantine when the
detail says NOT quarantined) and its "usable RW slices 31 of 32" undercounts
the actual blast radius (zero nodes could mount). Tension for next session:
D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377 made key retirement mandatory and
fail-closed; this defect requires the retirement to be gated on slice
cleanliness, or a self-departure fence certificate, or an admission path for
"key absent + durable clean-quiesce stamp" — a RULE-5 question, unresolved at
end of sess379.

**Hot-slot CAW hypothesis for the mass-unmount stall**
`docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md`: `mass_umount_stall_probe.sh`
with 28-of-32 departing showed a non-departing node's `stat()` on the shared
mount root (CAW slot LBA) hitting 59,742ms vs 3ms on an unrelated file's slot
— same node, same window. Traced to a blocked `statx()` inside
`mxfs_dlm_ilock_begin`'s cached-grant ownership verify
(`mxfs_pal_scsi_read_fua_bdev`), requesting PR not EX — so
D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B's original "root inode EX handoff,
2s/hop" mechanism was wrong. Elimination chain: zero P73/P139/P34 fleet-wide
ruled out leaked ISTATE_ACQUIRING or slow caw_lock; staggered unmount (3s
apart) → 0.04-0.09s, no stall; read-only 32-node stat storm on the same root
→ zero FUA retries, harmless; participant scaling showed a bimodal
all-or-nothing split (8/8 fine, 24→10 stalled at 60.3s, 28→27/28 up to 180.9s).
This session's fix targeted amplification, not the root: PAL per-task I/O
budget (`mxfs_pal_io_budget_enter/exit`) replacing nested
`30s×1×20` retries with one deadline, plus a DLM verify governor (1000ms
deadline, exponential circuit breaker 1s→60s, 2-deep inflight cap, ±25%
jitter) wired at all three fast-path verifies, all three enforcing (demoting
cached grants) rather than pure-detecting. Landed 0.15.2/0.15.3: max wall
181.5s→60.65s, 32/caw board 27/27. Residual 60s explicitly named as SCSI
error-recovery latency, not the budget — the real fix has to remove the
convergence, not bound the wait.

Two RULE-5 rulings shaped the follow-on work:

`docs/rulings/detector-io-off-the-fast-path.md`:
framed the question as whether cached grants are independently authoritative
or the verify read is part of what makes them safe. Verdict: move the stale-EX
verify off the caller path (sound if grants are revoke/fence-authoritative);
do NOT defer the dir-EX phantom verify on the "throttle already allows TOCTOU"
argument alone — either prove cached EX independently authoritative or keep a
bounded fail-closed check at the mutation boundary. A deferred sample cannot
retrospectively validate an earlier serve (ABA: local tenure unchanged, on-disk
grant lost/reacquired in between) — capture full generation/epoch/incarnation
context at queue time, re-validate under the same lock on completion, mark
SUSPECT (never silently reacquire) on mismatch. Hot-slot amplification from
moving reads off-path is a separate defect requiring per-LUN concurrency caps,
jitter, exponential backoff. Retry discipline: one absolute monotonic deadline
per logical op, no nested independent retry policies; for a detector read, no
answer = no sample, never "grant valid"; for an authoritative DLM read, a
timeout must fail the acquire, never be treated as success; CAW retries need
epoch reconciliation since a timed-out CAW may have landed anyway. Flagged the
single observed P108-REACQUIRE event as needing investigation before weakening
any check — "low detector yield is not the same as low consequence."

`docs/rulings/hot-slot-caw-fix-shape.md`: the
attribution was accepted as "more than merely consistent" but with two gaps
later closed empirically — the `.mus_probe` stat control doesn't prove LBA
isolation (a stat may not even issue a SCSI command) and a 60s quantum doesn't
prove a command was lost (a timeout just clips a queueing-distribution tail).
Both gaps are exactly what sess380 resolved. Endorsed fix shape for the
one-sector-per-resource CAW bitmap's fundamental O(N²)-ish contention: a
writer GATE record + per-node reader records at independently-writable
locations, with explicit crash/ABA/purge-herding hazards (node-ID reuse
requires incarnation/epoch in holder state; "skip release-all on heartbeat
loss" alone is UNSAFE without a full drain-then-publish-inactive teardown
ordering). Explicitly warned that no backoff changes the serialization bound
of the current format — only prevents catastrophic overshoot.

Session summary: `docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md`
(0.15.3) — both new critical defects filed here (hot-slot-serializes-per-LBA,
dirty-slice-bricks-filesystem), landing measured 181.5s→60.6s, board 27/27.
Harnesses added: `mass_umount_stall_probe.sh`, `mass_umount_reps.sh`,
`hotslot_contention.sh`, `lba_probe.sh`.

## sess380 — both sess379 root causes overturned by direct measurement

**Pace cost decomposition** `docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md`:
new `shared_dir_slot_cost.sh` counted every SCSI command to one shared
directory's CAW slot during concurrent creates — reads outnumber CAWs 13-16:1
(23-34 reads vs 1.7-2.0 CAWs per create), and `P383-SLOTREAD` caller-tagging
showed 83.3% of those reads are `find_slot_skip`'s open-addressing probe walk,
only 11.5% the grant poll loop that four prior sessions had blamed. Four
standing hypotheses refuted by direct measurement: unlock-CAS-loses-to-peer-
registration (0.2% of miscompares, not 98.3% — an exact byte-image classifier
proved most miscompares are multi-generation, unrelated); wake-the-whole-
waiter-field (0.0% of releases — nearly always mints exactly one successor);
the 2ms fastpoll window as amplifier (disabling it made reads worse,
26.6→32.9/create); reads-as-backstop-for-swallowed-nudges (raising poll-max
200ms made both reads and wall time worse). Conclusion for the sess379 GATE +
reader-record redesign: it removes CAS collisions (~7% of traffic) but not the
probe-walk reads (83%) — re-score the fix against these numbers before
committing to an on-disk format change.

**The 60s quantum is a genuine deadlock in SCST, not MXFS**
`docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md`: `scst_check_scsi_atomicity()`
walked the WHOLE `dev_exec_cmd_list` with `continue` (not `break`) at self, so
a command whose first atomicity check gets DEFERRED (parked by an unrelated
device BLOCK before its own check ran) installs wait edges back onto commands
already blocked ON IT — a true mutual-wait cycle, broken only by the
initiator's ABORT_TASK timeout, which produced exactly the 60s quantum behind
both 526B and D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379. TRACE_BLOCK captured
the exact sequence: device BLOCK parks a READ before its atomicity check runs
→ 5 CAWs queue behind it as overlap waiters → device UNBLOCK reactivates the
READ, which NOW runs its first check (device's `dev_scsi_atomic_cmd_active`
nonzero from its own waiters) and blocks on its own waiters → 60s of nothing
→ ABORT_TASK. Block/unblock accounting was exact (no leak), wait distribution
strictly bimodal (p50 8ms, then a long tail to 60.4s) — ruling out ordinary
queueing. Fix: `continue`→`break` in `scst_check_scsi_atomicity()` so edges
only point at predecessors (list is append-at-tail with one insert site and
one removal site, audited stable), plus a `dev_exec_seq` stamp and
`WARN_ONCE` orientation detector for the DAG-acyclic invariant. RULE-5
reviewed before landing. One-variable A/B (MXFS byte-identical, scst .2 vs
.3): 28-of-32 unmount 120.48s→0.37s; worst hot-slot command 60,426ms→59ms;
ABORT_TASK 12→0. This resolved both sess379 GPT-ruling gaps directly: paired
hot-vs-cold-LBA `READ(16)+FUA` during the storm now reads 68ms vs 24ms worst
(not 40,272ms vs 39ms), and the observer-stat acceptance form scores 1.6x
(13ms vs 8ms), inside the defect's own 2x bar.

Consequently both critical defects filed in sess379 were **DISPROVED**, not
fixed by an MXFS change: D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B and
D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379
(`docs/history/docs/history/docs/history/compiled-fencing-hotslot-scst-deadlock.md`).
The same summary also closes out D-32NODE-SHARED-DIR-CREATE-PACE's
attribution: three measurement tools were independently lying (P138-WAIT
times only one sub-call of a multi-retry acquire; P139-LOCKTOTAL's floor was
hardcoded at 800ms, above the whole distribution, yielding zero samples until
lowered; `create_scale_curve.sh`'s "private" control arm wasn't actually
private — every node's `mkdir -p` ran inside the measured window, contending
on one shared parent). Fixed measurement gives a clean ladder: shared-dir
p50 wall 49.8x private at 32 nodes, with per-op p50 flat (~10ms) — all cost is
tail, i.e. queueing, not per-op expense. Mechanism confirmed symmetric: the
one CAW slot per directory means a waiter's REGISTER and the holder's CLEAR
CAW the same word (mean 1.96 miscompares/contended unlock, mean unlock wall
27.9ms, 36% of it a fixed backoff nap); 109 of 121 acquire retries lose the
waiter-register CAS specifically (zero lost the claim CAS). This is exactly
the positive-feedback loop the sess379 GATE+reader-record ruling predicted,
and its fix — writer GATE + incarnation-tagged per-node reader records — still
applies, but per the probe-walk finding above, must be re-scored against the
83%-is-reads reality before implementation. Two new critical defects filed
this session, unrelated to this cluster's throughline:
D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380 and
D-DLMSCALING-DSCAN-MISS-CR3-EUCLEAN-SHUTDOWN-380.

## Recurring operational lessons across all three sessions

- `prep_cluster` clears every node's dmesg — dump rings to a file before
  re-prepping or forensics are lost (nearly cost both sess380 defects).
- The node device is `/dev/mapper/mpatha`, not `/dev/sda` (sda is one path,
  claimed by multipath, EBUSY on mount); raw `sg_raw` passthrough still
  targets `/dev/sda`.
- clyde's kernel ring buffer holds only ~10s of SCST block tracing under a
  32-node storm — stream with `dmesg -w > file &` for the whole run.
- Storm variability is real: 526B swung from 1/28 to 27/28 nodes over budget
  between reps on an identical build — never judge a fix on one run.
- `mkfs_mxfs` prompts for confirmation; scripts need `-f`.
