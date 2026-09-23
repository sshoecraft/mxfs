<!-- sess401-404: D-400 dir-publish pace fix, foreign-replay REDUNDANT_CLEAN gate proven unsound + relmark log-item fix, D-404 dead-waiter AG ticket fix,… -->
# Foreign-replay gate hardening + D-400 dir-publish pace (sess401-404, 0.23.13 -> 0.25.0)

Continuation of `docs/history/docs/history/compiled-foreign-replay-authority-tokens.md` and
`docs/history/docs/history/compiled-agifc-divergence-d399-sess398-400.md`. Two threads run in parallel across
sess401-404: (1) D-TMPFILE-CHURN-RULE0-PERF-400's tmpfile-churn latency, and (2)
D-FOREIGN-REPLAY-UNGATED-IMAGES's "victim bit present at replay" gate, which sess402
proved unsound and sess403-404 closed with a durable release-marker + fence-time
manifest design. A third, D-DEAD-WAITER-AG-TICKET-CREATE-ETIMEDOUT-404, was found and
fixed inside the same window.

## sess401 — D-400 root cause + fix 1 (0.23.14)

[[trap-long-rig-run-evidence-in-scratchpad-is-lost-to-a-host-reboot]]: rig-run
evidence (board lap logs, dmesg harvests) written to the session scratchpad dies with
a clyde reboot mid-run (happened at 18:05 CDT, ~15 min into a 6-lap d385 board — clean
reboot, not a crash, but the board and its agent both died). Rule: point `D385_OUT`,
`AGIFC_OUT`, `TMPC_OUT`, `FTR_OUT` at `tests/evidence/<sessNNN_topic>/` (NFS) at launch
time, never copy-after-the-fact from `/tmp`.

`docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`: the 6-lap d385
board on 0.23.13 lost its 4th row (`dirent_durability`) every lap because the outer
chunk timeout (280s) was derived from a "12s/test + 15s startup" model that was ~18s
short of measured. Real overhead: 33s/run.sh-invocation + ~9s/row. Re-derived to 295s
with the derivation written into the script header — not a widening, a re-derivation
per the derived-budget rule. Also: broker (`mxfs/coord`) retained-message hygiene needs `-W 5` per
probe round in a loop, not one `-W 60` absolute wait; and a 32-way parallel `dmesg |
grep -c` fleet sweep under `timeout 25` returns all rc=124 — write `dmesg` to a file
once, grep the file, instead of re-scanning the live buffer per pattern.

`docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`:
function_graph ftrace on tmpfile churn (open(O_TMPFILE)->write->linkat->unlink->close)
measured 5.0 ms/iter vs native 0.07 ms — ~11 synchronous storage round trips. Root
PROVEN for the unlink term: the per-op dir-publish gate at
xfs_create/xfs_remove/xfs_rename was `!dp->i_mxfs_self_created ||
dp->i_dlm_dir_gen > 0`; `i_dlm_dir_gen` is already 1 after the first acquire, so the
second clause (added sess48 for contended dirs) was true for every used directory —
the sess48 "node-private carve-out" never actually applied, even on a brand-new
private dir. GPT ruling: defer the per-op dir publish for a conservative "virgin
local dir" predicate (self-created, EX cached, no remote grant of ANY mode since, no
recovery transition, release drain armed) — EX-only `ho` is insufficient since PR
readers don't set it. Also flagged: drop the per-ifree AGI FUA re-read once AGI
mutation is lock-bracketed+drained; skip/coalesce fresh-inode `verify_rawmode` only
with a `fresh_exclusive_inode` predicate; chunk ino reservations per AG tenure. Fix 1
landed 0.23.14 (sv B51097BCF5B32EE21768BF4): `i_mxfs_self_created` IS the virgin
predicate (cleared on any peer BAST/reload/reclaim); new gate function
`mxfs_dir_op_needs_publish(dp)` with knob `dirop_virgin_skip` (default 1) + shadow
counter. A/B: skip=1 unlink 0.48ms avg / iter p50 3.2ms; skip=0 unlink 2.27ms / iter
p50 5.0ms. D-400 stays OPEN — terms (b)(c)(d) still 3.2ms vs 0.14ms ceiling.

## sess402 — D-399 closed; D-401 named; REDUNDANT_CLEAN gate proven unsound

`docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`: 0.23.15
(+ Fix-2 `ifr_agi_disk_check` knob), then 0.23.16 (+ `iunl_mismatch_inject` negative
arm, per-site verify counters, `P-VMAN-NOTHELD` slot-image print). D-399 -> FIXED AND
VERIFIED. D-401 = D-32NODE-SHARED-DIR-CREATE-PACE symptom (first-after-prep
crash_consistency: 3200 dirents through one shared-dir EX = 80-88s every time, re-run
16s). `tmpfile_churn_kill.sh` gained `TCK_PARAMS` (fleet module params + readback),
bounded wait-for-recovery, and `auto:single`/`auto:shared` victim selection by
disklock slot class.

kill1 (enforce OFF, inj20): both victim slices POLICY-REFUSED -117 via
P227-FR-ATOMIC-SKIP -> AG quarantine -> survivor EIO.
[[trap-grep-v-authorized-deletes-unauthorized-image-kernel-lines]]: the ATOMIC-SKIP
line ("...contains **un**authorized image(s)...") was being deleted from every pulled
log by `grep -v authorized` (meant to strip the ssh login banner) across 6 harness
scripts (22 call sites) — an hour was spent hunting a "silent" refusal path that
wasn't silent. Fix: anchor the banner filter (`grep -av '^Unauthorized\|^Warning:\|^If
you'`); when a counter says N refusals and no notices show, suspect the pipeline
before the kernel (`grep -c` on the node with no filter first).

kill2 (enforce ON, inj20, two-owner AGs): notheld=3/4 -> refused again -> AG
quarantine, even though the co-owner had ping-ponged the AG with the victim until 1s
before the kill. kill3 (enforce ON, inj0): harness unmounted before the 62s heartbeat
expiry, so no replay ran at all (fixed after).
`docs/rulings/token-gate-held-predicate-fence-snapshot.md`: ruling
that "victim bit present at replay" is NOT sound proof — a mutable current-state
predicate used as historical proof. A dead node's EX bit may legitimately clear only
via (a) a clean unlock completed on platter before death, or (b) explicit post-fence
cleanup after authority evidence is preserved — never via heartbeat-staleness stripping
alone. Required: a FENCE-TIME MANIFEST SNAPSHOT, durable, bound to victim
slot/incarnation/fence-event/generation/epoch/lineage, taken before any
strip/grant/repair, under a RECOVERY_PENDING freeze. A clean skip (no replay needed)
requires a durable CLEAN-RELEASE CERTIFICATE, not co-owner reacquisition (which can
result from recovery stripping the dead holder, not a clean drain). Hard ordering
specified: detect -> PR fence -> freeze/RECOVERY_PENDING -> snapshot -> classify vs
snapshot+clean-release records -> recovery-exclusive replay -> flush+durable
completion -> conditional purge -> advance epoch -> grant waiters. Two deterministic
two-owner subtests specified: (i) mid-tenure crash with handoff frozen, (ii)
post-clean-handoff crash.

kill4b/kill5b on 0.23.16
(`docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`): kill4b
(single-owner victims, enforce armed) PASSED — first successful token-enforced foreign
replay on the rig. kill5b (shared-AG victims) refused -117 and quarantined both AGs:
`P-VMAN-NOTHELD` showed holders=0x0 with `ex_epoch` one ahead of the tokens' epoch —
exactly one later grant existed and had been released; nobody held at replay. This is
the REDUNDANT_CLEAN case the ruling above anticipated: the victim's slice tail was an
OLD-TENURE record already cleanly released, not a lost write. Design direction floated
(a slot-resident `last_clean_release` record in `reserved[336]`) was later
DISQUALIFIED in sess403's ruling (see below).

`docs/rulings/direx-caw-verify-cookie-shadow.md`: D-400 term (c)
attributed to the un-throttled dir-EX CAW verify (xfs_mxfs_dlm.c ~30071, sess8-era):
every idle dir-EX ilock cache hit with no holders/pins does one 512B FUA slot read
(149 reads / 100 tmpfile iters measured). Ruling: no purely local skip predicate is
sound unless the protocol invariant holds that another node can never clear this
node's on-disk EX bit without a locally-observable event. Recommended: a
GENERATION-COOKIE predicate (grant_instance + release-generation + membership/recovery
incarnation + lineage + observed peer-request generation) — skip the read only while
every cookie component matches the value validated at grant; ship as a 100%-verify
shadow program first (`C_skip_would_find_not_EX` and subcounters) before trusting it to
skip. A pure throttle (bound latency, no correctness argument) was rejected outright.

## sess403 — clean-release marker (design B) lands as 0.24.0

`docs/rulings/release-marker-log-item-redundant-clean.md`: ruling
compares (A) a slot-resident `last_clean_release` record vs (B) an in-log
release-marker log item written by the releaser after drain, sync-forced before the
unlock CAS. **A disqualified**: tombstone recycle under inode churn turns routine
clean failover into quarantine, u32 epoch aliasing, no incarnation binding, single
strip record can't survive wrap/lineage. **B shipped**: marker must be durable BEFORE
the holder-bit clear (sequence: enter RELEASING -> force CIL -> drain -> bdev flush ->
sync-force marker -> CAS bit clear -> successor grant). Once durable, the release is
NON-ABORTABLE back to ACTIVE — a holder that needs the resource back after the marker
forces must reacquire via the normal grant path and mint a new epoch, never resume
writing under the old one. Fence-time manifest snapshot is RETAINED for the APPLY
class (marker only removes the need for it on REDUNDANT_CLEAN). Never reserve/force
log space from a non-sleepable DLM callback — acquire the marker log reservation
BEFORE entering the non-abortable phase, or defer the release with the bit still held.

`docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`: implementation —
new `XFS_LI_MXFS_RELMARK` (0x12c0) log item (`xfs/xfs_relmark_item.{c,h}`),
`mxfs_relmark_publish()` (tiny NO_WRITECOUNT sync-forced txn), pass-1 recovery table
(64K open-addressed, dedup), `mxfs_shadow_eval_token()` verdict extended to
`{REFUSE, APPLY, REDUNDANT}`, `P227-FR-REDUNDANT-SKIP` on pass-2, `MXFS_PROTO_GEN`
5->6. Publish hooked at both unlock_open arms of `bast_process`, the AG bast worker
before `mxfs_v5_dlm_ag_unlock`, and `mxfs_dlm_ag_release_work_fn`.

`docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`: verification on
0.24.0. kill5c (shared-AG victims, enforce armed): both slices reached 'complete',
`REDUNDANT_CLEAN=3 quarantine=0` — exactly fixes the kill5b refusal/quarantine shape.
kill4c (single-owner): PASS, 30/30 survivors clean. VERDICT on kill5c was FAIL only
because a co-owner (not a victim) hit 55x `[Errno 110] ETIMEDOUT` on `open(O_TMPFILE)`
during the death->replay window — a new, separate defect (attributed sess404, see
below). [[trap-never-rebuild-mxfs-ko-while-rig-run-in-flight]]: while kill5c/kill4c
were running, a one-line fix + `make modules` on the tree mid-run put the two kill
arms on different srcversions, because every `run.sh prep_cluster` insmods the tree's
`mxfs.ko` straight from NFS. Rule: once a rig run/agent is dispatched, the tree's
`mxfs.ko` and `tools/` are FROZEN until it reports; if a build can't wait, build into a
scratch worktree copy, and always cite the per-run srcversion the harness/agent
actually reports, not the tree's `modinfo`.

## sess404 — dead-waiter AG ticket fixed; enforcement-default-on + snapshot rulings; rman envelope started

`docs/rulings/ag-dead-waiter-ticket-bounded-courtesy.md`: the
sess403 co-owner -110 residual, root-caused as
`D-DEAD-WAITER-AG-TICKET-CREATE-ETIMEDOUT-404`. AG release builds a batch courtesy
ticket `yield_to = waiters` (dlm_caw.c ~10399) the same way INODE does, but AG never
got the sess31 fix A/B that lets a live acquirer bypass a ticket naming a now-dead
registered waiter — so every fresh AG acquire looped yield-backoff for ~1.2s x100
until the dead slot's ~74s purge, and NOQUEUE (checked only on the incompatible
branch) let the "non-blocking" allocator AG probe sleep and return -ETIMEDOUT, which
`xfs_dialloc_try_ag` treats as a hard error (only -EAGAIN skips) -> ETIMEDOUT surfaced
at `open(O_TMPFILE)`. Ruling: extend the INODE A/B fix to AG (holder bitmaps + CAS
generation are the exclusion authority, ticket is fairness metadata only); ordinary
NOQUEUE returns -EAGAIN immediately on a foreign live ticket BEFORE registering;
DEMAND|NOQUEUE takes the compatible claim directly instead of spinning to purge
(counted as `P-CAW-TICKET-DEMAND-OVERRIDE`); do not age-filter registered waiters at
release (can't distinguish dead from slow/partitioned).
`docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`: fix landed
0.24.2 (`dlm_caw.c caw_lock_body`) — NOQUEUE check moved ahead of registration, A/B
extended to INODE|AG, new counters. Verified via kill5e/5f/5g/4d (all PASS,
EXH/CAWEXHAG/AGLF=0 fleet-wide) and a 5-chunk board (26/27 PASS, the one FAIL being the
already-known D-401 pace symptom). `docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`:
D-404 CLOSED FIXED AND VERIFIED on 0.24.2 (sv 45CB1B5B316873A44731F38) after a clean
6-lap d385 (24/24, SPLIT=0). D-402 stays OPEN as a symptom of enforcement being
default-off (blanket-refuses).

`docs/rulings/enforcement-default-on-policy-a-gated.md`: ruling on
whether to flip `foreign_replay_token_enforce`/`release_proof_enforce` on by default.
**Option A shipped**: enforce=1, release_proof_enforce=1, target_cache_protected=0 by
default, and NEVER infer target_cache_protected from fua_disable; if
`fua_disable=1 && target_cache_protected=0` (the SCST rig's actual state), REFUSE the
clustered RW mount outright rather than silently falling back to blanket refusal at
runtime. Gated behind 7 stop-ship items before the flip: (1) fence-time manifest
SNAPSHOT for the APPLY class (a live read is still a correctness hazard for that
class), (2) ICLUS clean-release markers, (3) a fleet-wide board run WITH the
production defaults (not harness-only overrides) showing zero unexpected
POLICY-REFUSED/quarantine/EIO, (4) targeted crash coverage across N identical laps,
(5) the F2 config matrix, (6) fence-snapshot race/fault-injection tests, (7) explicit
mixed-version-mount prohibition for this transition.

`docs/rulings/fence-time-manifest-snapshot-s2-design.md`: the
APPLY-class snapshot design itself. **S2 shipped** (durable sealed manifest in a
per-victim region) over S1 (a digest over a live read — rejected: hashes are
error-detection, not a binding commitment, and unrelated generation bumps produce
false failures). Required ordering: detect HB expiry -> prove fence -> establish
recovery ownership/incarnation/term -> durable SNAPSHOT_IN_PROGRESS (protection starts
HERE, not at FENCED) -> block conflicting strip/grant/rebind/repair -> bulk-scan (fail
closed on error, never fall back to live authority) -> write manifest -> flush+seal ->
publish FENCED pointer -> classify/replay -> durable completion record -> purge ->
release protection. A post-seal mutation of a protected slot is a broken recovery
invariant: stop replay for the WHOLE slice/attempt (never just the one transaction),
preserve the manifest+image, fence the offender, require explicit re-decision. Also
required as defense-in-depth (S4): a centralized checked-CAS API that refuses any
clear/rebind/regrant/repair touching a victim's resources from SNAPSHOT_IN_PROGRESS
through replay/closure, keyed by slot+incarnation+fence-term+snapshot-seq. Flagged
stop-ship hazard: the existing 1MB legacy DLM journal slot the manifest was going to
reuse can't provably hold the protocol MAX of 65536 held-entries (24B each = 1.5MB) —
this became the reason sess404 started a proper on-disk `rman` region instead.

Step 1 of that build landed same session as 0.25.0 (sv CBC43BF0AE68ECED9B58DE9,
`MXFS_PROTO_GEN` 6->7): `MXFS_FORMAT_F_RMAN`, 64 slots x (2MiB+64KiB) = 132MiB region
in `mkfs_mxfs`'s layout `[super][journal][disklock][rman][XFS]`, validated by
`chk_mxfs` and gated by `--upgrade-protogate`. NOT yet verified on the rig — a
rig-runner sanity pass was in flight at the session's relay boundary. Remaining build
order (`docs/recovery-manifest.md`): SNAPSHOTTING descriptor stage between FENCING and
FENCED; the prover (bulk-scan + write + seal + CAS FENCED); the replayer
(`mxfs_shadow_eval_get` loads the sealed manifest, `mxfs_shadow_manifest_lookup`
answers from it, live read becomes only a current-safety check ->
`P-RMAN-POSTSEAL-MUTATION` on conflict); the `caw_slot()` writer guard; then kill laps
+ board; then the enforcement default-on matrix from the ruling above.
