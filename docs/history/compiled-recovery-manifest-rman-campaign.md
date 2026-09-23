<!-- sess404-408: rman fence-time manifest design+build, D-405 subsector-bio HB-thread hang, D-498/D-406 containment+busy-spin, D-407 guard-lag, D-408 SCS… -->
# Recovery-manifest (rman) campaign — design through sess408 host panic

Fence-time manifest snapshot ("rman"), built to give foreign-replay verdicts a durable
authoritative source instead of a live CAW-slot read. Spans design ruling, on-disk build,
a sector-alignment hang that fenced 6 nodes, a fence-retry busy-spin defect, a fenced-victim
non-containment gap, a writer-guard propagation-lag hole, and an SCST host panic that
interrupted final matrix verification. `docs/recovery-manifest.md` is the living build-order
doc; this article is the narrative/lessons record.

## Design ruling (sess404) — S2 authoritative snapshot
`docs/rulings/fence-time-manifest-snapshot-s2-design.md`: GPT the design-consult rule
ruling settled the shape after sess402 required a fence-time snapshot (live slot reads are
not durable authority — generation bumps from unrelated PR/open updates cause false
failures). Decision: replay verdict derives ONLY from a durable, sealed fence-time manifest
(S2); live reads are current-safety checks only, never historical authority. S4 writer-side
guard required as defense-in-depth: a centralized checked CAS API refuses clearing EX/PW,
epoch/lineage change, rebind, conflicting grant, repair/admin rewrite, or closure strip on a
victim's resources from durable SNAPSHOT_IN_PROGRESS through replay/closure, purge exception
narrowly scoped to the current elected owner+term.

Mandatory ordering: detect HB expiry → prove fence → durably establish recovery
ownership/incarnation/term → durable SNAPSHOT_IN_PROGRESS (protection starts HERE, not at
FENCED) → block conflicting strip/grant/rebind/repair → bounded bulk scan (fail closed, never
fall back to live authority) → write manifest → flush+seal → publish FENCED descriptor
pointing at that exact sealed manifest → classify/replay → durably record completion → purge
→ release protection. Post-seal mutation of a protected slot is a broken recovery invariant:
STOP replay for the whole slice, never skip just the transaction. Flagged stop-ship hazards
at design time: legacy-slot capacity vs 65536-entry protocol max, no protection during
snapshot construction, feature/version gate for the repurposed journal region, manifest
durable before the descriptor pointer becomes authoritative, and current-safety validation
on top of the snapshot (snapshot proves history, not "no concurrent regrant after seal").
Every one of these resurfaced as a concrete defect below.

## Step 1 — envelope (sess404, 0.25.0)
`docs/history/docs/history/docs/history/compiled-foreign-replay-relmark-deadwaiter-sess401-404.md`: on-disk region
added — `MXFS_FORMAT_F_RMAN`, `rman_offset`/`rman_size` super fields, `MXFS_RMAN_SLOTS=64`,
slot = 2 MiB+64 KiB, region = 132 MiB, `MXFS_PROTO_GEN` 6→7. mkfs/chk_mxfs/xfs_super.c/
v5_mount.c wired through. Layout verified clean on rig: `MXFS envelope v1: XFS data at
offset 239116288 proto_gen=7`; fleet 32/32.

## Steps 2-4 — descriptor, prover, replayer (sess405, 0.26.0)
`docs/history/docs/history/docs/history/compiled-recovery-manifest-rman-campaign.md`: SNAPSHOTTING stage inserted between
FENCING and FENCED; `mxfs_recov_manifest_ptr` (56B, magic RMVP) added to the descriptor;
on-disk `mxfs_rman_hdr`(4KiB, magic MXRM, seal "SLEDSEAL")+`mxfs_rman_entry`(32B) format.
Prover path (`disklock.c`): `fence_certify`→SNAPSHOTTING, `manifest_write` (zero hdr+flush,
entries+flush, sealed hdr+flush, re-check lease), `fence_seal` (SNAPSHOTTING→FENCED+pointer
in one CAS), strict `manifest_read` validation, `fence_takeover` accepts SNAPSHOTTING (only
the lease moves, cert bytes immutable). Replayer (`xfs_log_recover.c`): shadow eval loads the
manifest at creation, answers lookups from it, one live-slot read per hit as the
current-safety check → `P-RMAN-POSTSEAL-MUTATION`/`P-RMAN-LIVECHECK-ERR` abort the recovery
attempt under enforcement. Module param `rman_inject` (1 pre-write fail, 2 pre-seal-CAS fail,
3 torn-entry crc) added for fault injection. Remaining at handoff: writer guard in
`caw_slot`, kill laps, the design-consult rule review of the implementation, enforcement default-on matrix.

## D-405 — sub-sector bio hang wedges the prover's own heartbeat thread
kill6a/kill6b on 0.26.0 hung 6 nodes. [[trap-pal-bdev-write-must-be-sector-aligned-subsector-bio-hangs-dm]]:
the first prover manifest write issued a 96-byte (3×32B entries) bio via
`mxfs_pal_bdev_write`. On dm-multipath (`/dev/mapper/mpatha`) a non-sector-multiple length
does not fail fast — it hangs forever in `submit_bio_wait`, D-state, unkillable. The SCSI
paths (READ(16) FUA / write_fua) reject sub-sector lengths with -EINVAL; the plain bio path
on dm does not. Because `v5_pr_fence_prove_locked` runs on the disklock heartbeat thread
(`expire_cb`), the hang stalled the prover's OWN heartbeat past its lease → peers fenced the
prover → -52 (EBADE) after 64s → cascading re-elections, 6 nodes wedged, test1 fenced, rig
needed virsh destroy/start of 7 VMs. Rule generalized: every PAL bio must be a whole multiple
of the logical block size; MXFS rounds to 4 KiB (`MXFS_RMAN_IO_ALIGN`). Second lesson:
anything slow or hang-prone in `v5_pr_fence_prove` runs on the HB thread — a stall there
past the lease turns the prover into the next victim, so that path must stay bounded.

`docs/history/docs/history/docs/history/compiled-recovery-manifest-rman-campaign.md`: fix + a 19-item GPT the design-consult rule
review of the whole implementation applied in 0.26.1: protection now starts at FENCING with
a sync refresh at mount (no distributed barrier — `P-RMAN-GUARD-REFUSED>0` is the defect
signal if it's missed); SNAPSHOTTING takeover no longer bumps fence_term; pointer widened to
64B with writer_node/epoch; strict guard matrix + target-specific purge mask;
POSTSEAL-MUTATION made a terminal FSWIDE refusal (`MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED=4`)
checked post-recovery and pre-purge; structural manifest failure made a separate terminal
(`MANIFEST_INVALID=5`); LIVECHECK-ERR kept retryable (transient, not authority-broken).
`docs/history/docs/history/docs/history/compiled-recovery-manifest-rman-campaign.md`: kill6d on 0.26.1
CLOSED D-405 FIXED AND VERIFIED (sealed=2, zero hung tasks, zero P-RMAN-WRITE-FAIL). Note:
kill6c's earlier failure was rig recovery overload (11 nodes still power-cycling from the
0.26.0 wedge), not a build defect — distinguishing infra noise from the real regression
mattered here.

## D-406 / D-498 — fence-retry busy-spin and fenced-victim non-containment
`docs/history/docs/history/docs/history/compiled-recovery-manifest-rman-campaign.md`: rig FLOOD halt at
session start (5532 SCST reservation-conflict lines, 4494 from one node). Root: test9 was
still running 0.26.0, hit D-405 (unfixed on that build), its HB thread blocked, peers fenced
it, but `P305-RESV-HEALTH SELF_GONE` logged only once with NO containment action for 6
minutes — the D-498 counter covered HB-CAS-timeout and CAW-unlock paths but not "HB thread
itself blocked" nor XFS buffer `-EBADE`, so xfsaild kept retrying bounced metadata writes
against a fenced target, flooding SCST until the log errored out and force-shut. Same
session: `P304-FENCE-RETRY/PROVE-BUSY` pairs firing ~4/s for 5 minutes on the same node — the
retry worker never re-armed after the busy wrapper returned rc=1 (new minor
D-FENCE-RETRY-PROVE-BUSY-SPIN-406). Both fixed in 0.26.2: SELF_GONE now increments the
conflict count and launches a PR-worker inspection tick; `-EBADE` on the buffer I/O path also
counts as a conflict; busy re-arm gated on `!armed || deadline expired`; inject-hold shortened
30→12s. A GPT 16-item review of these fixes was applied same session (with one GPT misread
corrected: the inspection thread IS joined before unregister). Trap noted here too: rewriting
`tests/tmpfile_churn_kill.sh` while a rig-runner matrix was actively executing it corrupts
the verdict of whatever arm was in flight at that moment — never edit a running harness script.

## D-407 — writer-guard monitor-lag hole
`docs/history/docs/history/docs/history/compiled-recovery-manifest-rman-campaign.md`: first full rman matrix read.
Most FAILs were a harness mis-specification, not a defect: every arm lacking
`target_cache_protected=1 foreign_replay_token_enforce=1` is DESIGNED to refuse replay
(ledger #1 default keeps the sess232 fail-closed behavior) — sess406's "report-only expect
PASS" arms were wrong; fixed by carrying ENF on all arms. Real defect: `mutate1` showed the
replayer clearing a protected bit (`P-RMAN-TEST-MUTATE ... rc=0`) at T, with the writer guard
publishing protection (`P-RMAN-PROTECT`) only 1.7s later — the guard depended on the node's
periodic monitor pass (≤2s) even when the node itself already had direct proof of the fence.
Ledgered D-RMAN-WRITER-GUARD-MONITOR-LAG-407 (major) — exactly the "no durable protection
during snapshot construction" hazard flagged at design time
(`docs/rulings/fence-time-manifest-snapshot-s2-design.md`) resurfacing
as a real timing gap. Fix landed 0.26.3: `mxfs_disklock_protected_mask_add` — O(1)
local-proof publish plus a `protected_gen` counter so a monitor pass in flight when local
proof lands doesn't overwrite it with stale state. `mutate2` also surfaced two harness-logic
bugs worth generalizing: a 2-victim terminal arm's "0 replay completes" assumption was wrong
(the intact victim replays fine while the corrupted one goes terminal — assertion changed to
`frc<victims && frc+terminal>=victims`), and a takeover arm's exact survivor-count assumption
broke when the prover node finished its own workload before being killed (changed to `-ge`).

## D-408 — SCST host panic during final mutate2 verification
`docs/history/docs/history/docs/history/compiled-recovery-manifest-rman-campaign.md`: 0.26.3 matrix
was otherwise clean (base_single/base_shared/inject1-3/mutate1 all PASS, mutate1 showing
`P-RMAN-GUARD-REFUSED=1` — proof the D-407 fix works) when clyde PANICKED mid-mutate2
(`kernel BUG at scst_targ.c:6794`, the guarded-host rule's panic-on-oops rebooted the host, crash-latch
halted the rig, pstore preserved the trace). Root cause is in SCST core, not MXFS: after
`scst_unregister_session()` a dying session's `reg->tgt_dev` stays linked until
`scst_free_session` clears it under `dev_pr_mutex`; if a survivor's PREEMPT AND ABORT lands
in that window, `scst_pr_abort_reg` → `scst_rx_mgmt_fn_lun` on the dying session does a
`percpu_ref_get` on a killed/possibly-zero ref, tripping a READY-state sBUG. This window opens
on every kill-fence whose P&A arrives ~60-65s after the kill (normal iSCSI nop-in 30s +
timeout 30s) — it took hundreds of laps to hit once. Fixed upstream in
`/src/scst` (+caw-abort-reclaim.5): `scst_pr_abort_reg` pins with `percpu_ref_tryget` (legal
post-kill while count>0) instead of assuming the session is alive, skipping with a log line
if the ref is already zero (no commands remain, so the invariant already holds);
`SCST_PR_ABORT_ALL` exempted from the READY sBUG (core-originated, own ref keeps things
alive); a latent forever-wait fixed by decrementing both pr_abort counters on that exit path.
A test knob (`scst.pr_abort_shutdown_delay_ms`) and harness
(`tests/scst_pr_abort_shutdown_race.sh`) were added to force both racing windows on demand
instead of waiting for natural timing; `clyde_preflight.sh` now floors the SCST version and
refuses a run while the delay knob is nonzero. Ledgered
D-HOST-SCST-PR-ABORT-SESSION-SHUTDOWN-PANIC-408 (critical, OPEN until the harness passes).
Process note: GPT's the design-consult rule review of the fix needed a third prompt phrasing — the first two
were flagged by its safety filter for words like "panic"/"crash"/"kill"/"iptables" even in
a legitimate kernel-race description.

## Cross-cutting lessons
- Every stop-ship hazard named at the S2 design ruling (sess404) later manifested as a
  concrete, ledgered defect: capacity/alignment (D-405), protection-window timing (D-407),
  and the general principle that live-authority fallback must never substitute for the
  durable snapshot. Design-time hazard lists in this campaign predicted real bugs, not
  hypotheticals — worth trusting on the next fence/recovery feature.
- The heartbeat thread is a hard latency budget, not just a liveness signal: any I/O or lock
  reachable from `expire_cb`/`v5_pr_fence_prove` inherits the HB lease as its timeout, and
  exceeding it makes the prover fence itself.
- Harness "verdict" logic needs the same scrutiny as the code under test: sess407 alone found
  three harness-side false failures (wrong ENF defaults, wrong replay-count equality, wrong
  survivor-count equality) that would have been misread as regressions.
- Do not edit a kill-harness script while a rig-runner matrix is actively driving it
  (sess406) — the in-flight arm's verdict becomes unreliable.
