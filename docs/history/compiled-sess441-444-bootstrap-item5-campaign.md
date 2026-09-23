<!-- sess441-444: bootstrap items 5b-5f (owner claim, K adoption, takeover) landed 0.46.0-0.52.0; ICREATE taint (D-0510) and purge pace (D-0511) found+fix… -->
# Whole-cluster-restart bootstrap: items 5b-5f (sess441-444, 0.46.0 → 0.52.0)

Continuation of the item-5 bootstrap-owner campaign (`docs/history/docs/history/compiled-sess440-item5-slotless-bootstrap-build.md`).
Single owner node reconstructs cluster state after a whole-cluster crash: claims a
victim slice K for its own log, replays 31 foreign slices under authority
enforcement, then opens admission. Four sub-items landed in sequence, each with a
design-consult ruling before build and a the design-consult rule code review after.

## Item 5b — bootstrap OWNER path (0.46.0)

Landed `docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`: scan → claim
→ hb thread → fresh scan → classify keys → manifest → seal → RECOVERING → phase 3
(recovery_acquire / bare P&A for slotless) → PHASE3-COMPLETE → refuses replay
(-ENOSYS, unbuilt) leaving the record RECOVERING. `mxfs_bootstrap_release_claim`
allows pre-seal unwind; own-boot exemption (all frozen records = this host+boot)
routes to the existing P305 path instead of bootstrap.

the design-consult rule review `docs/history/gpt-review-item5b-landing.md` forced, before
first rig measurement: retain the owner's PR key/ledger entry on any post-claim
failure (P302) — an unwind must never unregister the key that authorizes takeover;
owner-identity exemption must be exact, not key-only; heartbeat vs SEAL/RECOVERING
transitions serialize under one lock; `note_dead_node` only after a certified
lease; `KEY_ABSENT_UNPROVEN` never certifies; fail closed on duplicate/overflow
identities. FIX-BEFORE-5D items banked: post-seal registrant reconciliation before
replay, durable defer/resume for `-EBUSY`, explicit `UNKNOWN_REGISTRANT` kind
(never fabricate node ids), re-verify the frozen identity against the victim
sector before intent, same-key-same-boot = RESUME, READ FULL STATUS before global
completion.

Chain 26c measured this design clean: 32 certs, 133s mount attempt, record
RECOVERING, key retained. Two harness bugs found in the process (self-succession
counted as P&A+SS=N; sg_persist counts distinct keys not per-nexus entries) —
fixed in `tests/bootstrap_seal_fence.sh`
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`).

## Item 5d — adopt one victim slice K for own-log replay (0.47.0 → 0.48.1)

design-consult ruling `docs/rulings/item5d-adopt-one-slice.md` chose
shape B over a pre-m_log shadow (A) or C: adopt ONE certified victim slice K via
full own-log `xfs_log_mount` (intents included, unlike foreign replay), keep the
existing barrier for the other N-1 slices. K's record becomes an explicit
`ACTIVE|BOOTSTRAP_RECOVERY_PENDING` state, visible to every scanner/liveness/
claimer/admission path, normalized to ordinary ACTIVE only at final completion.
Durable escrow (~290 reserved bytes, later grown) captures version/state, term,
owner identity, manifest hash, slot K, selection reason, expected old-sector
digest, original victim tuple, the full recovery descriptor, the fence
certificate, and the new claim identity — written BEFORE the guard sector is
overwritten, so a crash mid-sequence is always resumable or safely abandonable.
Ordering: seal → phase 3 for ALL incl. K → select K deterministically → escrow
PREPARED (read back) → CAW K's sector → K_CLAIMED → full replay → K_REPLAY_OK/
REFUSED → barrier over N-1 → reconcile → zero the N-1 sectors → RECOVERY_COMPLETE
→ normalize K, open admission. K is never zeroed. 12 STOP-SHIPs enumerated
(wrong replay mode, ambiguous ACTIVE, incomplete escrow, certificate reuse across
fence attempts, foreign-intent waiver, admission before cleanup, non-eligible K
selection, etc.) all folded into the landing.

Landed as 0.47.0, PROTO_GEN 15, bootstrap record v3
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`): escrow
struct at record offset 224, `MXFS_HB_FEAT_BOOTSTRAP_PENDING`,
`mxfs_disklock_claim_victim_slot` (exact-image CAW), `v5_bootstrap_adopt`,
`XLOG_MXFS_BOOTSTRAP_ADOPTED` bit gating `xfs_log_mount`'s untrusted predicate
(intents NOT skipped for the adopted slice), `P-BOOT-ADOPTED-REFUSED` on a torn K.

the design-consult rule code review `docs/history/gpt-review-item5d-code-landing.md`
against the actual landed code refuted 4 provisional TOCTOU/truncation/ordering
concerns but found new STOP-SHIPs: **S1** `xfs_has_norecovery(mp)` skipped replay
but `finish()` still marked K_REPLAY_OK — must reject bootstrap adoption under
norecovery; **S2** `mxfs_bootstrap_resume` existed but had no caller — durable
states PREPARED/K_CLAIMED/K_REPLAY_OK all needed a resume path; **S3** an empty
READ-KEYS reconcile list passed — must require the owner's own key present; **S4**
the completion bit lands before sector zero/purge, so RESUME must re-verify
zero+purge per complete bit rather than trust the bitmap. Own finding (a): any
unwind after K-claim (even an unrelated barrier `-EBUSY`) marked K terminally
REFUSED — converts a transient fault into a term needing `chk_mxfs
--clear-bootstrap`; fix: only a typed replay refusal marks REFUSED, otherwise
leave RECOVERING+K_CLAIMED as resumable.

Chain 27 on 0.47.0 exposed a real bug, not a review gap
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`): 7
of 31 foreign slices refused because `v5_rman_snapshot` fell into a NO_CAW arm —
the bootstrap owner fences at phase 3 with no CAW engine live yet, so the
fence-time manifest collector needs a bare-device path
(`mxfs_dlm_caw_manifest_collect_dev`). Fixed in 0.48.0, alongside all S1-S4 +
finding-(a) from the review: typed-refusal-only REFUSED transition, norecovery
refusal at `xfs_log_mount`, own-key-present reconcile gate, barrier stops at the
first terminal slice, and item 5e (RESUME) wired end-to-end: peek recognizes
own host/boot → `boot_resume_pending`, key/node_id restored, same-boot dirty scan
exempts our K, manifest re-read, complete-bit prefill honors S4 (still-guarded
sector ⇒ ladder tail, not trusted-done), `v5_bootstrap_adopt_resume` re-prepares
escrow or reclaims the slot. A second real hazard found in the same pass: a
mount abort ran full teardown with `depart_clean=true`, CASing K back to EMPTY —
discarding the victim slice entirely; fixed by never treating
`bootstrap_owner && !boot_finished` as a clean departure.

Chain 28 on 0.48.0 found another real bug
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`): K's own-log
replay ran the untrusted gate with authority enforcement OFF, because
`mxfs_fr_enforcement_active` was foreign-replay-only — 0.47.0's chain-27 pass had
only worked because K happened to hold a counter-only clean-skip txn. Fixed in
0.48.1 (escrow v4, `mptr[64]`, record v4/PROTO_GEN 16): enforcement now mandatory
for the adopted log, preflighted before `xlog_recover` with no bypass knob.

## Item 5f — takeover when the owner dies in a different boot (0.50.0)

design-consult ruling `docs/rulings/item5f-bootstrap-takeover.md`:
neither blind carry-forward nor blind reset — new-term RESEAL with **validated
inheritance**. The T+1 manifest must carry current registrants, every
non-completed surviving victim, every T-completed victim WITH durable completion
evidence (a still-present guard at GRANTS_RELEASED, or else a durable completion
receipt — never inferred from an absent slot), the old owner as a predecessor
victim, and K's chained provenance (original-victim certificate + new certificate
fencing the failed owner + the sealed T manifest). K replay must be gated by BOTH
lineages. Dead-owner proof must be incarnation-scoped (node+epoch+key), not just
`note_dead_node(node)`. Contenders for takeover must be serialized by a durable
election before registration/P&A — two racing contenders otherwise fence each
other's undetected work.

the design-consult rule review of the resulting build plan
`docs/history/gpt-review-item5f-takeover-build-plan.md` found 8
STOP-SHIPs before landing: REGISTER must precede the election CAW (WE-AR
requires registration to even write the sector); PREPARED alone doesn't prove K
is unadopted (must re-read against the escrowed image); a stale contender must be
fenced and marked dead BEFORE any recovery mutation; the TAKEOVER sector must be
a durable staged journal (CONTENDER → OLD_FENCE_INTENT → ... → RECORD_COMMITTED)
so a crash mid-fence is distinguishable from "key vanished"; CLAIMED is not
importable (fence + fresh flow only, no sealed manifest to import); inherited
completion proofs must be term-independent tombstones (a bit inherited at T+1
carries only a T receipt otherwise — unprovable at T+2); packed receipts need
exact-image CAW on the whole 512B sector; growing the region 8→32KiB is safe only
gated by PROTO_GEN. Composite K replay ruled: newest lineage pair checked live,
older pairs by immutable manifest+certificate only, chain must be unbroken, and
**the new owner's grant engine must stay frozen until K's own-log replay +
shadow eval complete** — otherwise the owner mutates the very bits its own live
check is reading (this exact race caused chain 29's near-miss under 5d, see
below).

Landed as 0.50.0 Stage A (32KiB layout: record v5, two term-parity manifest
banks, TAKEOVER journal, 64×64B CAW-sector tombstones, lineage) + Stage B (the
16-step election/fence/reseal arm) in
`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`; Stage
C (composite-K evaluator patch for `xfs_log_recover.c`) failed to apply that
session (whitespace anchor mismatch) and was applied cleanly next session
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`).

Chain 31 measured takeover points 11 and 12 clean end-to-end
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`):
election, abandon-window, slotless fence of the old owner's key, 33-entry
inheritance, phase 3 under T+1 (~200s of descriptor re-proofs), K adopted and
replayed clean, no unproven inheritance, no postseal mutation — walls 229s/211s
against a 660s bound.

## ICREATE taint blocks every full restart (D-0510)

Chain 29's harvest, after 5d's enforcement fix, proved the K-replay bug fixed but
surfaced a new, separate defect on every remaining leg
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`): one
foreign slice always terminally refused because `XFS_LI_ICREATE` (new-inode-chunk
init) taints the untrusted-replay gate even when every buffer image in the same
txn is authorized — the strict allowlist in `xfs_log_recover.c` only exempts
INODE/RELMARK/EFI-EFD/intents. First design consult on this
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md` consult 1)
STOP-SHIPped the obvious fix ("AG-class APPLY sibling authorizes ICREATE") — AG
allocation authority proves the allocation, not every physical cluster write
ICREATE performs, and a peer could have modified an inode of the same chunk under
different authority in a different slice.

Second consult (same memory, consult 2) ruled: **verify-and-SKIP only** — an
FUA-write SYNCINIT invariant at carve time (write every cluster before the carve
commits, fail closed on write failure) plus, at replay time, per-dinode content
verification via FUA read; a cluster that verifies is skipped (no re-init,
because "init if it doesn't verify" is unsound — a torn newer dinode next to
valid peer state can't be told apart from garbage without full quiescence); a
cluster that fails to verify or errors on read REFUSES the slice (TORN), never
re-initializes. The writer's protocol (whether SYNCINIT was actually carved) must
be persisted on the record, not inferred from the replayer's mount mode.
REDUNDANT_CLEAN siblings suppress entirely; a refused sibling dominates.

Landed as 0.51.0 (`struct mxfs_icreate_trailer`, `MXIC`/`F_SYNCINIT`, mandatory
per-node SYNCINIT carve on every mxfs mount, ICREATE excluded from the taint's
first loop and judged after it by AG-sibling verdict)
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`).
Third consult (landing review, same memory) forced further fixes before it was
safe to measure: fail-open stamping (an unstamped record could still commit) →
added a hard geometry gate before `xfs_icreate_log`; SCSI passthrough LBA vs
partition-relative bio LBA mismatch → `mxfs_bdev_to_sdev` refuses partitions,
bio path is offset-correct; read errors must not become terminal TORN → split
into content-mismatch (-EFSCORRUPTED, terminal) vs read-failure (-EIO,
retryable); `nbufs==0` must never produce a record. Filed
`D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES-0510` (critical). Standing open
dependency both consults flagged: `D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY` —
later INODE-class cluster-buffer images have the identical clobber shape and
their own authority gate is still unproven
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`).

Chain 30 (0.50.0, pre-fix) confirmed the terminal slice was ICREATE-only on all
4 legs, as predicted. Chain 32 (0.51.0) delivered the **first successful
end-to-end whole-cluster restart**: RECOVERY_COMPLETE, payload 32/32, K replay
clean, 31 foreign replays + 31 tombstones, 0 ICREATE refusals across 3
APPLY/3 VERIFIED events
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`).
The only failure left was a the derived-budget rule timeout (545s > 540s bound) caused by a
distinct, newly discovered defect (below). Chain 33's negative arm (corrupt a
platter dinode before replay, expect REFUSE) initially missed the ICREATE
code path entirely — the prep-carved payload chunk had no ICREATE in the replay
window — so the harness payload was rewritten to force one (200 fsync'd files
per node, corrupt the last file's dinode)
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`).

## D-0511: purge-node full-table scan pace

Root of chain 32's 545s timeout, found by code reading against the evidence:
`mxfs_disklock_purge_node` reads all 65536 lock-table records one 512B sector at
a time per dead node (~8.3s per purge), sitting between
`P-BOOT-SLOT-COMPLETE` and `RECOVERY_COMPLETE`. Filed
`D-PURGE-NODE-FULL-TABLE-SECTOR-SCAN-0511` (high). Fixed in 0.51.1:
`PURGE_BATCH=128` records per read with per-sector fallback, plus
`P-PURGE-DONE`/`P-COMPLETE-TIMING` instrumentation
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`).
0.52.0 (unbuilt at session end) added a second independent latency fix: snapshot
prefetch for `mxfs_xlog_slice_snapshot` (`mxfs_xlog_snap_prefetch`/`_cancel`,
knob `fr_stab_prefetch`) so the next foreign slice's stability proof starts
before the barrier reaches it
(`docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`).

## design-consult ruling: pipelining the per-slice stability proof

Foreign-replay's `mxfs_xlog_slice_snapshot` stability proof (pass 0 + two
sleep-separated compare passes) cost 31×4.5s ≈ 136s of the 32-node bootstrap.
Ruling `docs/rulings/frstab-pipeline-across-slices.md`:
pipelining across slices is GO, under strict invariants — each slice proves
itself independently (a mismatch resets only that slice's stable count), the
45s stability deadline is per-slice and starts at that slice's own snapshot
attempt (queueing time doesn't eat into it), slice N+1 is never replayed before
its own proof completes, and once replay of a buffer begins no async compare
may touch it; snapshot reads of N+1 and replay writes of N must be asserted on
disjoint LBAs. Rejected: crediting time since the P&A certificate instead of a
fresh compare (orphaned backend AIO can land after pass 0 regardless of
certificate age — shrinks the detection window with no bound), and skipping to
one compare pass for "old" certificates (same reason, no hard backend
guarantee exists). Long-term fix flagged: a target DRAIN primitive with a
completion guarantee recorded in the certificate — `SYNCHRONIZE CACHE` alone is
insufficient without explicit ordering after orphaned AIO.

## State at sess444 end (09:38Z)

Tree = 0.52.0, unbuilt (disk = 0.51.0 sv 1AB2A2C6). Chains 34 (32/caw board
regression sweep), 35 (takeover points 13/14, exercising Stage C composite-K
eval), 36 (builds 0.52.0, remeasures purge pace + node_death_replay), 37
(rewritten ICREATE negative arm on 0.51.1) queued in sequence via setsid+Monitor,
per `docs/history/docs/history/docs/history/compiled-sess441-444-bootstrap-item5-campaign.md`.
Open at handoff: D-0510 needs chain 37 + the board before F&V; D-0511 needs
chain 36; D-437 (whole-cluster-restart, the umbrella defect for this entire
item-5 arc) needs its item-5f entries updated from chains 31/35;
`D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY` remains open and is now a named
dependency of the ICREATE fix's soundness.
