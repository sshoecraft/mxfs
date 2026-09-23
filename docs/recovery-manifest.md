# Recovery manifest — the fence-time snapshot of a victim's write authority

Status: DESIGN (sess404), build in progress.  Ledger: D-FOREIGN-REPLAY-UNGATED-IMAGES
(owed item "fence-time manifest SNAPSHOT for the APPLY class"; stop-ship gate for
enforcement default-on).  Rulings: `docs/rulings/token-gate-held-predicate-fence-snapshot.md`,
`docs/rulings/fence-time-manifest-snapshot-s2-design.md`,
`docs/rulings/enforcement-default-on-policy-a-gated.md`.

## Why

The foreign-replay authority gate (docs/dlm-protocol.md) decides per victim
transaction APPLY / REDUNDANT_CLEAN / refuse from the token each buffer image
carries {class, resource, lineage, grant epoch}.  The "held at death" predicate
today reads the resource's CAW slot LIVE at verdict time
(`mxfs_dlm_caw_victim_manifest_read`: victim bit in holders_ex|pw, ex_grant_epoch,
resource_lineage).  That image is immutable between fence and purge only by
audit (the sole non-owner EX/PW clears are the post-verdict purge and the
post-recovery closure strip; while the bit is set no peer can take EX, so the
epoch cannot advance and the slot cannot rebind).  A live read is mutable
current state used as historical evidence; the rulings require a durable
fence-time snapshot that the verdict consumes, with the live read demoted to a
current-safety check, plus a writer-side guard that turns the audit into an
enforced invariant.

## Design (S2 + guard)

### On-disk region
New envelope region after the disklock region: `MXFS_RMAN_SLOTS` = 64 slots
(one per disklock heartbeat slot) × `MXFS_RMAN_SLOT_BYTES` = 2 MiB + 64 KiB.
Capacity proof: the protocol maximum held set is every CAW slot (65536) ×
32-byte entry = 2 MiB, plus a 4 KiB header — `max_held` is only a tracking cap
("granted but NOT tracked" past it), not an enforced grant cap, so the region
must hold the maximum.  Envelope: `MXFS_FORMAT_F_RMAN` flag + `rman_offset` /
`rman_size` in `struct mxfs_ondisk_super`; layout becomes
`[super][journal][disklock][rman][XFS data]`; `MXFS_PROTO_GEN` 6 → 7 (old code
must not join: it would replay without a manifest and would not protect the
region).  mkfs_mxfs formats it (zeroed headers); chk_mxfs knows the offsets.

### Manifest format (per victim slot)
Header (4 KiB, own magic/version/crc32c): victim slot, victim incarnation
(epoch), recovery_gen, fence_term, snapshot seq, entry count, exact byte
length, scan stamp, crc32c over the entry area, seal marker written LAST.
Entry (32 B): `u8 type` (AG/INODE/...), `u8 mode` (EX|PW bits), `u16 flags`,
`u32 slot_idx` (diagnostic), `u64 id` (ag number / inode number),
`u64 resource_lineage`, `u64 grant_epoch` for that mode.  PR-only and open
holders are NOT recorded as authority (they never satisfy APPLY).  Canonical
order: by slot_idx.  Sealed = header crc valid AND seal marker set.

### Stage machine (disklock recovery descriptor)
`FENCING` → (PREEMPT AND ABORT proven) → **`SNAPSHOTTING`** (certificate bytes
written, stage < FENCED so every existing gate still refuses; protection
starts here) → prover scans the whole CAW table (bulk reads), writes the
manifest, flushes, seals → `FENCED` with the manifest pointer {seq, count,
crc} in the recovery body (bytes after the outcome record) → claim → replay →
`IMAGES_REPLAYED` → ... → purge → CONSUMABLE.  Manifest retained until the
sector is zeroed.  Prover death between SNAPSHOTTING and FENCED: the
fencing-attempt takeover (fence_term) redoes the scan (idempotent; seq bumps).
Scan or write failure: fail closed — the attempt stays at SNAPSHOTTING and is
retried; never fall back to live authority.

### Replayer
At `mxfs_fr_enforce_preflight` the elected owner loads the victim's sealed
manifest (validates header identity against the descriptor pointer), builds an
in-memory index by {type, id}; `mxfs_shadow_eval_token` answers "held
{lineage, epoch} at fence time" from the manifest only.  The live slot is read
once per resource as a CURRENT-SAFETY check: the victim bit must still be
present and lineage/epoch unchanged — a mismatch is a broken recovery
invariant → abort the whole attempt (no purge, evidence preserved,
`P-RMAN-POSTSEAL-MUTATION`), never a per-transaction skip.  Missing / unsealed /
corrupt manifest or pointer mismatch → abort the attempt (retryable, slice
stays dirty).

### Writer guard (S4)
`caw_slot()` is the single CAS chokepoint.  A per-ctx `protected_mask`
(maintained from the monitor: set when a victim's descriptor is observed at
stage ≥ SNAPSHOTTING, cleared when the sector is CONSUMABLE) makes any CAS that
clears a protected node's EX/PW bit, changes ex_grant_epoch / lineage while a
protected bit is set, rebinds the slot, or grants a conflicting mode REFUSE
(-EPERM, `P-RMAN-GUARD-REFUSED`) unless the caller is the recovery owner's
purge for the current term.  Defense in depth: the audit said these paths do
not exist; the guard makes that an invariant.

**Local proof (sess407, 0.26.3, D-RMAN-WRITER-GUARD-MONITOR-LAG-407).**  The
monitor publishes at most once per 2 s pass, so a node that has DIRECT proof
of the victim's stage — the prover whose FENCING intent just became durable,
the replayer that just claimed the lease against a CERTIFIED descriptor — must
not wait for its own poll: matrix mutate1 on 0.26.2 caught the elected
replayer clearing a victim EX bit (`P-RMAN-TEST-MUTATE mode=1 ... rc=0`) 1.7 s
before its `P-RMAN-PROTECT` landed.  `mxfs_disklock_protected_mask_add(ctx,
slot)` sets the bit at once (O(1), no I/O, heartbeat-thread safe) and bumps
`ctx->protected_gen`; a monitor pass whose start-generation differs at publish
time SKIPS (its sectors may predate the proof) and the next pass recomputes
from the platter.  Called from `v5_pr_fence_prove_locked` (intent rc 0 and
SNAPSHOT_PENDING resume) and `mxfs_v5_dlm_recovery_acquire` (claim success,
before `P238-RECOV-LEASE` and the test hook).  Design-consult ruling (sess407, GPT):
gen validation + mask install + callback are ONE critical section under the
new disklock `prot_lock` for all three publishers (a bare counter still allowed
check-then-publish / OR-before-gen races).

**Structural rules (sess407 ruling Q3/Q4, 0.26.4).**  Independent of
`protected_mask`, `caw_slot_ex` refuses any non-PURGE CAS that clears ANOTHER
node's EX/PW bit (the only legitimate foreign clears are the recovery owner's
purge and the closure strip, flagged with the exact mask — audit of all 29 CAS
sites, sess407) — so the survivor monitor-lag window needs no heartbeat read.
`caw_guard_refuses` also refuses ADDING a protected node's EX/PW bit (a direct
handoff to a fenced, unpurged nominee would mint a post-seal grant absent from
the manifest).  `caw_repair_slot` (the one platter write outside `caw_slot_ex`)
refuses while the corrupt image holds a protected EX/PW bit and now preserves
`ex_grant_epoch` + `resource_lineage` (it had reset both to 0 since before
sess48/sess175).

**FSWIDE terminal halts replay (sess407 ruling Q5, D-FSWIDE-TERMINAL-REPLAY-
CONTINUES-407, 0.26.4).**  mutate2 on 0.26.2: slot 12 MUTATED-TERMINAL, then
the same replayer completed slot 17 five seconds later.  Once
`m_mxfs_quar_fswide` is set (own publish imports at once, peers via P240) no
new lease is claimed and no replay starts (`P-RMAN-FSWIDE-HALT`, reap loop
after terminal classification, no re-arm), `mxfs_xlog_recover_foreign_slice`
refuses at entry, and the per-transaction verdict aborts an in-flight slice at
the next transaction boundary.  Terminal arms assert `frc = 0`.

## Build order
1. DONE 0.25.0 (sess404): envelope + mkfs + chk + kernel discovery + PROTO_GEN 7;
   rig sanity `tests/evidence/sess404_v0250/` (fresh mkfs, 3 rows PASS, fleet 32/32).
2. DONE 0.26.0 (sess405): `MXFS_RECOV_DESC_VERSION` 3, stage ladder FENCING=1,
   SNAPSHOTTING=2, FENCED=3, …, GRANTS_RELEASED=6; `struct mxfs_recov_manifest_ptr`
   (56 B at body offset 216, own magic "RMVP"/crc bound to the victim identity);
   `mxfs_recov_cert_proves_exclusion` callers (claim, replay_authorized) additionally
   demand a valid pointer.  Takeover: `fence_takeover` accepts SNAPSHOTTING (lease
   moves, certificate bytes immutable); `fence_retryable` re-drives our own
   SNAPSHOTTING lease; `fence_intent` returns `MXFS_FENCE_INTENT_SNAPSHOT_PENDING`
   for our own SNAPSHOTTING attempt.  Monitor import → step 5.
3. DONE 0.26.0 (sess405): prover = `fence_certify` (→ SNAPSHOTTING, lease kept)
   → `v5_rman_snapshot` = `mxfs_dlm_caw_manifest_collect` (bulk 128-slot prio
   reads, EX|PW victim bit, fail closed on any unread slot) →
   `mxfs_disklock_recovery_manifest_write` (zero hdr+flush, entries+flush, sealed
   hdr+flush; on-disk `struct mxfs_rman_hdr` 4 KiB at slot+0, entries at
   slot+64 KiB) → `mxfs_disklock_recovery_fence_seal` (SNAPSHOTTING→FENCED +
   UNOWNED + pointer, one CAS).  Failure: `MXFS_RBLK_SNAPSHOT_PENDING`, fence-retry
   worker re-drives; owner death → SNAPSHOTTING takeover from the acquire path.
   Knob `mxfs.rman_inject` (TEST ONLY): 1 fail pre-write, 2 fail pre-seal-CAS,
   3 seal a torn entries crc.  TCP transport: `MXFS_RECOV_MPTR_F_NO_CAW_TABLE`
   manifest (lookups answer -ENODEV as before).
4. DONE 0.26.0 (sess405): replayer — `mxfs_shadow_eval_get` loads the manifest via
   `mxfs_v5_dlm_victim_manifest_load` (validates header vs pointer: seq, counts,
   crcs, term, prover, victim identity, recovery_gen, fs_gen), builds an
   open-addressed {type,id} index; `mxfs_shadow_manifest_lookup` answers from it
   (absent → -ENOENT not_held; NO_CAW → -ENODEV) and reads the live slot ONCE per
   hit as the current-safety check — mismatch → `P-RMAN-POSTSEAL-MUTATION`, read
   error → `P-RMAN-LIVECHECK-ERR`, both set `rman_abort`; under enforcement
   `xlog_recover_items_pass2` returns -EIO (`P-RMAN-ABORT`, verdict reason NONE →
   retryable, nothing purged) and `mxfs_fr_enforce_preflight` aborts on a failed
   load (`P-RMAN-LOAD-ABORT`).  Summary line `P-RMAN-EVAL` per untrusted log.
5. DONE 0.26.0/0.26.1 (sess405): writer guard in `caw_slot_ex` + `protected_mask`
   (disklock monitor computes it from every validated descriptor at stage ≥
   FENCING — protection starts at the INTENT, before the P&A — and publishes via
   `protect_cb` → `mxfs_dlm_caw_set_protected_mask`; `mxfs_disklock_set_protect_cb`
   does a synchronous 64-sector refresh so a mount is protected before its first
   CAW write).  Allowed-delta matrix: with any protected EX/PW bit in the compare
   image, non-purge CAS may change nothing in holders_ex/pw, ex_grant_epoch,
   resource_lineage, binding or validity; a PURGE CAS (`MXFS_CAW_CAS_F_PURGE` +
   the exact victim mask — `caw_purge_dead_nodes_body`, `caw_closure_strip_one`)
   may only clear that mask's bits.  Refusal = -EPERM `P-RMAN-GUARD-REFUSED`
   (ctx->guard_refused).
6. Tests (sess406, 0.26.2): `tests/rman_matrix.sh <evidence_dir> [arm...]`
   drives `tests/tmpfile_churn_kill.sh` once per arm — base_single,
   base_shared (enforce on), inject1/2 (`rman_inject` 1/2, knob cleared by the
   after-kill hook at +80 s → `snapshot_pending` then seal), inject3 (torn crc
   → TERMINAL MANIFEST_INVALID, `TCK_RMAN_EXPECT_TERMINAL=1`), mutate1
   (`rman_test_mutate=1` on test1 → `P-RMAN-GUARD-REFUSED`,
   `TCK_RMAN_EXPECT_GUARD=1`), mutate2 (`=2`, bypass → TERMINAL
   AUTHORITY_MUTATED), busy (`rman_inject=4`: prover held 30 s on the HB thread
   + forced retry sweep → 1 ≤ `P304-FENCE-PROVE-BUSY` ≤ 20, D-406), takeover
   (`rman_inject=1` parks the prover; `tests/rman_prover_kill.sh` destroys it
   at +75 s and clears the knob → `P-RMAN-SNAPSHOT-TAKEOVER` ≥ 1, sealed ≥ 3,
   the prover becomes an extra victim via `$TCK_OUT/extra_victims.txt`).
   Harness knobs: `TCK_TEST1_PARAMS`, `TCK_EXTRA_RECOV`, `TCK_RMAN_EXPECT_*`;
   the `rman:` sweep line now carries guard_refused/terminal/test_mutate/
   prepurge_verify/prove_busy; a prep that leaves < NODES mounted is a FAIL
   (kill6d counted 5 unmounted nodes churning their local root as survivors).
   Terminal arms assert terminal ≥ 1, P240-QUAR-IMPORT ≥ 1, frc = 0 and report
   (not count) survivor churn / chk.  Still owed: max-size manifest timing on
   the HB thread; board; then the enforcement default-on matrix.
   sess407 (first full matrix, 0.26.2, `tests/evidence/sess406_v0262/matrix.txt`):
   base_shared PASS, inject3 PASS; every arm run WITHOUT the enforcement knobs
   (base_single, busy, mutate1, inject1/2, takeover) refused replay —
   `POLICY-REFUSED rc=-117`, quarantine=60, ATOMIC-SKIP — which is the designed
   `foreign_replay_token_enforce=0` behaviour (ledger #1), not a manifest
   fault; all arms now carry ENF.  inject1/2 overran the 260 s wrap (recovery
   completes at +117 s after the +80 s knob clear) → wrap 310 s (measured
   122..143 s non-recovery + 150 s bound).  mutate1 exposed the monitor-lag
   guard hole (above).  mutate2: the bypassed mutation WAS caught
   (`P-RMAN-POSTSEAL-MUTATION` → `MUTATED-TERMINAL` slot 12) and the other
   victim's intact slice completed 5 s later — terminal arms now assert
   per-victim accounting (frc + terminal ≥ victims, frc < victims) instead of
   frc = 0.  takeover: the prover killed after finishing its churn counts among
   the completes (survivor check is now ≥).

## sess405 design-consult review (GPT, 19 findings) — dispositions
- 1 (guard lag / start): protection now starts at FENCING and a mount refreshes
  synchronously; the distributed ack barrier was NOT built — the first-order
  invariant is that no live path clears a foreign EX/PW bit (audit), the guard
  is defense in depth, and `P-RMAN-GUARD-REFUSED > 0` on any run is itself the
  defect signal (asserted = 0 by the kill harness).
- 2: claim keeps -EPERM at SNAPSHOTTING (reason text names it); the acquire
  path's -EPERM branch does the SNAPSHOTTING takeover; -EBUSY would misroute
  into the execution-lease takeover.
- 3/4: `fence_term` is NOT bumped by a SNAPSHOTTING takeover (it names the one
  proved fencing operation); the lease is owner_node/epoch (+stage_seq).  Pointer
  and header carry `writer_node/writer_epoch` (manifest writer) separately from
  the certificate's `fence_prover_*`; all validated for equality.
- 5/6: target-specific purge (mask) + strict matrix, see step 5.
- 7: waiters / PR / CW / CR / open / yield fields are not authority and cannot
  flip a grant while an EX/PW bit stands → not frozen.
- 8/9: `P-RMAN-POSTSEAL-MUTATION` is TERMINAL: `log->l_mxfs_rman_mutated` →
  `mxfs_xlog_recover_foreign_slice` publishes `MXFS_RECOV_REFUSAL_AUTHORITY_MUTATED`
  (FSWIDE), checked after xlog_recover returns (covers a last-txn detection);
  pre-purge `mxfs_v5_dlm_rman_verify_live` (item 17) publishes the same and
  purges nothing.  `P-RMAN-LIVECHECK-ERR` stays retryable.
- 10: a retried attempt re-runs XFS recovery from the slice head (LSN-gated
  buffer/inode replay, intent/done pairs) — the same restartability a crash
  mid-recovery relies on; the mutation case no longer retries.
- 11/12/13: live check compares mode + slot_idx too (`victim_manifest_read_ex`);
  manifest semantic validation (scan_slots, geometry, flags, reserved bytes,
  entry ranges, strict slot order, duplicate {type,id} → load fails); seq taken
  only from a sealed crc-valid header of the same victim identity; wrap → fail.
- 14: SNAPSHOTTING takeover precondition = `v5_node_is_dead` (session dead AND
  fenced from the LUN), unchanged.
- 15: pointer required at every stage ≥ FENCED (claim, replay_authorized,
  recovery_advance); every descriptor CAS carries the body through.
- 16: report-only mode applies no tokenized image (blanket refusal) — the live
  path there is telemetry only.
- 18: a quarantined victim sector is never reclaimed, so its rman slot (the
  evidence) is never overwritten.
- 19: test list folded into step 6.

## sess437 — owner liveness is the incarnation tuple (0.41.11)

Item 14 above ("takeover precondition = `v5_node_is_dead`") is superseded.
`node_id` is per mount context but the epoch is redrawn on every slot claim,
so `(same node_id, different epoch)` is a real state, and judging the owner by
node id alone stranded the chain-7 takeover arm for ever (`P238-RECOV-OWNED`
on R with `owner_node == R`).  Per the sess437 design-consult ruling (`docs/rulings/incarnation-owner-liveness-and-whole-cluster-restart.md`):

- `v5_incarnation_state(ctx, node, epoch)` → LIVE / REVOKED / UNKNOWN from the
  heartbeat table (`slot_node_id`, `node_track[].last_epoch`, `slot_live`).
  REVOKED = our own earlier epoch, a proved-dead node, or a LATER incarnation of
  that node heartbeating.  UNKNOWN (expired but unproved, not in the table)
  still waits: heartbeat silence never authorises a takeover.
- Execution-lease `-EBUSY`: takeover on REVOKED (ordinary abandon-window CAW,
  `owner_term + 1` — a same-node successor inherits nothing from its old
  epoch's auth), wait on LIVE/UNKNOWN.  Fencing-attempt / SNAPSHOTTING takeover
  uses the same test on `fence_prover_epoch` / `owner_epoch`.
- Epochs are compared for equality only; there is no "later" epoch.
- Ladder audit (ruling item 2): every stage advance is read + `recov_auth_holds`
  (tuple, gen, term) + CAS on the exact image; takeover is one CAW with
  `term + 1`; replay is already re-runnable after a dead-owner takeover.
