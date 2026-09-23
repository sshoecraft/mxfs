# Unattended whole-cluster restart — design (sess437)

Status: items 1 (sess437, 0.42.0) and 2 (sess438, 0.43.0) LANDED IN TREE —
item 2 unverified on the rig at the time of writing; items 3-6 not started.
Owner defect:
`D-WHOLE-CLUSTER-CRASH-RESTART-REQUIRES-OPERATOR-437` (critical); also resolves
`D-PR-KEY-32BIT-NODE-ID-COLLISION-RISK-377` and gives
`D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE` its identity link.
Design-consult ruling: `docs/rulings/incarnation-owner-liveness-and-whole-cluster-restart.md`.

## The measured failure

`tests/no_survivor_crash_replay.sh` (chain 7, 0.41.8): all 32 VMs destroyed with
fsynced payload; test1 rebooted and remounted 27 s later:

    P304-PREOBSERVE 'mxfs' held=1 type=0x7 (WE-AR) ...
    P305-PR-NEXUS-ALREADY-REGISTERED plain REGISTER of key 0xcc438ac9 returned RESERVATION CONFLICT
    P305-PR-PREDECESSOR-KEY-PRESENT ... a same-nexus successor cannot fence its predecessor
    CAW mount: SCSI PR register failed (-17) — refusing to join unfenced
    MXFS DLM init failed — aborting mount

Every host is in the same state after a power loss: its previous incarnation's
PR key is still registered on its own I_T nexus (PTPL), nobody survives to
PREEMPT anyone, and the only remedy is a manual `single_node_exclusive=1` mount
on one chosen node — an exclusion-by-topology assertion that becomes false the
moment the other 31 boot.  The sess432 ruling that produced the refusal covered
only the lone-node dirty remount (same boot, predecessor may still issue I/O).

## Identity today

| thing | lifetime | where |
|---|---|---|
| `node_id` (32-bit) | per mount context (random) | HB record, CAW slots, PR key (`local_key = node_id`) |
| `epoch` (64-bit) | per heartbeat-slot CLAIM (redrawn on every claim) | HB record, descriptors |
| PR key | = node_id, registered per I_T nexus, PTPL | target |

Nothing ties a registration to a HOST or to a BOOT, so a successor cannot prove
its predecessor is a previous boot of the same machine.

## Ruling, mapped onto the code

### 1. Full 64-bit PR key per host boot, plus an identity block in the HB record

- `mxfs_pal_boot_identity(uuid_out[16])` (pal/linux/kern.c): read
  `/proc/sys/kernel/random/boot_id` once at module init (the kernel's
  `sysctl_bootid` is file-static; the proc file is the only stable per-boot
  source and is immutable for the boot).  `mxfs_pal_host_identity(uuid_out[16])`:
  `/etc/machine-id` (stable across boots of the same install); fall back to a
  hash of the initiator IQN from `/etc/iscsi/initiatorname.iscsi`; if neither
  exists refuse automatic self-succession (the same-boot rule stays).
- `pr_key` = 64-bit unpredictable value drawn ONCE per module load (per boot),
  never `node_id`.  Same key on every path of this host (multipath: all nexuses
  register the same key — verify with READ FULL STATUS after registering).
- HB record gains `struct mxfs_hb_identity { magic, ver, host_uuid[16],
  boot_uuid[16], pr_key, key_gen, crc }` in the reserved tail (`reserved[448]`
  has room; `_Static_assert` the mepoch/feat/prov tail stays put).  Fencers
  take the victim key from the victim's HB record (`fence_victim_key` in the
  descriptor already exists for exactly this), never from `node_id`.
- Incompat: `MXFS_FORMAT_F_PRKEY64` envelope flag + proto_gen bump (a 32-bit
  key node must be excluded from the cluster, not tolerated: it would fence the
  wrong key).  `mkfs_mxfs` sets it; `chk_mxfs` validates/prints the identity
  block; `tools/hb_epoch_inject.py`-style forge for tests.

### 2. When a boot may replace its own predecessor key

All of the following, else refuse exactly as today (`P305-...-PRESENT`):

1. a HB record (any slot, ACTIVE or WITHDRAWN) carries `host_uuid == ours` and
   `boot_uuid != ours`, and its `pr_key` is among the keys the target reports
   (READ KEYS) on our nexus;
2. no OTHER live record carries our `host_uuid` (duplicate machine-id / cloned
   VM → refuse);  no record carries our `boot_uuid` under a different
   `node_id` still heartbeating (two mounts of one boot on one LUN → refuse);
3. session reinstatement / duplicate-IQN evidence (a `P304-PREOBSERVE` holder
   that is not a known predecessor key) → refuse;
4. the target validated PR semantics at admission (`P303-FENCECAP`: PTPL, P&A,
   all-registrants reservation) — already required.

Then, in order: REGISTER AND IGNORE EXISTING KEY (replace) on the mounting
path; REGISTER on the other paths; PREEMPT AND ABORT the predecessor key if it
is still registered anywhere or holds the reservation; READ FULL STATUS must
show the predecessor gone and ours present on every path, else abort the mount
(`P305-PR-SELF-SUCCESSION-UNVERIFIED`).  Log `P305-PR-PREDECESSOR-BOOT-REPLACED
host=<uuid> old_boot=<uuid> old_key=<k> new_key=<k>`.

### 3. Bootstrap: the first node up after a total outage

Ordering is what makes this safe; it is serialized on disk.

1. PR identity first (§2) — no slot claim, no filesystem write before it.
2. Claim a heartbeat slot with a new `(node_id, epoch)`.  The claim MUST
   preserve the prior occupant's pending recovery: today a claim of a slot
   holding a dead ACTIVE record is a pass-2 fresh claim that adopts the slice
   (`XLOG_MXFS_ADOPTED_SLICE`) — the own-crash reclaim (pass 1) is the path
   that replays it and is unreachable by random `node_id`.  Replace the pass-1
   match with the identity block: `host_uuid == ours && boot_uuid != ours` on
   the record ⇒ this is OUR previous boot's slot; reclaim it with
   `slice_adopted = false` (full replay of the predecessor's slice under a
   transitional/victim identity, sess434 note on D-OWN-CRASH) after the
   predecessor key is cleared (§2).
3. Bootstrap coordinator lease: a dedicated disklock sector (`bootstrap` record:
   owner tuple, term, stamp) taken by CAW.  Only its holder runs §4 for foreign
   slots; others wait for it or take it over by the incarnation-tuple rule
   (`v5_incarnation_state`, 0.41.11) after the abandon window.
4. For every other slot with a dead record: observe through the death interval
   (no re-stamp), re-scan immediately before each fence, never fence a record
   whose `boot_uuid` is now heartbeating under a new key (a peer that booted
   meanwhile), PREEMPT AND ABORT the dead boot's `pr_key`, certify
   (`P236-FENCEKIND kind=PREEMPT_ABORT_DONE`), persist the certificate in the
   descriptor as today.
5. Replay: own predecessor slice first (§3.2), then each foreign slice under a
   certified descriptor with term-fenced ownership; release the freeze per
   slice as it completes; release the coordinator last.  A lone survivor
   replays all 32 slices; peers that joined meanwhile share the work through
   ordinary recovery ownership.

### 4. What stays refused

- Same-boot predecessor (`boot_uuid == ours`): the sess432 rule, unchanged.
- Duplicate host identity anywhere live, cloned/snapshot-resumed VMs, duplicate
  IQN: automatic succession refused with the identity named in the message.
- "Every key's slot is heartbeat-dead and the reservation holder is absent"
  is NOT accepted as exclusion: a paused host can resume.  Foreign boots are
  fenced by P&A + verification only.

## Item 2 as actually built (sess438) — corrections to §1

Two findings changed §1 before any code landed:

**The HB record has no spare bytes.**  `reserved[448]` is the LOCK record,
not the heartbeat record; the heartbeat is 40 B header + 384 B body union +
prov 32 @424 + mepoch 44 @456 + feat 12 @500 = 512.  The identity block is
therefore carved from the evict hint ring exactly as prov was (sess346): ring
23 → 19 entries, union 384 → 320, `struct mxfs_hb_identity` (64 B) at offset
360, recovery-body pad 104 → 40.  The tail offsets 424/456/500 — mirrored by
`tools/recov_forge.c`, `tools/chk_mxfs.c`, `tests/hb_epoch_inject.py` — do not
move.

**The registrant ledger cannot be deferred** (design-consult ruling, `docs/rulings/prkey64-item2-ledger-not-deferrable.md`).
A host that crashes after REGISTER and before its slot claim leaves a durable
PTPL registration with no durable owner; a collision-redrawn per-LUN key is
unrecoverable across a module reload; and "once per module load" is not "once
per host boot per LUN".  So item 2 carries a minimal ledger, a new envelope
region (`MXFS_FORMAT_F_PRKEY64`, sess438): 512-byte CAW-written entries
`{magic, state, key_gen, pr_key, host_uuid, boot_uuid, fs_uuid, node_id,
stamp, crc}`.  Key selection per LUN, in order: (1) scan the ledger for an
entry with our `{host_uuid, boot_uuid, fs_uuid}` and reuse ITS key (module
reload, retried mount) — a different key for the same boot on the same LUN is
never chosen; (2) otherwise draw a 64-bit key (≥ 2^32, never 0), READ KEYS
exactly once, redraw only if present, CAW a free/RETIRED entry to PREPARED;
(3) REGISTER; (4) READ FULL STATUS verifies our key on every path; (5) entry
→ REGISTERED.  Clean unregister → RETIRED.  A certified PREEMPT AND ABORT
marks the victim's entry FENCED.  Seeing our own key on a retry or a path
expansion never redraws it.

**Victim key at fence time.**  The monitor freezes `pr_key`/`key_gen` in the
per-slot incarnation snapshot the moment it reads a VALID identity block whose
`(node_id, epoch)` is the tracked incarnation — from an ACTIVE or a WITHDRAWN
record, never from a GUARD (that names the guard writer).  The death callback
carries the frozen key with `(node, slot, epoch)`; the fence intent stores it
as `fence_victim_key`.  No frozen key for the exact incarnation ⇒ the fence is
refused with its own terminal kind (`NO_VICTIM_KEY`); there is no fallback to
`node_id`.  A different key observed for an already-frozen `(node, epoch)` is
a protocol violation and fail-stops the observer.

**crc binding of the identity block**: `{magic, ver, key_gen, host_uuid,
boot_uuid, pr_key, host_src, slot, flags, fs_gen, node_id, epoch}` — slot and
flags so a block cannot be transplanted across slots or record roles.

## Build order (each increment rig-measurable)

1. PAL: `mxfs_pal_boot_identity` / `mxfs_pal_host_identity`; print both at
   module init.  Unit-visible in `dmesg`, no format change.
2. HB identity block + envelope flag + proto_gen bump + mkfs/chk support;
   64-bit per-boot `pr_key` published in the record; fencers read the victim
   key from the record.  Verify: fence_live_node PASS with a non-node_id key;
   READ KEYS shows the published key; chk prints the block.
3. Predecessor-boot self-replacement (§2) with every refusal case; verify with
   `tests/no_survivor_crash_replay.sh` (lone node must mount unattended and
   replay 31 foreign + its own slice) and a same-boot dirty remount still
   refused (`tests/lone_mount_create.sh remount_refused`).
4. Own-previous-boot reclaim keyed by the identity block (§3.2) — closes
   D-OWN-CRASH-RECLAIM-PATH-UNREACHABLE's reachability arm.
5. Bootstrap coordinator (§3.3-3.5); all-32-simultaneous-boot and
   boots-straddling-the-death-timeout arms.
6. The 19-case matrix from the ruling (see the ccmemory note) before unattended
   startup is the default.

## 5. Bootstrap record and self-succession — as ruled (sess439)

design-consult ruling: `docs/rulings/bootstrap-record-self-succession-intent.md`.
It replaces §2 and §3 above where they conflict.  Two proposals were put to
it and both were rejected:

- **Self-succession at REGISTER by identity match + REGISTER AND IGNORE
  EXISTING KEY + a ledger `FENCED`-by-successor record** — UNSAFE.  The
  removal of the predecessor key is not serialized against the fence
  intent a peer may already own on the predecessor's slot: peer P wins the
  slot's intent CAS, S REGISTER-IGNOREs the old key, P's PREEMPT AND ABORT
  observes `KEY_ABSENT_UNPROVEN`, S crashes before its ledger write — an
  unprovable residue, the sess93 hazard re-introduced through a new door.
- **No bootstrap record: the rebooter claims a free slot ACTIVE and lets
  the pre-mountfs barrier resolve every dead record** — UNSAFE for a total
  outage.  Per-slot descriptors decide who fences and replays ONE slice;
  they do not close the recovery set for the outage (which old slots and
  which old registrants, including keys with no slot), give a slotless
  actor a durable identity/term, or forbid ACTIVE publication and
  `xfs_mountfs` before a global completion record exists.  Cross-slice LSN
  ordering is NOT one of the missing invariants: the sealed-manifest token
  model is order-independent, so slices may be recovered concurrently and
  the bootstrap owner may delegate them.

### 5.1 The bootstrap record

One dedicated CAW-written 512-byte record in its own envelope region
(`MXFS_FORMAT_F_BOOTSTRAP`, `bootstrap_offset`; a re-mkfs, as for every
region).  Fields: `state ∈ {IDLE, CLAIMED, MANIFEST_SEALED, RECOVERING,
RECOVERY_COMPLETE}`, `bootstrap_term`, the owner's provisional identity
`{host_uuid, boot_uuid, node_id, epoch, pr_key, key_gen, nonce}`, owner
heartbeat stamp, `fs_uuid`, the sealed victim-slot bitmap (64 bits), the
registrant-ledger generation/hash at seal time, a manifest hash, the
per-slot completion bitmap, crc.  Claim, takeover, seal, stage and
completion transitions are CAS; the heartbeat is a CAW from the last image.
A silent owner is never replaced on silence alone: its `pr_key` is fenced
(or its self-succession certificate consumed) first, then a CAS to a
higher term, then its incomplete per-slot terms are taken over.

The provisional identity is a real `(node_id, epoch)` that may own fence
intents and recovery descriptors; `v5_incarnation_state` and the
descriptor-owner liveness checks consult the bootstrap record as an
additional heartbeat source.  It is NOT an ACTIVE member: no filesystem
write, no grant, no `xfs_mountfs`.

### 5.2 Self-succession, under an intent

REGISTER AND IGNORE EXISTING KEY is a key-removal command and is issued
only by the owner of a durable fence intent on the predecessor's slot
descriptor, `method = SELF_SUCCESSION`, naming the victim tuple, the old
key/key_gen/boot_uuid, the successor's provisional identity, the expected
transport-ID digest, the bootstrap term and a nonce.  A peer-owned intent
always wins: the successor waits (or takes over after abandonment under a
higher term), consumes the peer's `PREEMPT_ABORT_DONE`, and then registers
its new key normally from the absent state — it never writes
`SELF_SUCCESSION_DONE` over a peer's certificate.  If the successor's
intent wins, no peer issues a PREEMPT AND ABORT for that key.

`SELF_SUCCESSION_DONE` is a valid exclusion certificate iff: `boot_uuid`
differs; nexus reinstatement (the old task set aborted on session loss) is
established for every predecessor path; READ FULL STATUS shows the old key
absent on ALL transport IDs and the new key present on every successor
path; no unclassified registrant or reservation holder exists; result and
certificate are CAS'd under the intent.  The later slice-recovery owner
consumes it by intent id/term.  An absent key with neither a
`PREEMPT_ABORT_DONE` nor a self-succession certificate explaining it stays
`KEY_ABSENT_UNPROVEN` and aborts the bootstrap.

Ledger additions: `FENCE_INTENT` state, bootstrap term, `succeeds
{old_key, old_boot}`, slot intent id, method + certificate reference.  A
ledger-only intent exists for a manifest registrant that has no slot.

### 5.3 Order

1. **Identity.**  Read every HB slot, the ledger, the bootstrap record,
   READ KEYS and READ FULL STATUS on every path; refuse on any
   inconsistency (§5.4).  Fence/certify a prior bootstrap owner; CAS
   `CLAIMED(term, provisional owner)`; heartbeat; CAS `MANIFEST_SEALED`
   with the victim bitmap and ledger hash.  Nothing is ACTIVE.
2. **Successor registration** (each host blocked by its own predecessor
   key): ledger `PREPARED` with `succeeds()`; CAS the predecessor slot's
   descriptor to a `SELF_SUCCESSION` intent (if another intent exists: no
   REGISTER-IGNORE); confirm boot boundary + reinstatement; REGISTER-IGNORE
   on our paths; stable FULL STATUS on all paths; CAS `SELF_SUCCESSION_DONE`;
   CAS the predecessor's ledger entry `FENCED` referencing it; CAS ours
   `REGISTERED`.  Already certified `PREEMPT_ABORT_DONE` ⇒ register normally.
3. **Fence every manifest registrant**: one CAS intent each; consume
   self-succession certificates; the intent owner issues the P&A; result +
   certificate CAS'd; unknown absence aborts.
4. **Recover every slice** (concurrent allowed): GUARD, consume the
   certificate, CAS ownership + term, token-gated replay, purge the dead
   tuple's grants, CAS per-slot `RECOVERY_COMPLETE`.  No evidence-bearing
   slot is zeroed before step 5.
5. **Global completion**: verify every sealed slot and registrant complete;
   CAS bootstrap `RECOVERY_COMPLETE(term, hash)`; only then zero completed
   victim slots and claim one normally (or convert an eligible GUARD to
   ACTIVE); ACTIVE heartbeat; `xfs_mountfs`.

### 5.4 Refusals (in addition to §4)

Old key tied to more than one `host_uuid`; more than one non-retired
predecessor candidate for our host; our `boot_uuid` under another identity;
key/key_gen rollback or ABA; an unclassifiable transport ID; READ FULL
STATUS unsupported, unstable between reads, or inconsistent across paths;
an unknown reservation holder; the old key on a transport ID not proven
ours; nexus teardown unprovable on any predecessor path; incomplete
multipath (a path that cannot be checked or updated); ledger, slot,
bootstrap record and FULL STATUS disagreeing on fs/host/boot/key/gen; a
live intent owner on the predecessor descriptor; a bootstrap term owned by
a live different incarnation; bad crc / slot binding / stale term.

### 5.5 Full occupancy

With the bootstrap record a 64-node cluster bootstraps: the provisional
identity owns and completes at least one recovery without a slot, and the
slot it frees is then claimable.  Claiming the own predecessor's slot
directly into a GUARD (C(b) in the ruling) is a fallback only — it needs
the provisional identity anyway and does not cover replacement hardware.

### Build order, revised

3. Bootstrap region + record + CAS claim/heartbeat/seal/complete/takeover
   API; owner-liveness consults it; mkfs/chk support.  No behaviour change
   on the ordinary mount path.
4. Self-succession under a `SELF_SUCCESSION` intent + certificate; fence
   consumption of that certificate; ledger `FENCE_INTENT`/`succeeds`.
5. Mount bootstrap path (§5.3 phases 1-5) entered on REGISTER -EEXIST with
   a valid identity match; `tests/no_survivor_crash_replay.sh` unattended.
6. The 19-case matrix.

## Item 2 correction (sess439): the ledger is written AFTER REGISTER

Chain 17 on 0.43.0 measured the flaw in "ledger PREPARED before REGISTER":
the first node up registers and takes the WE-AR reservation, and from then
on an UNREGISTERED initiator cannot write any sector of the LU — the
PREPARED CAS returned RESERVATION CONFLICT (`P-PRKEY-PREPARE-FAILED
rc=-52`) on 31 of 32 nodes and only test1 mounted.  The same applies to the
bootstrap record: a provisional identity must REGISTER before it can CAS
anything.  Design-consult ruling: `docs/rulings/prkey-register-before-ledger-derived-key.md`.

As built in 0.44.0 (`dlm/prledger.{c,h}`, `dlm/scsipr.c`, `pal`):

- The key is DERIVED, not drawn: `mxfs_prledger_derive_key(host_uuid,
  boot_uuid, fs_uuid)` (≥ 2³², ≠ ~0).  The same boot on the same LUN always
  recomputes it, so a module reload or retried mount needs no on-LUN record
  to reuse its registration.  A collision (another owned ledger entry, or
  READ KEYS showing the key when our nexus does not hold it) is REFUSED —
  never redrawn, since reproducibility is the property.
- Order: `select` (no write: derive, scan the ledger for our own entry /
  collisions / a reusable entry, remember READ KEYS's view) → plain
  REGISTER; on RESERVATION CONFLICT, `REGISTER(rk=K, sark=K)`
  (`mxfs_pal_scsi_pr_register_swap`) proves whether this nexus already
  holds our own key (same boot, `P305-PR-SAME-BOOT-KEY-REUSED`) — any other
  key on our nexus is still the P305 predecessor refusal → READ KEYS verify
  (`P-PRKEY-REGISTERED`) → `mxfs_prledger_publish`: CAS the reusable entry
  straight to REGISTERED (`P-PRKEY-PUBLISHED`), or refuse on collision, in
  which case the mount path unregisters.
- What is lost: a crash between REGISTER and the publish leaves a
  registration no peer can attribute.  It is an explicit fail-closed state
  (a future bootstrap refuses on an unclassifiable registrant); the same
  boot's next mount repairs it; a peer never guesses and deletes.
- Self-succession (item 4) therefore uses `REGISTER(rk=old, sark=new)` on
  our own nexus — a nexus-local compare-and-swap that fences nobody and
  needs no on-LUN intent — followed immediately by the successor's ledger
  entry `REGISTERED{new, succeeds={old_key, old_boot, old descriptor
  generation}}`.  The `SELF_SUCCESSION` intent on the predecessor's slot is
  required before any PREEMPT AND ABORT of the old key elsewhere (other
  paths), and a peer may certify an absent old key as replaced only with
  that durable successor record corroborated by READ FULL STATUS.

## Item 4 as built (sess439, 0.45.0) — self-succession

Successor side (`dlm/v5_mount.c v5_self_succeed`, reached when the plain
REGISTER conflicts and `REGISTER(rk=K, sark=K)` proves the nexus holds a
DIFFERENT key, CAW transport, `single_node_exclusive=0`):

1. `mxfs_prledger_find_predecessor`: exactly one REGISTERED entry with
   `host_uuid == ours`, `boot_uuid != ours`, `fs == ours` whose key READ KEYS
   still shows (`P305-PR-PREDECESSOR-CANDIDATE`); none or more than one ⇒
   `P305-PR-SELF-SUCCESSION-REFUSED` (never guess).
2. Clone scan (refusal evidence only): two reads of the 64 heartbeat sectors
   2.5 s apart; a record carrying our `host_uuid` under another boot whose
   stamp advanced ⇒ `P305-PR-HOST-DUPLICATE-LIVE`, refused.
3. `mxfs_scsipr_register_succeed` → `mxfs_pal_scsi_pr_register_swap(old,
   new)` (`P305-PR-PREDECESSOR-BOOT-REPLACED`) → READ KEYS verify.
4. `mxfs_prledger_publish(..., succeeds{old_key, old_key_gen, old_boot})`
   (`P-PRKEY-PUBLISHED ... succeeds=0x…`); the entry layout gained
   `succ_old_key/succ_old_key_gen/succ_old_boot` at offsets 104/112/120.

Prover side (`v5_self_succession_consume`, after `mxfs_scsipr_fence_node`
returns `KEY_ABSENT_UNPROVEN` under our attempt lease): the victim's
host/boot uuids are frozen with its key in the death snapshot
(`mxfs_disklock_victim_identity`); `mxfs_prledger_find_successor` must find
exactly one REGISTERED entry naming `{old_key, old_boot}` under the victim's
host; READ FULL STATUS must show the old key absent and the successor key
present; then the certificate kind is `SELF_SUCCESSION_DONE` (proves
exclusion; the victim's ledger entry is marked FENCED after certification).
Anything less stays `KEY_ABSENT_UNPROVEN` and is retried
(`P238-FENCE-ABSENT-NO-SUCCESSOR / -UNCONFIRMED / -SUCCESSOR-UNCONFIRMED`).

Not in item 4: the `SELF_SUCCESSION` intent for a PREEMPT AND ABORT of the
old key on OTHER paths (multipath where a path's session was not
reinstated) — that path still ends in `KEY_ABSENT_UNPROVEN`/P305 refusal
and belongs to item 5 with the bootstrap phases.

## 6. Item 5 — the slotless bootstrap owner, as ruled (sess440)

design-consult build review: `docs/rulings/item5-slotless-bootstrap-build-review.md`.
The phase structure of §5.3 (claim, seal, fence all, replay all, global
commit, only then ACTIVE) was confirmed; the first build plan drew ten
STOP-SHIPs.  What follows is the plan with each of them folded in.  The
measured trigger is chain 22 s439d on 0.45.0: the lone rebooter
self-succeeded and then hit `P300-CLAIM-EXHAUSTED` — 32 dead ACTIVE records
on a 32-slice volume, so no slot, no slice, no `xfs_log_mount`, and the only
replayer (the survivor engine, §3) had no way to run.

### 6.1 Entry — the survivor scan

In `mxfs_v5_dlm_init`, after REGISTER / self-succession / ledger publish /
reserve / admission validation and after the bootstrap record read, and
BEFORE the ordinary slot claim: read all 64 heartbeat sectors twice, at
least one full dead window apart (the monitor's own `dead_timeout_ms`, plus
the read-loop duration, on a monotonic clock, FUA reads).  Any occupied
record whose stamp, identity, flags, generation or feature block changed ⇒
a survivor exists ⇒ the ordinary path (claim a free slot, or the existing
P300 refusal: the survivor resolves the dead slices).  No change on any
record and at least one occupied member-shaped record ⇒ a total outage ⇒ the
bootstrap path, REGARDLESS of free slots (a fresh ACTIVE claim over a total
outage is the rejected proposal B of §5).  A torn / unparseable occupied
record fails closed (bootstrap refused, `P-BOOT-SCAN-UNREADABLE`).  Zero
occupied records ⇒ fresh volume, ordinary claim.  The scan is a failure
detector, not proof: safety comes from fencing every presumed victim before
any replay.

A record already CLAIMED / SEALED / RECOVERING by another identity: if
`owner_is` is fresh (age < ABANDON), WAIT — bounded by
`popcount(victim_bitmap) × replay budget + fence budget` — for
RECOVERY_COMPLETE and then take the ordinary path; if stale beyond ABANDON,
fence the owner's key (P&A, or consume its self-succession if it was our own
predecessor boot) and `mxfs_bootstrap_takeover(term+1)`, resuming from the
recorded state.  Silence alone never replaces an owner.

**Waiters do not register.**  The bootstrap record is read BEFORE the
REGISTER step (reads are permitted to an unregistered initiator under
WE-AR).  A node that sees a claimed term neither registers nor
self-succeeds; it polls and restarts the mount from REGISTER after
RECOVERY_COMPLETE.  This is what makes the registrant set closed (6.3).

### 6.2 Provisional identity

`node_id` = ours; `epoch` = drawn ONCE by `hb_draw_incarnation` and carried
unchanged into the ACTIVE claim of 6.6 (`mxfs_disklock_claim_slot` must
accept a pre-drawn epoch; today it draws its own at every claim); `pr_key /
key_gen` = our registered key; `nonce` random.  CAS CLAIMED; a bootstrap
heartbeat thread CAWs the record every `MXFS_BOOTSTRAP_REFRESH_MS`; `-ESTALE`
aborts every further destructive step (each step re-validates the term
before starting and before publishing).

Descriptors we own carry an explicit `owner_kind = BOOTSTRAP` (descriptor v4,
`MXFS_PROTO_GEN` bump) with `owner_slot = MXFS_RECOV_NO_SLOT`; consumers
dispatch on the kind — `BOOTSTRAP` ⇒ require `NO_SLOT` and consult
`mxfs_bootstrap_owner_is(node, epoch)`; otherwise ⇒ `owner_slot <
slot_max` and the heartbeat sector.  Audit (sess440): the descriptor's
`owner_slot` has one in-kernel reader (`disklock.c` outcome-record copy)
and two offline decoders (`chk_mxfs`, `recov_forge`); every other
`owner_slot` in the tree is a DLM lock record or a log token naming the
VICTIM's slot, which the owner never writes.  `v5_incarnation_state`
already resolves a slotless tuple through `owner_is` (0.45.0).

### 6.3 Seal — every non-owner key is in the manifest

At seal time (a FRESH scan after winning CLAIMED), classify every key READ
KEYS returns:

1. the owner's current key;
2. a victim key with a slice — named by a dead member-shaped record (ACTIVE,
   WITHDRAWN, or a RECOVERY_GUARD with a sub-complete descriptor whose owner
   is dead), including out-of-range records ≥ slice count (fenced, never
   replayed);
3. a slotless pre-bootstrap registrant — a ledger REGISTERED entry named by
   no record: it holds write permission under WE-AR and is FENCED (P&A,
   ledger FENCED), with nothing to replay;
4. a valid self-successor — a ledger entry `N succeeds {O, old_boot}` where
   O is a class-2 key: N is NOT a P&A target; the owner's fence of O
   consumes the certificate (`SELF_SUCCESSION_DONE`) exactly as item 4's
   prover does;
5. anything else ⇒ unclassifiable ⇒ bootstrap refused (`P-BOOT-KEY-UNCLASSIFIED`),
   record left CLAIMED for the operator / a retry after the key's owner
   explains it.

The sealed manifest is the immutable list itself — `{slot, victim node,
epoch, host, boot, pr_key, key_gen, class}` per entry — written to the
bootstrap region (the region is `bootstrap_size` bytes, one sector holds
the record; the manifest occupies the following sectors, crc'd, hash in the
record).  A takeover resumes from the manifest, never from sectors that a
completed slot may already have erased.

### 6.4 Phase 3 — fencing, in `mxfs_v5_dlm_init`

For each class-2 slot: mark pending from the record's tuple, then the
existing `mxfs_v5_dlm_recovery_acquire` up to the certificate (intent CAS,
P&A of the victim key; an absent key with a class-4 successor ⇒
`SELF_SUCCESSION_DONE`; an absent key with nothing explaining it ⇒
`KEY_ABSENT_UNPROVEN` ⇒ bootstrap refused, `P-BOOT-FENCE-UNPROVEN`).  Our own
current key is never a target (`P238-FENCE-OWN-KEY`).  For each class-3 key:
P&A + ledger FENCED (a ledger-only intent; no descriptor).  Ambiguous
command completions are resolved ONLY by READ FULL STATUS (ruling Q6 case
4): O present ⇒ retry; O absent + N present + durable successor ⇒
succession certificate; O and N absent + our sealed P&A evidence ⇒ our
certificate; O and N absent with no evidence ⇒ unproven; O and N both
present ⇒ refuse (multipath / nexus anomaly).  A no-op P&A on an absent key
proves nothing.

### 6.5 Phase 4 — replay, from `xfs_mountfs`

`mxfs_v5_dlm_init` returns with the ctx in BOOTSTRAP_OWNER state:
`node_slot = -1`, no CAW DLM engine, no monitor thread, bootstrap heartbeat
running, phases 1-3 durable.  `xfs_mountfs` at the log-slice selection
point (after per-AG init, before `xfs_log_mount`) calls
`mxfs_dlm_bootstrap_recover(mp)` when `m_mxfs_node_slot < 0` and the ctx is
a bootstrap owner.  It runs the barrier's replay loop over `manifest slots
& ~complete_bitmap & in-range`: classify → `recovery_acquire` (already
certified: this takes the execution lease under the provisional tuple) →
`mxfs_xlog_recover_foreign_slice` (the shadow log) — and NOT the completion
ladder yet.

**Gate: the `m_log == NULL` audit.**  The shadow engine allocates its own
`xlog` and AIL and takes no DLM grants, but its `!mp->m_log` guard is an
architectural precondition until every accepted item handler is shown
independent of the mounted log (buffer / inode / dquot / icreate handlers,
intent handlers, `xfs_log_force`, mount AIL, transaction allocation,
delwri ownership, verifier shutdown paths, workqueues outliving the shadow
log).  Proof = the call-graph audit plus a rig run with `mp->m_log` set to
a POISON pointer during phase 4 (an oops in a test VM is the detector),
every accepted item type exercised, and synchronous drain before return.
The shadow log is passed explicitly; it is never assigned to `mp->m_log`.
Until this gate passes item 5 does not ship.

### 6.6 Completion — evidence first, zeroing last

After EVERY manifest slice is replayed (under a bootstrap term the barrier
completes the sealed set only after all replays; outside a bootstrap term
the ordinary barrier publishes each foreign slice as soon as it is durably
replayed, exactly as the live reap path does, because the replay gate judges
every image against the victim's own sealed manifest and never against
another victim's grants), for each slot
run the completion ladder to `GRANTS_RELEASED` (durable per-slot evidence:
certificate, descriptor history, outcome) but HOLD step 3 (the heartbeat
sector zero — `mxfs_disklock_purge_node`); CAS the bootstrap
`complete_bitmap` bit.  Then: READ FULL STATUS reconciliation — every
remaining key must be the owner or a class-4 successor of a certified
victim, else refuse.  Then CAS `RECOVERY_COMPLETE(term)`.  Only then zero
every completed victim sector and purge its CAW manifest.  A slot that
ended TERMINAL (quarantined, intents undischarged, policy refused) does NOT
complete the bootstrap: the record goes to a new `BOOTSTRAP_REFUSED`
state naming the slot, the verdict stays in the sector, and the mount is
refused — a quarantined slice is not a recovered slice.

Then the ordinary join, from the hook: `mxfs_disklock_claim_slot` with the
pre-drawn epoch (free slots exist now; the allocator takes an in-range slot
whose slice was replayed and zeroed — a fresh claim, `slice_adopted = true`,
so `xfs_log_mount` will not re-apply the replayed images), CAW capability
check, CAW DLM engine, HB/monitor thread, stop the bootstrap heartbeat,
`m_mxfs_node_slot` set, and `xfs_mountfs` continues into `xfs_log_mount`
and an empty barrier cut.

### 6.7 Crash / retry

- Owner crash mid-phase: nothing was zeroed; every certificate, descriptor
  and the manifest are durable; a takeover (6.1) trusts a `complete_bitmap`
  bit only if the slot's descriptor validates at `GRANTS_RELEASED` under the
  sealed term, re-acquires and replays every other slice, reconciles READ
  FULL STATUS before resuming and before completing.
- Same-boot retry (the hook failed and the mount unwound; same host, same
  boot, same key): an exact-owner RESUME — the record still names our
  `{host, boot, node, epoch, pr_key, key_gen, nonce, term}` — continues the
  SAME term (no takeover, no fence: our own key cannot be P&A'd and
  self-succession proves nothing here), under a local single-process
  exclusion.  Anything short of an exact match needs a new boot and the
  fence rules.
- The pre-existing self-succession hole (a peer that swaps O→N and dies
  before its ledger entry is durable) is permanently unprovable by design
  and needs an operator repair path; it is filed separately, not guessed
  around.

### Build order

5a. `owner_kind` in the descriptor (v4, PROTO_GEN 14), pre-drawn epoch for
    `claim_slot`, `mxfs_scsipr_unregister` refusing a non-owned key (0.45.2).
    Rig-verified 0.45.3 (sess441 chain 25: prep, fence_during_write,
    node_death_replay, remount_snx, remount_refused on 32/caw).
5b. Survivor scan + waiter-before-REGISTER ordering + manifest sectors +
    class-3 fencing; `no_survivor_crash_replay.sh` must reach
    MANIFEST_SEALED / RECOVERING with 32 certificates (no replay yet).

    **As built (sess441, 0.46.0)** — `dlm/v5_mount.c`:
    - `v5_bootstrap_peek()` runs BEFORE `v5_prkey_setup`/REGISTER on the CAW
      path: a record in CLAIMED/SEALED/RECOVERING/REFUSED refuses the mount
      with `P-BOOT-ADMISSION-REFUSED-PREREGISTER` so no waiter key ever has to
      be classified (ruling Q3).  `v5_bootstrap_setup` (after the disklock)
      re-reads under the same rule.
    - `v5_bootstrap_run()` sits between `set_slot_limit` and `claim_slot`.
      Window = dead window (`lease_timeout_ms`) + one scan poll; a table that
      moves or is empty returns 0 (ordinary claim, +2.5 s on a live cluster).
      Frozen ⇒ `P-BOOT-SCAN-FROZEN` ⇒ CLAIM (`P-BOOT-CLAIMED`) ⇒ record
      heartbeat thread (`v5_boot_hb_fn`, 1 s, `-ESTALE` ⇒ `boot_hb_lost`
      halts every further step) ⇒ `set_owner_bootstrap` + `predraw_epoch` ⇒
      FRESH full-window scan ⇒ `v5_boot_classify_keys` (READ KEYS; owner /
      victim-explained / ledger class 3 / ledger class 4 via `succ_old_key` /
      else `P-BOOT-KEY-UNCLASSIFIED` refuse) ⇒ `manifest_write` ⇒ `seal`
      (ledger_gen = the target's PR generation at classification) ⇒
      `set_recovering` ⇒ phase 3.
    - Anything failing BEFORE the seal hands the record back
      (`mxfs_bootstrap_release_claim`, CLAIMED→IDLE, `P-BOOT-RELEASED`):
      nothing durable happened yet.
    - Phase 3: class 2 ⇒ `mxfs_disklock_mark_recovery_pending_ident` (the
      victim's key/gen/host/boot frozen from the MANIFEST — there is no
      monitor snapshot after a total outage; `P-BOOT-VICTIM-FROZEN`) then the
      ordinary `mxfs_v5_dlm_recovery_acquire` (UNFENCED ⇒ P238-FENCE-REDRIVE ⇒
      intent ⇒ P&A ⇒ certify ⇒ snapshot ⇒ lease); `-EBUSY` on pass 1 is
      deferred to pass 2 (a descriptor owned by another victim's dead
      incarnation).  Class 3 ⇒ `v5_boot_fence_registrant`: key present ⇒ bare
      P&A, certified ONLY as `PREEMPT_ABORT_DONE`, ledger FENCED,
      `registrant_done`; key absent ⇒ explained only by a class-4 successor
      present on the target, else `P-BOOT-FENCE-UNPROVEN`.  Class 4 ⇒ never a
      target.  Any unproven entry ⇒ `mxfs_bootstrap_refuse(slot,
      FENCE_UNPROVEN)` ⇒ REFUSED.
    - `P-BOOT-PHASE3-COMPLETE certs=N` then, in this build,
      `P-BOOT-REPLAY-UNBUILT` ⇒ mount refused `-ENOSYS`, record left
      RECOVERING (admission closed for everyone; certificates + manifest
      durable for 5d).  Same-boot RESUME (§6.7) is 5e, so a retry in the same
      boot is refused at the peek until mkfs/`chk_mxfs --clear-bootstrap`
      (the latter is not built yet either).
    - Exemption: every frozen record belonging to THIS host's THIS boot is the
      same-boot dirty predecessor (`P-BOOT-SCAN-OWN-BOOT`), owned by the P305
      path — its key is ours and cannot be preempted; not a bootstrap.
    - design-consult code review (sess441, `docs/history/gpt-review-item5b-landing.md`) applied before the
      first measurement: SS-1 the refusal after the seal RETAINS the owner's
      key and ledger entry (`mxfs_scsipr_retain_key`; the record names that
      key and a takeover is authorised only by fencing it) — only a claim
      handed back before the seal leaves nothing behind; SS-8 a key published
      by two victim records, or a victim publishing OUR key inside a total
      outage, is unclassifiable (refuse); SS-9 the own-boot exemption also
      requires READ KEYS to hold no foreign key, else it is a total outage.
      SS-4 (heartbeat vs. transition serialisation) is already satisfied:
      both run under `b->lock`, reload the platter and validate by
      term/owner/nonce, never by exact image.  Deferred to 5c/5d: post-seal
      registrant reconciliation before replay (F-1), a durable defer/resume
      policy for `-EBUSY` (F-2), READ FULL STATUS at completion (F-7).
    - Measurement: `tests/bootstrap_seal_fence.sh` (chain 26, sess441).
5c. The `m_log` audit + poison run.  **SUPERSEDED (sess441 design-consult ruling,
    `docs/rulings/item5d-adopt-one-slice.md`)**:
    the pre-`m_log` shadow replay (shape A) is not built.  Facts: the
    foreign engine hard-refuses without `mp->m_log` (xfs_log.c:938), skips
    intents by design, and the mount-cohort barrier already runs after
    `xfs_log_mount`; the own-log path does FULL replay including intents.
5d. **Shape B — adopt ONE certified victim slice K.**  After phase 3 for
    every entry: select K deterministically (a stale predecessor
    `BOOTSTRAP_PENDING` record first, else the lowest certified class-2
    slot); ESCROW K's complete descriptor + certificate + victim tuple + the
    new claim identity into the bootstrap record's reserved bytes
    (PREPARED, durable, read back); CAW K's sector from the exact guarded
    image to `ACTIVE` + `MXFS_HB_FEAT_BOOTSTRAP_PENDING` with
    `slice_adopted = false` (FULL replay, never ADOPTED_SLICE); escrow →
    K_CLAIMED; the mount continues normally: `xfs_log_mount` on K replays K
    fully (a torn K is a terminal `K_REPLAY_REFUSED`, never a fallback to
    another slot in the same term); the existing barrier replays the N-1
    other manifest slices (leases already held from phase 3); each slot's
    completion ladder CASes its `complete_bitmap` bit AFTER `GRANTS_RELEASED`
    and BEFORE its sector zero (durable per-slot evidence precedes the
    erase; zeroing precedes `RECOVERY_COMPLETE` because that state opens
    admission); every N-1 slice's intent census must be clean (else durable
    REFUSED); READ FULL STATUS reconcile (only the owner key and class-4
    successors remain) persisted; `RECOVERY_COMPLETE`; normalise K's record
    (clear the PENDING flag); stop the record heartbeat.  K is never zeroed.
    Crash windows: escrow-but-unclaimed ⇒ successor resumes the CAW or
    abandons the term with nothing lost; K claimed ⇒ K's record carries the
    term so a scanner correlates it with the escrow; owner dies after
    claiming K ⇒ the next term sees K as a FRESH class-2 victim (new fence,
    new certificate; the old escrow never fences the failed owner) and
    prefers it as its own K.  12 STOP-SHIPs in the memory.
    `no_survivor_crash_replay.sh` unattended: 32 replays (1 own + 31
    foreign), 32 payloads, clean umount, chk clean.
    **Measured (sess442, chain 27 s441d on 0.47.0,
    `tests/evidence/20260829T065923Z_bootfull`)**: the owner path ran to the
    barrier — seal 32, 32 certificates, escrow read back, K=0 adopted, own-log
    FULL replay clean, 24 foreign slices complete — and then refused 7 slices
    (exactly the ones carrying dirty tokened transactions).  Root, proven from
    the evidence and the code: `v5_rman_snapshot` seals a `NO_CAW_TABLE`
    manifest whenever `ctx->dlm_caw == NULL`, and the bootstrap owner fences
    at phase 3 with no CAW engine (§6.5) — so every victim's fence-time
    manifest was EMPTY and the evaluator answered `-ENODEV` per lookup
    (`manerr=3`, ATOMIC-SKIP, TORN-UNPUBLISHED, terminal).  Fixed in 0.48.0:
    `mxfs_dlm_caw_manifest_collect_dev` reads the lock region from the bare
    device (`disklock_offset + MXFS_DISKLOCK_HB_SIZE`); the owner uses it.

    **design-consult code review of the landing (sess442, `docs/history/gpt-review-item5d-code-landing.md`)** — four
    provisional concerns refuted by the code; four STOP-SHIPs, all in 0.48.0:
    S1 an adopted slice refuses `norecovery` (`P-BOOT-ADOPTED-NORECOVERY`);
    S2 RESUME wired (5e below); S3 reconcile requires the owner's own key
    present (`P-BOOT-RECONCILE-OWN-KEY-ABSENT`, term left standing); S4 a
    completion bit that landed before its zero is redone by the resume.  Plus:
    only a TYPED verdict ends the term on K (`mxfs_v5_dlm_bootstrap_k_refused`
    from `xfs_log_mount`: the authority refusal, or a torn K =
    `-EFSCORRUPTED/-EUCLEAN` from `xlog_recover`); every other unwind leaves
    `K_CLAIMED`/`K_REPLAY_OK` resumable — 0.47.0 turned any unwind into a
    terminal REFUSED term.  The barrier stops at the first terminal slice
    under a bootstrap term (chain 27 printed `P-BOOT-COMPLETE-CASFAIL` ×24
    after the refusal; every sector stayed held).

5e. **Same-boot RESUME — as built (sess442, 0.48.0).**  A mount that claimed
    the record and unwound leaves: the record CLAIMED/SEALED/RECOVERING
    naming our host/boot/key, our retained key on the nexus, every
    descriptor owned by our {node, epoch}, and (after adoption) K as our
    ACTIVE|BOOTSTRAP_PENDING record.  **An unfinished term is never a clean
    departure**: the full destroy used to run `release_slot` (CAS K → EMPTY —
    the victim's slice discarded as "released", nothing left to resume);
    now `bootstrap_owner && !boot_finished` suppresses the release and the
    GOODBYE (`P-BOOT-DEPART-UNFINISHED`).  The next mount of the same boot:
    - `v5_bootstrap_peek` (pre-REGISTER): a claimed term whose owner
      host/boot uuid is ours is a resume candidate, not a refusal
      (`P-BOOT-RESUME-CANDIDATE`); a REFUSED term refuses even its owner.
    - after `v5_prkey_setup`: the derived key must equal the record's
      (`P-BOOT-RESUME-KEY-MISMATCH` refuses); `ctx->node_id` becomes the
      record's `owner_node` BEFORE REGISTER/publish/disklock
      (`P-BOOT-RESUME-IDENTITY`), so every record and ledger entry carries
      the identity the term's descriptors name.
    - REGISTER finds our key on the nexus (`nexus_reused`);
      `v5_same_boot_dirty_scan` exempts the ACTIVE|PENDING record of
      {owner_node, owner_epoch} (`P-BOOT-RESUME-OWN-K`).
    - `v5_bootstrap_setup` lets our unchanged record through.
    - `v5_bootstrap_run` → `v5_bootstrap_resume_prepare`:
      `mxfs_bootstrap_resume` (exact host/boot/key/gen match; adopts
      node/epoch), `mxfs_disklock_adopt_epoch` (the term's incarnation is
      ours; pre-drawn), record heartbeat, manifest read + hash check,
      SEALED → RECOVERING, then the prefill of `done[]`: class 2 = K by the
      sector (a guard is re-leased like any victim; our own record is
      re-taken by the adoption), else done iff its completion bit is durable
      AND the sector is no longer a guard (bit set + still guarded ⇒ the
      ladder tail runs again through the barrier); class 3 done iff the
      ledger entry is FENCED (a FENCED entry whose `registrant_done` CAS did
      not land is CAS'd now); class 4 done.  CLAIMED-only ⇒ release, ordinary
      path.  Then `goto phase3` — the same two-pass fence loop.
    - Adoption on a resumed escrow, `v5_bootstrap_adopt_resume`: PREPARED +
      K still a guard ⇒ the escrow is RE-PREPARED with the current guarded
      image (the lease fields moved across the unwind's relinquish +
      re-acquire; the certificate did not; `P-BOOT-ESCROW-REPREPARE`) and
      `claim_victim_slot` runs; PREPARED + our ACTIVE record, K_CLAIMED,
      K_REPLAY_OK ⇒ `mxfs_disklock_reclaim_own_slot` (our ACTIVE|PENDING
      record of {node, epoch}, nothing written, provenance continued,
      `slice_adopted = false`: FULL replay of our own log again).
    - The mount then continues exactly as 5d; `finish` completes the term.
    - Measurement: `tests/bootstrap_resume.sh <label> <point>` with the
      TEST-ONLY one-shot `mxfs.bootstrap_inject` = 1 (after phase 3, escrow
      NONE) / 2 (after PREPARED, before the claim CAW) / 3 (after K claimed);
      chain 28 (sess442) runs the full restart and all three.
    - Operator path: `chk_mxfs --clear-bootstrap` hands a REFUSED record back
      to IDLE (term carried forward; `prev_owner_*` = the refused owner,
      `prev_fence_kind = 0`); offline only (O_EXCL + 3 s heartbeat liveness);
      a TERMINAL_SLICE refusal requires the named sector to carry no
      descriptor first.  A CLAIMED/SEALED/RECOVERING term is never cleared by
      an operator: its owner resumes it, or a peer takes it over.
5f. Takeover arm (owner in a DIFFERENT boot, D-0450) — §6.8 below; the
    19-case matrix (item 6).

### 6.8 Item 5f — takeover of a term whose owner died in another boot

Rulings: ccmemory `ccloop-c7ee71c6-sess442-GPT-ruling-item5f-bootstrap-
takeover` (design) and `ccloop-c7ee71c6-sess443-GPT-review-item5f-takeover-
build-plan` (the plan below, with its eight STOP-SHIPs applied).  Neither
today's blind carry-forward (`mxfs_bootstrap_takeover`, state/bitmaps/manifest
copied to T+1 after a caller-supplied fence kind) nor a blind reset is
lawful: the successor RESEALS a new term T+1 from VALIDATED inheritance.

**Region (PROTO_GEN 17, record v5, `MXFS_BOOTSTRAP_BYTES` 8 → 32 KiB; the
super's `bootstrap_size` carries the geometry and a gen-17 kernel refuses a
smaller region).**

| sectors | contents |
|---|---|
| 0 | the record (v5: + `lineage_count`, `takeover_gen`) |
| 1–15 | manifest bank A (terms with even parity) |
| 16–30 | manifest bank B (odd parity) — T+1's manifest never overwrites T's, which the takeover validates and imports from |
| 31 | TAKEOVER journal (one CAW-written sector, §6.8.2) |
| 32–39 | completion TOMBSTONES, 64 × 64 B, 8 per sector, sector updated by exact-image CAW (§6.8.4) |
| 40–47 | LINEAGE, one 512-byte entry per ended term (§6.8.5); 8 hops, then operator |
| 48–63 | reserved |

A fresh IDLE→CLAIM resets the episode: lineage_count 0, tombstones cleared
(the bank of the new term is rewritten anyway).

**6.8.1 Contender.**  `v5_bootstrap_peek` finds a CLAIMED/SEALED/RECOVERING
record whose owner is not this boot.  It no longer refuses: the mount
REGISTERs its key first (review SS-1: under WE-AR an unregistered host cannot
CAW the TAKEOVER sector, so the election cannot precede REGISTER — a loser
unregisters its own key; a dead loser is a class-3 registration the eventual
owner fences), then in `v5_bootstrap_run` snapshots the record image R0 on
its own clock and re-reads every second: any change restarts the window; R0
unchanged for `MXFS_BOOTSTRAP_ABANDON_MS` (bounded: three windows, then the
mount is refused as today) ⇒ ELECTION = exact-image CAW of the TAKEOVER
sector from EMPTY (or from a stale CONTENDER whose own seq did not advance
across the same window) to `CONTENDER{target record identity = term + nonce
+ owner tuple + key, R0.seq, our tuple + key, nonce, seq}`.  A lost CAS ⇒
unregister, -EAGAIN, mount refused.  The winner heartbeats the TAKEOVER
sector (seq++, 1 s, exact-image CAW; -ESTALE aborts every further step).

**6.8.2 The TAKEOVER journal** is a staged, durable record of the takeover
so a successor contender can tell "fenced then crashed" from "key vanished":
`CONTENDER → OLD_FENCE_INTENT → OLD_FENCE_DONE → [K_DESCRIPTOR_DONE] →
CAPSULE_WRITTEN → RECORD_COMMITTED`.  It binds the target record identity,
the old owner's exact tuple + key, our tuple + key, the PREDECESSOR
contender's tuple + key when we replaced one (kept, never overwritten away),
the fence kind + PR generation of every fence it performed, and K's
descriptor crc.  Every write is an exact-image CAW.

**6.8.3 Fences, in order** (review ordering, 16 steps):
1. REGISTER + ledger entry;  2. election CAW;
3. replacing a stale contender ⇒ fence INTENT for it, P&A its exact key,
   certificate in the journal, its exact tuple into `dead_incarnations`
   (a stale contender's in-flight descriptor CAW / manifest write / record
   CAS is stopped only by the fence, never by its heartbeat failing later);
4. old-owner fence INTENT durable;
5. fence the old owner O.  Shape by T's escrow:
   - `K_CLAIMED` / `K_REPLAY_OK`: K's sector is O's ACTIVE|PENDING record
     ⇒ `mark_recovery_pending_ident(K, O tuple from R0)` +
     `recovery_acquire(K)`: intent → P&A(O's key) → PREEMPT_ABORT_DONE
     certificate in K's descriptor → fence-time manifest snapshot of slot
     K's CAW bits (O's grants) → lease.  K's descriptor is now the takeover
     descriptor for K's SECOND incarnation.
   - `PREPARED` does NOT prove K unadopted (crash between the claim CAW and
     escrow K_CLAIMED): read K against the escrowed guarded image — still
     the victim guard ⇒ O slotless; O's ACTIVE|PENDING record ⇒ as
     K_CLAIMED; any third image ⇒ terminal.
   - `NONE` (or PREPARED with K still guarded): O is slotless ⇒ bare P&A of
     R0.owner_pr_key, PREEMPT_ABORT_DONE, ledger FENCED, certificate in the
     journal.
   - `K_REPLAY_REFUSED`: terminal for the operator; never a takeover.
   - O = our own host's previous boot: self-succession (item 4) is accepted
     ONLY when the ledger successor entry binds {host, old boot, old epoch,
     old key, new boot, new epoch, new key} — and the review notes the
     ledger binding is not an I/O-abort certificate; the platform argument
     (iSCSI session teardown at reboot aborts the old nexus's commands, the
     key is on no other path) is what carries it.
6. fence DONE durable;  7. re-read the record;  8. owner/term/state/nonce/
   manifest identity must be unchanged (seq may have advanced before the
   P&A; the post-fence image is the CAS expected image);  9. take over any
   descriptor an earlier contender left (`recovery_takeover`, dead proof by
   exact incarnation);  10. write the T+1 manifest bank;  11. write an
   INHERITED tombstone for every completed slot being carried;  12. lineage
   entry;  13. revalidate TAKEOVER ownership;  14. CAS the record → T+1;
   15. record heartbeat;  16. clear TAKEOVER by exact-image CAW iff it still
   names us.

Dead-owner proof is INCARNATION-scoped (ruling STOP-SHIP 3):
`dead_nodes[node]` becomes `dead_incarnations[{node, epoch, key}]`;
`v5_incarnation_state` answers REVOKED only on an exact tuple match.

**6.8.4 What T+1 inherits** — by T's state (review SS-5):
- CLAIMED: nothing is sealed; fence O, then the ORDINARY fresh scan / claim
  / classify / seal flow under T+1 (`prev_owner_*` = O).
- MANIFEST_SEALED: import the manifest (bank T%2, validated by
  R0.manifest_hash); no completion to inherit.
- RECOVERING: import the manifest + completion proofs + escrow/K state.

Entry classes in T+1 (the 64-byte manifest entry gains nothing; classes
carry the meaning): class 2/3/4 as today; **class 5 FENCED_OWNER** = O
(K's slot when adopted; certificate reference); **class 6
INHERITED_COMPLETE** = a T class-2 slot whose completion is PROVEN: the
sector is still a validating guard at ≥ GRANTS_RELEASED owned by O's tuple
under T, or a tombstone validates.  A `complete_bitmap` bit with neither is
INHERITANCE_UNPROVEN ⇒ REFUSED (new reason; never silently omitted or
reprocessed).  `complete_bitmap` in T+1 = the proven bits only.  A class-6
slot still guarded is finished by the ordinary tail (its descriptor taken
over, exact-image CAW zero); an already-zero one rests on its tombstone.
No re-replay of a class-6 slot: a guard at GRANTS_RELEASED proves replay →
purge → flush → stage were durable in that order.

Tombstone (64 B, term-INDEPENDENT so a second takeover can still prove it):
`{magic, kind DIRECT|INHERITED, slot, victim node/epoch/key/key_gen,
obligation = crc of the T manifest entry, proving term, source proof crc
(INHERITED), desc crc at GRANTS_RELEASED (DIRECT), crc}`.  The owner writes
a DIRECT tombstone (exact-image CAW of its sector) after GRANTS_RELEASED and
BEFORE the completion-bit CAS; a takeover writes INHERITED tombstones for
every bit it carries before its record CAS.  A tombstone never claims T+1
replayed what T replayed.

READ KEYS after the fences: every present key must be ours, a class-4
successor, a carried class-3, or a dead contender (class 3) — else
UNCLASSIFIED refuse, as today.

**6.8.5 Lineage and the composite K.**  Before the record CAS the successor
FUA-writes `lineage[lineage_count] = {T, O tuple + key, T.manifest_hash,
T's final escrow verbatim (264 B), fence kind, crc}`.  Then the ordinary
flow: phase 3 (class 5/6 skipped), adopt K — the PENDING-flagged record is
preferred, exactly as §6.5 — escrowing K's NEW descriptor (the takeover
certificate) and its manifest pointer; K_CLAIMED; the mount continues.

K's log now holds two (or more) incarnations: the original victim V, then O
(and every later hop).  The shadow evaluator for the adopted K is built
from an ARRAY of (descriptor, manifest) pairs — the T+1 escrow (victim = O's
tuple) plus every lineage entry whose escrow reached K_CLAIMED/K_REPLAY_OK
(victim = that hop's tuple), selected per transaction by the token's {node,
epoch, slot}; a token no pair explains is refused (ATOMIC-SKIP, as today).
O's transactions are accepted only if T's final escrow was K_CLAIMED or
K_REPLAY_OK — never from PREPARED, even when the claim CAW is found to have
landed, because O's engine was not allowed to run before durable
K_CLAIMED.  **Live check (ruled):** only the LATEST pair is checked against
K's current CAW bits; older pairs are judged by their immutable sealed
manifest + certificate (a proven later incarnation was allowed to overwrite
those bits).  That is sound only because every hop carried a P&A of the
previous incarnation, the snapshot followed the P&A, the certificate binds
descriptor + manifest + slot + tuple, the lineage is an unbroken chain for
the same K, old rman storage is immutable until the episode retires, and
epochs are never reused.  **The new owner's grant engine must stay frozen
until K's own-log replay and shadow evaluation complete** — otherwise the
owner mutates the bits its own live check reads (the chain-29
P-RMAN-POSTSEAL-MUTATION risk).

**6.8.6 Paused owner.**  After the P&A completes, O's CAWs — its record
heartbeat included — are rejected by the target; O cannot alter the record
between the fence and our CAS.  Before the P&A it may bump seq, which is
why step 7 re-reads.

**6.8.7 Measurement.**  `tests/bootstrap_takeover.sh <label> <11|12|13|14>
[N] [owner] [contender]`: the owner mounts with a TEST-ONLY HOLD point
(`mxfs.bootstrap_inject` 11/12/13 = block after phase 3 / after PREPARED /
after K claimed; 14 = after the 8th foreign completion, so bits + zeroed
sectors + tombstones exist), is `virsh destroy`ed there, and a second host
must take the term over: election, fence of O's key, T manifest imported,
T+1 CAS, lineage, K adopted with composite provenance, 32 replays (minus
the inherited ones at point 14), RECOVERY_COMPLETE, payload intact, the old
owner rejoining in its new boot, clean umount, chk clean (record
RECOVERY_COMPLETE at term T+1, one lineage entry).

### 6.9 ICREATE under the authority gate — the SYNCINIT invariant (sess444, 0.51.0)

**Root, measured on chain 29 (0.48.1) and unchanged on 0.50.0.**  Every
bootstrap leg ended on one terminal slice whose only refusal was
`nonbuf_taint=1`: every buffer image of the create transaction was APPLY
(`WOULD_APPLY=9 ENFORCEABLE=9`), but the `XFS_LI_ICREATE` item — the
inode-chunk initialisation logged by the payload's file create — sat on
the strict non-buffer allowlist's deny side, so the whole transaction was
ATOMIC-SKIPped → TORN-UNPUBLISHED → the term REFUSED.  Chain 27's 24/31
clean slices were exactly the slices without a dirty create.

**Why the taint was a defect of the replay, not just a gap
(D-ICREATE-REPLAY-REINIT-CLOBBERS-PEER-INODES-0510).**  ICREATE replay
re-initialises WHOLE clusters.  An inode of that chunk may since have been
handed to a peer under inode authority and modified in another slice or
on the platter; upstream's cancellation/LSN ordering is intra-log only.
A blind re-init clobbers the peer's dinode — and a node's OWN-log replay
after its own crash is not gated at all, so the exposure there was live.

**design-consult rulings (two consults).**  (1) An AG-class APPLY sibling proves
the allocation, not every cluster write — insufficient alone.  (2) A
cluster that does not verify may never be initialised without per-cluster
authority: REFUSE, write nothing.  (3) The writer's protocol must be
persisted on the record, never inferred from the replayer's mount mode.
(4) REDUNDANT_CLEAN siblings → suppress the ICREATE entirely (a successor
may have reused the extent).  (5) A refused sibling dominates.

**As built (0.51.0).**

- *P1, the invariant* (`xfs/libxfs/xfs_ialloc.c`): on every MXFS mount
  (single-node included) each cluster of a new chunk is written with a
  raw SCSI FUA write (`P133-ICLUSTER-SYNCINIT`) before the carve
  transaction commits.  A FUA failure now FAILS the carve
  (`P133-ICLUSTER-SYNCINIT-FAIL`, `xfs_trans_binval` + error; the
  transaction is already dirty from the extent allocation, so the cancel
  shuts the mount down — fail closed).  When every cluster succeeded the
  ICREATE item is stamped with a writer-time trailer
  (`struct mxfs_icreate_trailer {MXIC, F_SYNCINIT}` contiguous after
  `xfs_icreate_log`; upstream replay reads only the struct).
- *P2, replay* (`xfs/xfs_icreate_item.c`): after upstream's cancel check,
  a SYNCINIT record FUA-reads every cluster and verifies each dinode
  (magic, v3, `di_ino` == position, meta uuid, CRC).  All verify →
  `P-ICREATE-VERIFIED`, skipped, nothing written (an allocated or
  peer-modified inode passes).  Any fails → `P-ICREATE-VERIFY-FAIL` +
  `P-ICREATE-REFUSE`, `-EFSCORRUPTED` (TORN for a foreign replay, mount
  failure for an adopted one).  A record without the trailer on an MXFS
  mount or untrusted log → `P-ICREATE-REFUSE`.  Only a non-MXFS mount
  replaying a trusted log keeps upstream's unconditional init.
- *P3, verdict* (`xfs/xfs_log_recover.c` `mxfs_report_replay_authority`):
  the ICREATE is judged after the buffer loop from its AG-class siblings
  with `res == icl_ag`: SYNCINIT proof AND no refused sibling AND (any
  APPLY → APPLY; all REDUNDANT → REDUNDANT, suppressed in pass 2 exactly
  like a REDUNDANT buffer); else REFUSE and the transaction stays tainted.
  `P-ICREATE-AUTH lsn agno agbno syncinit ag_apply ag_redundant ag_refused
  verdict[ why]`; the P273 summary carries `icreate=apply/redundant/refused`.

**Landing review (third consult) — STOP-SHIPs applied before the build:**
no ICREATE record may exist without the proof (the carve fails on
`!v3inodes`, `nbufs == 0`, or a length that is not a whole number of
clusters — `P133-ICLUSTER-SYNCINIT-GEOMETRY`); a verify READ failure is a
retryable `-EIO` abort with no verdict, only a CONTENT mismatch is the
`-EFSCORRUPTED` TORN verdict; the SCSI passthrough resolver refuses
partitions (passthrough LBAs are whole-LUN — the bio fallback
`mxfs_pal_bio_{write_fua,read}_bdev` is offset-correct and also serves
non-SCSI/loop devices, so single-node loop mounts keep carving).

**Stated assumptions (not proven here).**  The verifier is an identity
check (magic/v3/di_ino/uuid/CRC), not a proof of the init image: the
"init was on the platter before the record existed" argument also relies
on the fence + drain of a prior owner's delayed I/O to the same extent
(the D-512 reuse-barrier family).  Upstream's cancelled-buffer early
return stays as a NO-WRITE skip (the cancelling transaction's own images
are gated at their pass 2).

**Still open, re-flagged by the ruling:** an INODE-class cluster-buffer
image writes the whole cluster under authority for one inode —
D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY.

**Verification:** chain 32 (`tests/sess444_chain32_0510_icreate_syncinit.sh`)
— full restart + resume 3 on 0.51.0 must reach RECOVERY_COMPLETE with
`P-ICREATE-AUTH verdict=APPLY` and `P-ICREATE-VERIFIED` on the formerly
terminal slices; the refusal arm needs its own negative measurement (a
deliberately corrupted SYNCINIT cluster → `P-ICREATE-REFUSE`, TORN, no
write) before the defect can close.

**Measured (chain 32, 0.51.0 sv 1AB2A2C6, `20260829T085854Z_bootfull`):**
the first whole-cluster restart to complete end to end with no operator
action — 3 create transactions `P-ICREATE-AUTH verdict=APPLY` +
`P-ICREATE-VERIFIED`, zero refusals, `nonbuf_taint=0` on every slot, 31/31
foreign replays, 31 DIRECT tombstones, RECOVERY_COMPLETE, payload 32/32
from the owner and from a peer, 31/31 peers admitted, chk clean.  The one
failure is budget: the mount took 545 s (bound 540) because each
completion costs ~8.5 s in `mxfs_disklock_purge_node`'s 65536-sector
one-at-a-time scan — D-PURGE-NODE-FULL-TABLE-SECTOR-SCAN-0511, batched in
0.51.1 (`P-PURGE-DONE scan_ms`, `P-COMPLETE-TIMING` per step).

## 7. Judging a standing descriptor's holder: the view, then the platter

A descriptor at stage FENCING (its holder the prover) or SNAPSHOTTING (its
holder the attempt-lease owner), or an execution owner's descriptor at a
later stage, may be taken over only when the holder INCARNATION is proved
revoked.  Heartbeat silence never is that proof.  Two judges answer in turn
(`mxfs_v5_dlm_recovery_acquire`):

1. **The membership view** (`v5_incarnation_state`): LIVE when the exact
   tuple heartbeats or is this mount's own; REVOKED when the tuple is in
   this mount's certified-fenced set (noted at every certificate, at a claim
   that read a certificate, at completion, and when the monitor watches the
   slot zero), when a later incarnation of the same node id heartbeats, or
   when it is this mount's own earlier epoch; otherwise UNKNOWN.
2. **The platter** (`v5_holder_slot_state`), only when the view says
   UNKNOWN: the holder's own heartbeat record.  REVOKED when that record is
   all-zero end to end (only a published recovery behind a certified fence,
   or mkfs, writes zeros), when no record in the table carries the tuple
   (every slot it held was published or re-tenanted, each a terminal event:
   a claim needs EMPTY or zero first, and an ACTIVE record is never
   re-tenanted by timeout — the claim wait rescans and fails, it never
   reclassifies), or when the record under the tuple is EMPTY or
   RETIRE_PENDING (the holder's own final image; a clean unmount waits for
   the node's own parked fence or recovery work before it publishes either,
   measured s578j/k/m, so this branch cannot strand a descriptor of its
   own).  UNKNOWN for a record still standing under any other flag, a
   bootstrap holder (no slot), a sector that could not be read, and a
   sector that is neither all-zero nor a record this build recognises (the
   disklock magic and a feature block that is the pre-gate zero tail or
   carries its own magic).  That last case is the hazard the scan must not
   have: absence proves revocation only when every record it rests on was
   read AND understood, otherwise a torn or corrupted sector — which may be
   the holder's — is laundered into "no record carries the tuple".

**Why the platter judge is never reached inside the episode that publishes
the holder, and why a later mount has nothing else.**  The mount that
certifies a dead holder's fence notes the tuple dead, takes every attempt
the holder held over in the same replay round, and publishes the holder's
own recovery only after replaying its slice (measured s581a on the
crash-departed-owner shape: certificate and takeover at the same second,
`P-COMPLETE-TIMING` for the holder 20 s later).  Takeover therefore always
precedes purge within one episode, and the view answers.  A LATER mount
draws a fresh node id (`node_uuid` is random per mount context), so it can
never see the dead holder as its own earlier epoch or as a predecessor of
a live node; its certified-fenced set starts empty and holds at most 32
tuples.  A descriptor whose holder was published by an earlier episode, or
by a peer whose certificate this mount never saw, is judgeable by nothing
but the platter — the s562 state, six attempts held by two published
provers on a table that had not been re-formatted.

**How that state is produced on two nodes without forging anything**
(`tests/d0932_platter_fallback.sh`).  A staging mount runs with
`dbg_fence_takeover_decline` above zero: it fences the dead prover,
certifies, notes it dead, proves the attempt's holder revoked, and DECLINES
the takeover (`P238-FENCE-TAKEOVER-DECLINED`); the prover's own recovery is
then replayed and published by the shipped writers, the declined slice
holds the barrier, and the mount aborts at its bound.  Every byte on the
platter was written by a real fence, a real replay and a real purge; the
knob wrote nothing.  A second mount with the knob at zero is a native
judge: it prints `P238-FENCE-HOLDER-SLOT ... verdict=REVOKED` from the
zeroed slot, takes the attempt over, lays a NEW intent with the victim key
frozen from the victim's own record at admission, proves and certifies,
replays, publishes, and mounts.  The same harness asserts the fail-closed
side in the staging mount: UNKNOWN for every evaluation while the
holder's record still stood.
