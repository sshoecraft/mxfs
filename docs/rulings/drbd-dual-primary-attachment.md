# DRBD dual-primary attachment: what replaces SCSI reservations and COMPARE AND WRITE

Design consult (GPT, 2026-10-02) on `2/net/mesh/drbd`: two nodes, a local disk
each, DRBD 8.4 dual-primary on protocol C, MXFS on `/dev/drbd0`. The question
was what the attachment must supply in place of the two SCSI facilities the
TCP lock manager depends on: persistent reservations (fencing, admission,
boot succession, retirement) and COMPARE AND WRITE (heartbeat, slot claim,
recovery milestones, bootstrap owner, authority-ledger tickets).

## The verdict in one line

Plausible only as a new two-node storage and fencing architecture, never as
"PR replaced by DRBD status". The decisive gap is **continuing exclusion**: a
missing PR key keeps a fenced node out until someone deliberately lets it back;
a power-off is a point event, and a fenced peer that reboots and reconnects
breaks every proof made after it.

## Rulings

### An atomic CAS built from replicated plain I/O

A two-party Lamport bakery lock on the device, then read-compare-write of the
target sector, is **conditionally viable**. It needs the list below. The lock
itself is now a two-party one-bit lock (`docs/attachment-methods.md`, "A
compare-and-swap built on the device", says why): every requirement below is
a property of the registers and the swap around the lock, and each still
holds, with "a bounded ticket number" read as the lock's two one-bit fields.

- each register in its own aligned sector, written by exactly one enrolled
  endpoint, each step waiting for protocol-C completion, direct I/O only;
- registers carrying magic, version, participant identity, membership
  generation, boot nonce, a bounded ticket number and a checksum; corruption
  fails closed; a ticket never wraps;
- release ordered after the target write is durable under the original CAW's
  FUA semantics;
- a dead participant's ticket ignored only after that participant is fenced
  and the membership generation has advanced, never because its epoch is old;
- **immutable, complementary enrollment**: participant index bound to the
  filesystem UUID, MXFS node, DRBD endpoint and peer identity, DRBD data
  generation and the backing disk. Two nodes believing they hold the same index
  silently break mutual exclusion, so a duplicate, unknown peer, cloned node or
  changed backing identity fails closed. Resource names and minors are
  administrative names and identify nothing;
- **no plain writer to any protected sector, on any path**: error, withdrawal,
  bootstrap, retirement, repair, compatibility, zeroing. The heartbeat own-slot
  update stays a CAS; making it a plain write races takeover, purge,
  retirement, claim, adoption and a delayed write of an old incarnation.

The existing fallbacks that turn a CAS into a plain FUA write on `-EOPNOTSUPP`
(bootstrap, PR ledger) are incompatible with this and with any device without
COMPARE AND WRITE; they fail closed.

### A DRBD fence proof profile

Disconnected, local Primary and UpToDate, peer Outdated, no suspension, and a
completed node fence **can** support a new fence profile (a fresh kind; an
existing kind is never widened). Its evidence must be:

- exact accepted states, never enum ordering (`DUnknown`, `Inconsistent`,
  `Diskless` are not Outdated);
- a fence receipt bound to **the current disconnect episode** and the target
  endpoint by an operation identity, not by wall-clock time; a reconnection
  invalidates it;
- **continuing restart inhibition** of the fenced node, held until recovery
  completion is durable;
- a mapping proving the victim incarnation ran on the endpoint that was fenced.

The re-check before each irreversible recovery step requires the peer to be
still disconnected and still inhibited. **"Connected and Secondary" is not
exclusion**: Secondary is a transient role and the peer can be promoted between
the re-check and the write. A later profile may add it only with a durable
rejoin interlock the peer must honour.

In-flight writes at the link loss behave like a power cut at any permitted
write boundary: what the victim saw complete is on the survivor's disk. That
covers the journal; each class of unjournalled write (recovery descriptors,
allocation metadata, lock-handoff ordering) needs its own review.

### The PR lifecycle

PR supplied more than the fence operation: an inventory of registered users,
exclusion that survives software restarts, evidence of a victim key's
absence, prevention of a fenced node simply rebooting into access, boot
succession, rogue-registrant detection, a device-level contract independent of
userspace, and a basis for retirement. Each needs a counterpart:

- **admission** is a snapshot, so a **runtime policy** must freeze or withdraw
  MXFS on any unsupported DRBD transition (disconnect, local disk not
  UpToDate, diskless Primary, suspension, configuration change, forced
  promotion);
- **restart inhibition** replaces the absent key; a newly booted loser must not
  run its fence handler against the survivor from stale state;
- **whole-cluster restart** selects an authoritative winner explicitly and fails
  closed when neither side holds continuing exclusion;
- **retirement** proves the old endpoint is fenced, cannot rejoin under its old
  authority, and that the membership generation has advanced.

### Tie-breaking

A delay on one node is not arbitration: a slow fence, a paused node or a
rebooted loser defeats it. Fencing must be **serialised by an authority
outside both nodes** that grants one winner per episode (an external fence
coordinator, or quorum with an independent third vote). Automatic split-brain
resolution (`after-sb-*` discard policies) is off: a heuristic that discards a
replica can discard acknowledged MXFS writes, so a split stays disconnected
until the authoritative side is selected explicitly.

### Other hazards named

Overlapping cross-node writes that DRBD "resolves" lose one of them, so no
legitimate overlap may exist (sub-block and sector sharing included); cross-node
order comes only from lock handoff; flushes and FUA must reach both backing
disks; a VM snapshot or clone restores old DRBD metadata, tickets and
incarnations together and must be detected or prohibited.

## How the rig realises it

- The fence authority is the hypervisor host: `tools/rig_fence_virsh.sh`,
  reached through one restricted key, serialises fence requests per pair,
  refuses a requester that is itself fenced, powers the target off, and holds
  a restart inhibit that a libvirt hook enforces until the survivor releases
  it.
- DRBD runs `fencing resource-and-stonith` with `tools/mxfs_drbd_fence_peer.sh`
  as its handler, and every `after-sb` policy is `disconnect`.

## Retirement of a clean departure (second and third consult, 2026-10-02)

A cleanly unmounted DRBD node leaves its heartbeat slot RETIRE_PENDING, and on
SCSI that record becomes reusable only once a node proves the departed PR key
absent. A DRBD mount has no key, so nothing ever settled it: no node could
mount twice, and a whole-cluster restart after a clean shutdown was refused.

The consult's position: RETIRE_PENDING written after a durable unmount record
proves **cleanliness**, not **exclusion**. A restored VM snapshot, a cloned
node or a re-promoted old boot can still write, and only external revocation
of the incarnation (a power-off, a resource-level fence, or an externally
enforced promotion permit) excludes it. Demotion to Secondary was rejected as
the exclusion primitive: it is enforced state, not revocation, and a promotion
can land between the check and the slot's reuse.

The decision (the user's, 2026-10-02): **the clean release is the
retirement**, and the resurrection paths the consult names are excluded by
prohibition rather than by revocation. A node of this attachment is never
restored from saved memory or reverted to a snapshot; on the rig the libvirt
hook refuses a restore and a start of an inhibited node, and the rig refuses
to run beside a node that has a snapshot. Records carry an explicit attachment
marker (`MXFS_HB_FEAT_DRBD`), the rule applies only between DRBD incarnations,
and key 0 alone remains UNKNOWN. A stricter profile would need the consult's
external revocation.

## Recovery after a pair outage (2026-10-02)

The ruling above says a whole-cluster restart "selects an authoritative winner
explicitly and fails closed when neither side holds continuing exclusion".
The decision is **startup fencing**: the first mounter after a pair outage has
the fence authority power its peer off and inhibit it, which creates exactly
the continuing exclusion kind 25 certifies, and only then claims the bootstrap
record. The authority's one-grant-per-episode rule is the explicit selection
when both nodes try at once. An operator assertion ("the pair restarted") was
the alternative; it was not taken, because recovery after a power cut would
then need a person and a wrong assertion would be unsafe.
