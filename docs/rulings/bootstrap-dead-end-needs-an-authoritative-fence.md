# The bootstrap dead end needs an authoritative fence, not a PR inference

Design-consult ruling on D-BOOTSTRAP-TAKEOVER-NO-PROOF-LEAVES-VOLUME-UNMOUNTABLE,
following `bootstrap-takeover-closure-and-the-recovery-dead-end.md`.

## The shape

A bootstrap owner that dies mid-term must be fenced before a contender replaces
it. Two cases are measured on the 2-node CAW rig (QNAP TS-453 Pro):

- **Owner stalled, session alive:** the owner's PR key is still on the target,
  the contender's PREEMPT AND ABORT names it, a certificate for that exact
  owner and key is produced and consumed, and the takeover completes. The
  resumed owner's first I/O gets RESERVATION CONFLICT.
- **Owner power-cut:** the target purges the owner's registration with its
  session. Nothing is left for PREEMPT AND ABORT to name, the takeover refuses
  with `-ENOKEY`, and every later mount repeats the refusal. The volume stays
  unmountable until an operator clears the record.

The reservation MXFS holds is WRITE EXCLUSIVE – ALL REGISTRANTS. With the owner
as the sole registrant, the purge releases the reservation as well, so after it
an unregistered nexus could write.

## What was decided

**The refusal is correct and stays.** Once a registration has vanished, SPC-4
has no operation that fences the former nexus: none identifies and aborts its
outstanding commands, and none stops the initiator reconnecting and
registering again. A PR generation change, a snapshot showing the key absent,
or a reservation seen held at two instants is not a fence.

Rejected, with the interleaving that breaks each:

- **Keep a reservation continuously held and treat "key absent" as exclusion.**
  A same-boot owner reconnects, issues REGISTER (always permitted), and the
  SCSI/iSCSI layer retries its queued write before MXFS's own key-loss
  self-fence runs. Continuity also cannot be proved from PR IN snapshots.
- **A shared cluster key.** It collapses the victim and the contender into one
  identity; a returning owner re-registers the same key and regains rights.
- **APTPL as the profile.** It concerns the target losing power, not a session
  loss purging a registration.
- **Resealing the record REFUSED, or clearing it, from the refusal.** Already
  rejected in the earlier ruling: an absent registration does not prove the
  owner is dead.

Sound repairs, in order of preference:

1. **An authoritative external fence backend.** Host power-off through an
   independent control plane (hypervisor, BMC, PDU) with the "off" state
   verified, not merely requested; or target-side initiator revocation that
   terminates sessions, drains or aborts outstanding commands on every path,
   and denies relogin until the cluster readmits the node. The certificate
   records the backend, the operation, its verified completion and the exact
   victim scope (host, boot, epoch, key, initiator ports).
2. **A qualified target profile** in which registrations survive session and
   connection loss for longer than any recovery interval, and a completed
   PREEMPT AND ABORT aborts every covered command on every path. The existing
   exact-key route is then sufficient. This QNAP fails the profile.
3. **Otherwise fail closed** with the operator path — and `chk_mxfs
   --clear-bootstrap` should require the operator to assert or produce a real
   fence, rather than clearing blindly.

Whatever the backend, the returning owner must never re-register and release
queued writes on its own: its write freeze has to sit below every layer that
can retry a write, and it rejoins only as a fresh participant.

## What is still open

Which backend(s) the product provides is a product decision: each one adds
configuration and an external dependency (for Proxmox, its own fencing and
power control are the natural first backend). The consult's required
measurements for any choice: registration lifetime across every loss mode;
outstanding I/O at queue depth fenced at each stage; PREEMPT AND ABORT scope
across paths; stale-owner return at every bootstrap transition with iSCSI and
multipath retries; reservation-type semantics; target failover; crash points
through the whole takeover. The shipping criterion is an observed
linearisation point after which the old owner cannot complete a write.
