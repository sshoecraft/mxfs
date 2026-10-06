# DRBD pair without a node fence: the built-in two-node exclusion

The DRBD attachment (`2/net/mesh/drbd`, `docs/rulings/drbd-dual-primary-attachment.md`)
was designed around a fence authority outside both nodes that powers the loser
off. Two Proxmox hosts with no IPMI, no PDU and no third machine have no such
authority. The owner's requirement for that case: fencing is on by default and
needs no hardware; where safe automatic recovery is impossible, MXFS says so
plainly and never proceeds unsafely; a node fence (IPMI, PDU, a hypervisor)
replaces the default through `/etc/mxfs/drbd-fence.conf`.

## What established systems do (primary sources, 2026-10-05)

- **Proxmox VE HA** self-fences with `watchdog-mux` (client timeout 60 s, device
  10 s, softdog by default) and requires three votes. A two-node cluster
  without a QDevice does not recover from a peer loss.
- **corosync `auto_tie_breaker`**: the side holding the lowest node id stays
  quorate; no takeover when that node is the one that died. `two_node` leaves
  both sides quorate in a split.
- **OCFS2** (`fs/ocfs2/cluster/quorum.c`): in an even split the half holding
  the lowest node number survives and the other half `emergency_restart()`s.
  It tells a dead node from a split by the shared disk heartbeat, which DRBD
  does not provide (the heartbeat splits with the link).
- **SBD**: diskless mode is unsupported on two nodes without a QDevice; an SBD
  disk must not be on DRBD.
- **LINBIT**: dual-primary requires `resource-and-stonith`; "the fundamental
  problem with 2-node clusters is that in the moment they lose connectivity
  there are two partitions and neither partition has quorum."
- **DRBD's handler contract** (`drbd_nl.c conn_try_outdate_peer`): under
  `resource-and-stonith` I/O is frozen until the handler answers; 7 or 4 mark
  the peer Outdated and resume; anything else leaves I/O frozen.

No surveyed system recovers automatically from the loss of a peer with two
nodes, no fence hardware and no third vote. Neither does this design.

## The decision

1. **One fixed tie-break, never mixed with another rule.** Participant 0 (the
   endpoint with the lower DRBD IPv4 address, the module's own CAS enrollment
   rule) is the only endpoint that can win an uncoordinated split. A consult
   showed that mixing a quorum rule with a local fallback can elect both sides
   (one side sees a new quorate view, the other times out on an old one); no
   settle timeout fixes that.
2. **The exception is positive evidence, not time.** Participant 1 may carry on
   when the peer answers over authenticated ssh (a Proxmox cluster's root key
   trust) that it holds no live MXFS superblock (no mount, module refcount 0)
   and its DRBD is not Primary. A peer in that state cannot be the winner of a
   split, because DRBD runs the handler only on a Primary. Without it, a planned
   restart of participant 0 would also restart participant 1.
3. **The winner excludes the peer before DRBD resumes I/O:** nftables drops the
   DRBD port and MXFS's ports to and from the peer's address (the replica and
   the lock manager, never corosync or ssh); a durable inhibit and an EXCLUDED
   receipt are fsynced on the root filesystem; then exit 7, then StandAlone.
   The isolation is re-applied at boot by `mxfs-drbd-guard` before DRBD can
   reconnect, so the exclusion survives a restart of the winner.
4. **The loser exits 1:** DRBD keeps its I/O frozen and nothing it holds
   reaches a disk. It logs why, and restarts the host if MXFS is mounted on the
   resource (the only way back in). After the restart nothing promotes or
   mounts it until it is Connected with both disks UpToDate, so there is no
   reset loop.
5. **Release is positive evidence only:** the same ssh answer as in 2. Never
   elapsed time: a softdog reset deadline is not proof of a reset, and a
   wedged old incarnation that resumed after a reconnect would bring stale
   caches and stale lock state back.
6. **A new proof kind, 26 (`DRBD_REPLICA_EXCLUDED_V1`).** It proves the old
   incarnation can no longer reach this replica or this lock manager, not
   that the peer is off. It is never accepted as kind 25, is minted only into
   recovery descriptors, and a bootstrap takeover (whose record any later
   mounter reads, on either replica) still requires a node fence.
7. **Startup fencing after a pair outage is refused** by the built-in
   authority: it cannot prove a live, connected peer's earlier incarnation
   gone. A clean shutdown of both nodes needs no startup fence; a simultaneous
   crash of both does, and then needs a node fence or an operator.

## What it does not cover

- **Participant 0 dying.** Participant 1 cannot tell that from a cut link, so
  it freezes, restarts, and stays out until participant 0 returns. This is
  the same outcome as PVE without a QDevice and as `auto_tie_breaker`. The
  log line says what to do: restore the peer, or configure a node fence.
- **Administrative bypass.** `drbdadm primary --force`, `resume-io`, clearing
  Outdated, or mounting the device outside `mxfs-drbd@` defeat the argument;
  the guide forbids them.
- **Whole-host fencing.** This excludes the loser from the replica and the
  lock manager. It does not stop the loser's other services; the restart does
  that when MXFS was mounted.
- **Restoring a node from saved memory or a snapshot**, as in the original
  ruling.
