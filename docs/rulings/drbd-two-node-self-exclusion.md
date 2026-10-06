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
7. **The built-in authority fences nothing at startup.** After both nodes
   crash, the first mount does not need it to: a peer that is Secondary on a
   Connected link proves every earlier incarnation ended (decision 9), and the
   boot program arranges for the peer to be exactly that. Asked anyway (the
   peer Primary), it refuses, and the mount waits for the peer to step down.
8. **The exclusion, not the heartbeat, declares the death.** The disk
   heartbeat is replicated by DRBD, so once the link is StandAlone the peer's
   last beat on this replica is final and the stale window (31 samples, 62 s,
   restarted when DRBD's freeze ends) can only run out; the authority lease it
   outwaits governs writes that can no longer reach this replica. DRBD
   completes every write it received from the peer before it reports the
   connection closed, and that is before it runs the fence handler
   (`drbd_receiver.c` `conn_disconnect` → `drbd_disconnected`). So the
   handler's notice makes the mount ask its witness; a confirmed exclusion
   declares the lock manager's death and is posted to the heartbeat monitor,
   which declares the tracked incarnation dead on its next pass after a
   priority re-read. The fence leg still judges the same evidence before it
   certifies anything, and a posting is bound to the node, the incarnation the
   monitor tracks, and a sequence number, so it can never fire on a later
   incarnation. Without a confirmed exclusion the window decides as before.
9. **Kind 27 (`DRBD_PEER_SECONDARY_V1`): the pair's death certificate.** It
   recovers a pair whose two nodes lost power at once, which the built-in
   authority alone could not. Its judgment (`mxfs_drbd_judge_peer_secondary`)
   is one witness report: this node a working Primary under the attachment's
   configuration, the link exactly Connected, both disks UpToDate, the peer
   Secondary, no inhibit on it. DRBD 8.4's own code then gives:
   - **No incarnation is alive on the peer.** `drbd_open` refuses a Secondary
     every write open, and a Primary cannot demote while anything holds it open
     (`is_valid_state`, `SS_DEVICE_IN_USE`). An MXFS mount holds its device
     open from fill_super to kill_sb. While Connected, a peer's promotion is
     applied to this node's view before the peer can complete it
     (`receive_req_state`), so "Secondary" in the report means the peer was not
     Primary at that instant. `allow_oos`, a load-time parameter, admits only
     read-only opens of a Secondary, and a read-only open cannot write.
   - **Every write of an earlier incarnation is on this disk.** A demotion
     reports the new role only after every request the demoting node sent has
     been acknowledged (`drbd_set_role` waits for `ap_pending_cnt`), and under
     protocol C an acknowledgement means this node's disk completed the write.
     A crashed host's writes are settled by the reconnect resync of its
     activity-log extents before both disks read UpToDate.
   - **The roles are one instant's.** `/proc/drbd` prints the connection, role
     and disk states from one copy of the device's state word (`drbd_proc.c`).

   The certificate covers every victim but this mount's own incarnation. On
   the peer the report shows none alive. On this host a block device has one
   superblock (`get_tree_bdev`), so no earlier MXFS of the device is alive
   while this one mounts, and DRBD holds the backing device exclusively, so
   nothing mounts that beside it. No other host reaches either replica.
   Where a victim's host and boot are recorded (a takeover's bootstrap
   record), one of this host's current boot is refused as everywhere else.
   DRBD records carry no identity block, and all zeros means "not recorded".

   It is a fact about incarnations that have ended, never a continuing fence.
   Nothing re-checks the peer against it, because the peer may be promoted
   the moment after the report and is then a new incarnation, which meets the
   bootstrap term at its peek and admission at its join. Nothing clears the
   peer's swap register under it either, because that could erase a live
   ticket. The emulated compare-and-swap instead sets the dead attachment's
   register aside: a swap that has waited a second on the peer's ticket, its
   own ticket already published, takes a witness report. If the judgment
   holds, the register as read before the report is recorded byte for byte
   and read as idle while the sector still holds those bytes. A new attachment
   of the peer first rewrites its register under a fresh random nonce, which
   ends the setting aside, and its doorway reads the published ticket and
   takes a larger one. A register that does not validate (a sector torn by the
   power cut) reads as busy, never idle, and is cleared or set aside only on
   the same evidence.

   Kind 27 is accepted for the startup fence, for every victim's certificate,
   and for a bootstrap takeover's old owner, so it is valid in both record
   families. If the link is lost after the report, the tie-break decides as
   for any loss. The winner's replica, which holds whatever the recovery wrote,
   is the one the loser resyncs from before it can be promoted. The loser's
   I/O stays frozen, so nothing it wrote reaches either disk.

   The boot program provides liveness only. Two nodes that promote together
   leave neither able to prove the other Secondary. So, Connected, participant
   1 promotes only once participant 0 reports over ssh that it has MXFS mounted,
   or that its boot program has not been running for 30 s. A refused mount
   steps down to Secondary and is retried with a doubling backoff. The module
   refuses an unsafe mount whatever order the nodes take.

## What it does not cover

- **Participant 0 dying.** Participant 1 cannot tell that from a cut link, so
  it freezes, restarts, and stays out until participant 0 returns. This is
  the same outcome as PVE without a QDevice and as `auto_tie_breaker`. The
  log line says what to do: restore the peer, or configure a node fence.
- **Administrative bypass.** `drbdadm primary --force`, `resume-io`, clearing
  Outdated, or mounting the device outside `mxfs-drbd@` defeat the argument;
  the guide forbids them. So does writing a backing device while DRBD is
  down, which no replica state can reveal.
- **Storage that acknowledges a flush it has not made durable.** Kind 27, like
  every replay, takes "UpToDate/UpToDate after the resync" to mean both
  replicas hold DRBD's current data. A disk that loses acknowledged writes at
  a power cut breaks that, on any attachment.
- **Whole-host fencing.** This excludes the loser from the replica and the
  lock manager. It does not stop the loser's other services; the restart does
  that when MXFS was mounted.
- **Restoring a node from saved memory or a snapshot**, as in the original
  ruling.
