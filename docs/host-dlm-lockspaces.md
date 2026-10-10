# One DLM per host, one lockspace per filesystem

How a host mounts more than one MXFS filesystem at once, each shared with a
different set of hosts, on the network transport.  This is the model the
kernel DLM gives GFS2 and OCFS2: the host joins the cluster once, and each
filesystem is a lockspace inside it.

## What MXFS does today

Every mount builds a complete DLM of its own, network included:

- **Its own listener on the shared ports.**  The TCP DLM listens on 7600
  (`MXFS_PORT_DLM`, `include/mxfs/mxfs_ports.h`) and discovery and the lease
  use UDP 7601-7603.  A second mount binds the same ports with `SO_REUSEPORT`
  (`pal/linux/kern.c` `mxfs_pal_tcp_listen` and `mxfs_pal_udp_open`), and
  each listener drops what is not for its volume: the accept loop closes a
  NODE_JOIN whose `volume_id` differs from its own (`dlm/peer.c`), and the UDP
  receive paths filter on the volume UUID.
- **Its own identity.**  The node id is drawn once per mount context
  (`dlm/v5_mount.c`), along with the epoch and, on SCSI, the reservation key.
- **Its own discovery threads**, announcing node UUID, volume UUID and port
  (`docs/discovery.md`).

The port sharing does not demultiplex, it guesses.  Linux gives a new
connection on a `SO_REUSEPORT` port to one listener, chosen by a hash of its
addresses and ports, not by its volume.  With two mounts, a connection meant
for one lands on the other half the time, is closed, and is retried from a new
source port until the hash happens to pick the right one.  A unicast datagram
is worse: it goes to one socket by the same kind of hash, and a peer sending
from a fixed source port always hashes to the same socket, so a mount can
fail to hear a peer for as long as that peer keeps its port.  Multicast and
broadcast reach every socket, so default discovery survives; `peers=` (unicast
discovery and lease) and the TCP mesh do not.

The DRBD tooling assumes one resource per pair: the fence helper's firewall
rules drop the fixed MXFS ports to and from the peer, whatever resource fenced
it, and its rejoin check counts every mxfs mount in the peer's
`/proc/mounts`.

## The design

Two layers, split along what is a fact about a host and what is a fact about
a filesystem.

### Host layer: one per host, in the module

- **One listener per port, and one connection to each peer host**, shared by
  every mount that has that peer in common.  Created with the first mount that
  needs it and gone with the last.
- **One host identity**: a host UUID that survives remounts and reboots, and
  the address the host is reached at.  This is what a peer is: a mount on
  another host is reached through that host.
- **One liveness judgement per peer host.**  Whether pve2 is reachable is the
  same question for every filesystem pve1 shares with it, and gets one
  answer.  When the host layer declares a peer host dead, every lockspace that
  has it as a member hears so at once.
- **Discovery per host**: one announcement listing the volumes this host has
  mounted, not one sender per mount.

### Lockspace layer: one per mounted filesystem

- **Keyed by the volume id** (the FNV-1a of the filesystem UUID that already
  goes into every heartbeat and NODE_JOIN).
- **Joining**: a mount asks the host layer for a lockspace with that id.  The
  host layer tells each connected peer "this host is joining volume X"; a peer
  with X mounted adds the host to X's membership, and a peer without it
  ignores it.  Every lock message carries the volume id, and the receiving host
  hands it straight to that lockspace.  There is no guessing which socket
  holds which volume, because there is one socket.
- **Per filesystem, as now**: locks, grants, masters, ledger pages, the slot
  and journal this host holds on the device, the mount's generation, and
  journal recovery.
- **The device heartbeat stays per filesystem.**  On DRBD and CAW a mount
  proves it may still write a device by landing writes on that device; a
  heartbeat on one device says nothing about another.

### Liveness and fencing

These come apart, and the split is the point of the design:

- **A dead host is dead for every lockspace.**  When the host layer loses a
  peer, each lockspace it was a member of runs recovery for it on its own
  device: replay its journal there, take over what it held there.
  Lockspaces it was never in are not touched.
- **Fencing is of access to a device, and its reach is the fence's own.**  A
  SCSI reservation fences one LUN; a DRBD exclusion fences one resource; a
  power fence or the DRBD helper's host isolation fences the whole host.  A
  host-wide fence must be followed by every lockspace the fenced host is a
  member of, which the host layer's single liveness judgement gives; a
  device-scoped fence must not take down the fenced host's other mounts.
- **A partition between two hosts is a host-layer event.**  If A and B lose
  each other but B and C do not, A and B's shared filesystems resolve it
  between them, and B's filesystems with C carry on as if nothing happened.

## The test: three hosts, three filesystems, overlapping memberships

```
              +------------- sdZ -------------+
              |                               |
    A ------ sdX ------ B ------ sdY ------ C
```

| filesystem | presented to and mounted on |
|---|---|
| `sdZ` | A, B and C |
| `sdX` | A and B only |
| `sdY` | B and C only |

So every pair of hosts shares more than one filesystem except A and C, which
share only Z: A and B share X and Z, B and C share Y and Z.  B mounts all
three.  On the shared-LUN rig that is three pool LUNs, each attached to its
hosts only.  On DRBD, which replicates between two hosts, X and Y are two
resources (X between A and B, Y between B and C) and Z runs on the shared-LUN
rig, so the DRBD run covers steps 1-8 for X and Y with Z absent.  Every mount
runs the network transport.

What each step must show, beyond the usual integrity checks (every fsynced
file intact, a cold check of each filesystem clean, no kernel warning):

1. **Mount.**  Each host has one listener and one connection to each peer it
   shares a filesystem with: A to B and C, B to A and C, C to A and B.
   Memberships: Z {A, B, C}, X {A, B}, Y {B, C}; A never appears in Y and C
   never in X.  Each mount within its normal mount budget, with no rejected
   connection on any host.
2. **Concurrent load** on all seven mounts.  Locks for X travel only between
   A and B, for Y only between B and C, and for Z among all three
   (per-lockspace message counters on every host); the A-C connection carries
   Z only.  Pace on each filesystem within its bound for its member count:
   sharing a host's connection layer costs no filesystem anything measurable.
3. **A dies.**  B recovers A on X; B and C recover A on Z, each within that
   filesystem's recovery budget.  Y on B and on C does not stall: its writes
   continue throughout, with no recovery and no membership change.
4. **C dies.**  The mirror of step 3: Y and Z recover C, X is untouched.
5. **B dies.**  A recovers B on X, C recovers B on Y, and A and C recover B on
   Z; nothing of X reaches C and nothing of Y reaches A.
6. **The A-B link is cut; A-C and B-C are not.**  A and B have lost each
   other, so both filesystems they share must resolve it the same way: on X
   one of them keeps the filesystem and the other withdraws from it, and on Z
   the same one is excluded, since Z's two other members still reach each
   other through C and must agree with X on who is gone.  Y, which A is not
   in, carries on between B and C untouched.  On DRBD the helper's host
   isolation of B by A must not reach B's traffic with C.
7. **The A-C link is cut; A-B and B-C are not.**  A and C share only Z, so Z
   alone resolves it and excludes one of them; X and Y, which do not have
   both A and C as members, carry on untouched.
8. **B unmounts X while Y and Z are under load**, then mounts it again: Y and
   Z are unaffected, and B's connections to A and C are never torn down,
   since Z still needs both.
9. **B unmounts Z** while X and Y are loaded: the A-B and B-C connections
   stay (X and Y need them); the A-C connection, which carries Z only, stays
   for A's and C's own Z mounts.
10. **The last mount on a host goes away**: the host layer's listener and
   connections go with it, and a remount builds them again.

The mount order varies (Z first, Z last, X and Y in both orders), and steps
6 and 7 each run with either side of the cut as the one that keeps the
filesystem.

## Open questions

- **Which host owns a lockspace's master map.**  Today a mount's masters are
  hashed over its own membership; that stays per lockspace, but a peer host
  that leaves one lockspace and stays in another must change the first's map
  without disturbing the second's.
- **Who decides a cut between two hosts that share several filesystems.**
  When A and B lose each other (test step 6), X has only the two of them and
  breaks the tie by its own rule, while Z has C as a third vote.  The two
  must exclude the same host, or B is a member of Z and a fenced stranger on
  X at once.  Either the host layer makes the decision once and every shared
  lockspace follows it, or the lockspace with the most members decides and the
  others take its answer; which, and how a lockspace with no third vote learns
  it, is open.
- **Discovery on the wire.**  An announcement that lists volumes changes the
  discovery packet; a mixed cluster (old per-mount announcer, new per-host)
  needs either a version bit or a flag day.
- **The DRBD fence helper** must key its isolation by peer host and tell every
  resource with that peer, and its rejoin check must ask about the one
  resource, not count mounts.
- **The CAW transport** coordinates through the device itself and has no
  listener to share; whether its UDP nudges move to the host layer is to be
  decided with the rest of the UDP plane.
