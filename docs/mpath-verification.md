# What "verified" means for the mpath attachment

A configuration on the `mpath` attachment (`<nodes>/<class>/<method>/mpath`) is
released only when everything in this document has passed on the build being
released. Passing the ordinary suite on a multipath map with every path healthy
proves that MXFS works *through* dm-multipath. It does not prove multipath, whose
whole purpose is what happens when a path is lost. A site that is told `mpath`
works will pull a cable on day one; this is the list of things that must have
been done to them first.

The three must-haves order every verdict below: no corruption, no node or host
crash or hang, then pace.

## 1. The topology under test

A path is only a path if it can fail alone.

- **T1. One NIC, one network and one target portal per path.** Every node has a
  storage NIC per path, each on its own layer-2 network and subnet, each
  reaching its own portal of the target. Two portals reached over one NIC are
  one path with two names and verify nothing here.
- **T2. The storage networks are not the cluster network.** Lock traffic
  (`net/mesh`), discovery and the harness's own control channel ride a separate
  NIC, so that removing a storage path removes exactly that and a result cannot
  be confused with a cluster partition.
- **T3. The map is assembled by multipathd** from the paths the node logged in
  on, and the filesystem is mounted on the map, never on a path device.
- **T4. The settings under test are written down and are the ones a site is
  told to use.** They decide every outcome below, so they are part of the
  claim: `tools/mpath_settings.sh` is the single source for the multipath and
  iSCSI initiator settings the rig applies, and the release ships the same
  text as its recommended configuration. A site running other settings is
  outside what was verified.

**The one rule the settings must satisfy:** the longest time a node's I/O can
stall when a path is lost (path-failure detection, plus the transport's
recovery timeout, plus multipath's switch) must be well under MXFS's death
window, the time after which peers declare a silent node dead and fence it.
A stall longer than that turns a survivable path loss into a fenced node.
The harness measures the stall and fails a row on it; it is not assumed.

What the rig cannot provide, and what is therefore **not** claimed: two
independent *targets* or storage controllers (both portals are one target on
one host), Fibre Channel or SAS transports, and more than two paths.

## 2. The baseline

- **B1.** The full suite (`tests/suite/manifest`, every row that applies) passes
  on the map, as for any attachment.
- **B2.** The run's own log records that every node's mount sat on a multipath
  map with at least two active paths at prep and at the end of the board
  (`run.sh`), and a board that ends otherwise fails.

## 3. Path-fault rows

Every row below runs under load on **every** node: fsynced file writes whose
content is checksummed, metadata churn (create, rename, unlink), and a
cross-node workload in shared directories and shared files, so the lock manager
is busy when the fault lands. A fault is injected from outside the node, at the
link (the hypervisor's `domif-setlink` here; a switch port or cable on
hardware), so the node sees what it would see in production.

Every row requires all of these unless it says otherwise:

- no I/O error returned to any application on any node;
- no node shut down, withdrawn, fenced or declared dead; membership stays at N;
- the measured I/O stall on the faulted node is under the bound in section 1;
- afterwards, every acknowledged file reads back with its checksum from a node
  other than the one that wrote it, and a cold `chk_mxfs` is clean;
- no kernel BUG, oops, hung task or lockdep report on any node or on the host.

| row | fault | what it proves beyond the common requirements |
|---|---|---|
| **F1 failover** | one path down on one node | I/O moves to the other path |
| **F2 path recovery and failback usability** | restore it; once multipathd reports it active again, take the *other* path down | the returned path actually carries I/O, and the node's reservation key is honoured on it — a path that came back unregistered would be refused here |
| **F3 fabric loss** | one whole storage network down (that path on every node at once), restore, then the other network | the common production failure: a switch or fabric dies and every node fails over together |
| **F4 flap** | one path down and up repeatedly, faster than the path checker settles | no error, no fence and no leak from repeated failover and reinstatement |
| **F5 fence while degraded** | node A is on one path; node B is killed | A fences B, replays B's journal and loses nothing, through its one remaining path |
| **F6 fenced node's dead path returns** | node B has one path down, then is frozen and fenced by its peers; its path is restored; B is thawed | B is refused on **both** paths, including the one that was down when the fence was issued: no write of B's reaches the platter after the fence, and B stops rather than hanging |
| **F7 all paths lost** | every path down on one node for longer than the death window, then restored | containment: that node is fenced and stops; the others continue; whatever the node had queued is refused when the paths return; after a remount it rejoins |
| **F8 mount and unmount while degraded** | mount with one path down; restore; unmount with a different path down | a node can join and leave on one path, uses the second when it appears, and leaves no registration behind on a path that was down at unmount |
| **F9 lock command applied, answer lost** (`disk/caw`) | on one node, the target's replies on one path are dropped while the node's commands still arrive, under lock traffic, until the path fails; the path is restored and the same is done on the other path; then, with both paths up, the node is told to treat the answers of its next 40 applied lock swaps as lost | the deliberate form of the hazard described below: a COMPARE AND WRITE that the target applied and the node never heard about is sent again. The dropped replies are the real fault and catch whatever command is in flight; measured, that is the slot read which precedes every swap, not the swap. So the row also puts the lost answer exactly where the fault would have to (a test-only module parameter): the swap is applied on the platter the peers are using, reported to the retry as a transport error, and sent again. The row counts the resends that met their own write and fails if there were none, and fails unless every injected loss ended as either "met its own write" or "a peer had written since". Both paths are muted in turn because the lock commands travel on one path at a time and the row does not assume which |
| **F10 a peer withdraws** | a node shuts its filesystem down and unmounts; then the same with every survivor on one path | the others recover a node that left without being killed, on two paths and on one, and it joins again. Each recovery must be certified: by a PREEMPT AND ABORT naming the withdrawn node's registration when its key is still on the target (what the unmount of a shut-down filesystem leaves, as measured), or, when the key is already gone and one node survives, by a witnessed reset of the logical unit, which that node may issue only as the sole registrant. The reset's own admission on a key registered once per path is measured by `tests/lu_reset_admit_gate.sh` and `tests/lu_reset_fence.sh` on the `mpath` attachment |

**F2 is path reinstatement, not automatic failback.** With the settings under
test (`failback manual`) multipath keeps I/O where it is when a path returns.
F2 proves the sequence that matters to a site: a failed path returns, becomes
usable, and carries the I/O when the path that survived fails in turn. It does
not test multipath moving I/O back to a preferred path group on its own
(`failback immediate` with path priorities, as on an ALUA array): the rig's two
paths have equal priority, so there is no preferred group to fail back to, and
that behaviour is not claimed.

**The stall is measured, not assumed.** For every fault the harness records
T0, when the link was taken down; T1, the last operation that completed before
the stall; and T2, the first that completed after it. The stall is T2 - T1, per
node and per fault, and every value is kept in the row's evidence so the
distribution across runs is regression data. The bound in section 1 is the
verdict; the expected figure from the settings is only a prediction.

F5-F8 and F10 exist because fencing is per path. A SCSI persistent reservation is held
per initiator-target nexus, and a multipathed node has one nexus per path. Every
way a path can be absent at the moment a registration is made, preempted or
retired is a way for the fence to have a hole in it.

**How a node's registrations follow its paths.** MXFS registers its key on each
path separately. At mount, one path that answers is enough. A path that was
absent then (down, or not yet logged in) is registered when it appears, by the
node's reservation worker, and only while the node still holds its authority
lease. That is the one registration made after a mount, so it is the one that
could follow a fence, and SCSI has no command that registers one nexus only if
another still holds the key. So the worker reads the key table first and
registers nothing if the key is gone; after registering it reads the table
again, and unless the key is still held by another of the node's paths (a
fence removes it from all of them at once) it unregisters the path immediately
and the node treats itself as fenced. At unmount a path that cannot be reached
is retired from one that can: PREEMPT naming the node's own key removes it
from every other nexus, and the unmount is complete only when the key table no
longer shows the key.

Two things this does not close, stated so they are not assumed:

- Between a returned path being put back in the map by multipathd and the
  worker registering it (the worker looks twice a second), a write routed to
  that path is refused by the reservation, which multipath does not treat as
  a path failure. Under the settings of T4 I/O moves to a returned path only
  when the path in use fails, so this needs a second path failure inside that
  half second; the node then stops, without corrupting anything.
- If a node is fenced between the worker's first read and its REGISTER (it
  would have to be stalled there for longer than the death window, or be
  fenced while still heartbeating), the key is back on the late path until
  the second read undoes it, a few milliseconds. A write of that node already
  queued below MXFS could be delivered down that path in that interval.

**The sole registrant, on more than one path.** A survivor that must recover a
node whose key is already absent has nothing to preempt, and proves the dead
node's accepted writes are gone with a LOGICAL UNIT RESET. It may issue one
only when it is the only registrant, because the reset ends every initiator's
in-flight work on the unit. With one registration per path, "only registrant"
is established per registration: a RESERVE matching the reservation already in
force changes nothing and is answered GOOD only by a nexus that holds the key,
so one sent down each path counts the registrations that are this node's, and
the count must equal the number the target lists. A registration on a path
that is down cannot be asked. When exactly one path answers, the node removes
its key from every other nexus (PREEMPT of its own key, as at unmount) and
proceeds as a single-path node; the path is registered again when it returns,
under the late-registration check and with the first of the two residuals
above.
The reset is sent through one path's session, chosen among the paths of the
one multipath map that are logged in; it ends this node's own in-flight
commands on every path, and the node does not replay until a write issued
after the reset has landed inside its authority lease.

The node's key is not handed to multipathd (its `reservation_key` feature
registers a returning path by itself): that registration knows nothing of the
authority lease and is never checked afterwards.

**`disk/caw` adds one hazard to every row above.** A COMPARE AND WRITE that was
in flight when its path died has an unknown outcome: the target may have applied
it before the path failed. MXFS sends its lock commands down one path of the
map itself (a SCSI command of this kind cannot be carried through the
multipath device), so dm-multipath never resends one; the lock manager does,
down a surviving path, and a command that had already succeeded then reports
MISCOMPARE against its own write. The lock manager has to recognise its own
completed swap and neither lose the lock nor grant it twice. So on `disk/caw` the load in every row
includes a mutual-exclusion witness across nodes, and a double grant or a lost
lock is a failure of that row. Random timing reaches that window only
sometimes; F9 reaches it on purpose.

## 4. Where it must pass

- **Every node count and both lock managers the release names**: F1-F10 are
  suite rows on the `mpath` columns, so a configuration's board cannot be green
  without them.
- **Per platform.** The multipath stack is the platform's (multipath-tools,
  the initiator, the kernel's dm-multipath), and its defaults differ between
  distributions. A platform is listed for `mpath` only when the packaged build
  has passed F1, F2 and F6 on that platform's own nodes, on two paths. A
  platform where that has not run is listed for `direct` only.

## 5. What a release then claims

Exactly this, and the README says it in these terms: the node counts, lock
managers, platforms and kernels on which sections 2-4 passed; iSCSI; two paths
on separate networks to one target; the settings of T4. It names what was not
tested (a second target or controller, FC/SAS, more than two paths, other
settings) rather than leaving it to be assumed.
