## Recommendation

Build a new network transport, conceptually **NET2**, with:

1. A **bounded-degree routed overlay** instead of a TCP full mesh.
2. **Many hash-partitioned lock shards**, each replicated across three nodes, instead of arbitrary single-node mastership.
3. An end-to-end **reliable midcomms protocol** independent of individual overlay connections.
4. A separate, prioritized **membership and fencing plane**.
5. When CAW is usable, an optional **CAW delegation/envelope mode** that amortizes disk operations while keeping disk fencing authoritative.

NET2 should replace the internals of the existing TCP fallback or be negotiated as a new protocol version. It must still obey the mount-time transport selection rule; there must be no live CAW↔NET2 switching.

The most important safety rule is:

> Loss of connectivity, quorum, leader state, or membership certainty must stop new grants. It must never be converted directly into lock revocation.

A holder can be bypassed only after it has either completed the drain-and-release sequence or has been fenced from all shared-storage access and recovery has completed.

---

# 1. Connection topology

## Preferred topology: bounded-degree routed overlay

Have each live node maintain connections to approximately `O(log N)` overlay neighbors rather than every peer. For 64 nodes, a practical target is 6–10 neighbors per node, selected using a deterministic ring/expander arrangement based on:

```text
{cluster_uuid, membership_epoch, heartbeat_slot, node_incarnation}
```

Messages carry source and destination identities and are routed over the overlay. Maintain at least two preferably node-disjoint next hops for control and lock traffic.

Properties:

- Approximately `O(N log N)` cluster connections rather than `O(N²)`.
- No permanently distinguished relay nodes.
- A failed link can be bypassed without destroying the logical source/destination session.
- Typical path length is two to four hops at the 64-node limit.
- Neighbor links can use TCP or another reliable byte stream, but **link reliability is not the DLM reliability boundary**. End-to-end NET2 sessions are.

Use separate bounded queues and priorities:

1. fencing/membership,
2. BAST/revoke and RELEASE,
3. GRANT/acquire,
4. ordinary discovery and statistics.

A bulk acquire stream must not queue behind or block lease renewals, BASTs, or completed releases.

### Why not the alternatives?

### Relay tree or spanning tree

A tree gives `O(N)` connections, but:

- an upper-level relay becomes a congestion and failure concentration point;
- relay failure partitions a subtree until reconvergence;
- reconvergence creates ambiguity about whether a message was delivered;
- lock traffic near the root can recreate the current bottleneck.

A redundant tree could be used as the physical routing implementation, but it still needs end-to-end retransmission, duplicate suppression, and at least two independent paths.

### Small fixed coordinator set

A fixed set of three to seven coordinators is reasonable for the **low-rate membership control plane**, but not for all lock traffic. It moves the scaling wall from TCP peer sockets to coordinator CPU, queues, and NICs.

### Gossip

Gossip is useful for discovery and suspicion dissemination. It is not sufficient for:

- ordered lock state transitions;
- proving that all PR holders have released;
- exactly-once processing of a RELEASE;
- establishing a single current membership epoch.

Do not use gossip as the authority for lock ownership.

### Direct client-to-shard-master connections

This is simpler and may work initially, but clients touching resources across all shards will eventually connect to most nodes, recreating a near-full mesh. Routing over a bounded-degree fabric gives a hard connection bound.

---

# 2. Lock mastership and hot resources

## Partition the resource directory into many virtual shards

Hash the complete `resource_id`, not only inode number, into a large virtual shard space, for example 1,024 or 4,096 shards:

```text
shard = H(cluster_uuid, resource_id) mod nr_virtual_shards
```

Map each virtual shard to a three-node replica group selected from the active membership. Each shard has:

- one current leader/sequencer;
- two replicas;
- a monotonically increasing shard term;
- a replicated log of lock state changes;
- resource grant generations and holder state.

Leaders should be distributed across all eligible nodes. Virtual shards allow inexpensive rebalancing without moving the entire resource namespace.

This eliminates one node becoming the master for a disproportionate part of the filesystem. AGs, directories, and inode locks naturally spread across shard leaders.

A small membership service determines the mapping epoch, but it does not process ordinary lock operations.

## Leader migration and rebalancing

Move a shard leader when:

- its lock-operation queue is persistently overloaded;
- it owns too many hot shards;
- network path latency is poor;
- a node is draining or suspected.

Migration must be a logged term transition:

1. stop new grants in the old term;
2. commit the new leader and term to a shard quorum;
3. transfer/reconstruct resource state;
4. resume grants with the new term.

Messages from old terms are rejected. Migration is an optimization, not a way to resolve an uncertain old holder.

## The unavoidable hot-resource limit

A resource with conflicting EX operations is inherently serial. No topology can safely make two conflicting EX grants execute concurrently.

Therefore partitioned mastery solves:

- concentration of many unrelated resources on one master;
- per-node imbalance;
- global queueing behind an overloaded master.

It does **not** eliminate serialization of one genuinely hot directory or AG lock. That requires reducing the number of conflicting transitions.

## PR fan-out and delegation

For read-mostly resources, the shard leader may grant PR to multiple nodes concurrently and maintain the PR-holder set. An EX request performs:

1. Commit an EX-pending/revocation state.
2. Send BAST/revoke to every PR holder.
3. Each holder drains and flushes as required.
4. Each holder sends a generation-qualified RELEASE.
5. Commit removal of every PR holder.
6. Grant EX only after the holder set is empty.

For repeatedly accessed read-mostly resources, use renewable PR delegations. A node can satisfy repeated local PR acquisitions under a cached delegation without another network operation.

Hierarchical PR fan-out through regional agents is possible, but should be a later optimization. An agent returning a PR delegation must first prove that every child has drained and released. Agent failure otherwise expands the recovery and fencing domain.

## Hot EX/PR transitions

For shared parent directories and AG-0, useful optimizations include:

- retaining existing cached locks longer;
- batching compatible requests;
- coalescing multiple waiters from the same node;
- speculative BAST notification when an incompatible request is queued;
- moving the shard leader close to the dominant traffic source;
- finer resource granularity only where XFS locking semantics prove it safe.

Do not split one logical lock merely to improve throughput. If the protected metadata is not independently coherent, that would violate invariant 1.

---

# 3. Reliable delivery and ordering

The current grant-generation cookies are necessary but not sufficient. NET2 needs a real end-to-end reliable-midcomms layer.

## Logical session identity

A session should be identified by something like:

```text
{
    cluster_uuid,
    membership_epoch,
    source_slot,
    source_incarnation,
    destination_slot,
    destination_incarnation
}
```

A heartbeat slot alone is insufficient because slot reuse creates ABA problems.

Each direction maintains:

- monotonically increasing sequence numbers;
- cumulative ACK plus optional selective ACK;
- retransmit queues;
- receive windows;
- duplicate suppression;
- reconnect/resume state;
- bounded flow control.

ACKs must be generated by the logical destination, not by an intermediate relay. A message may be retransmitted along a different overlay path.

## Operation identity

Every lock operation also carries:

```text
{
    resource_id,
    mapping_epoch,
    shard_term,
    request_id,
    grant_generation,
    requester_incarnation
}
```

The existing grant-generation cookie should become part of this larger fencing token.

Receive-side processing must be idempotent:

- duplicate ACQUIRE returns the same pending or granted result;
- duplicate GRANT reaffirms the same generation;
- stale RELEASE is ignored;
- duplicate RELEASE returns its previous result;
- a message from an old membership epoch or shard term cannot mutate current state.

## Replication and ACK rules

For a replicated shard:

- Do not acknowledge a new GRANT as authoritative until the grant is committed to a shard quorum.
- Do not acknowledge a RELEASE as processed until removal of that generation is committed.
- A new leader reconstructs granted holders, pending revocations, and request deduplication state from the replicated log.
- Leader failure must not cause the new leader to assume that grants or releases were never delivered.

A completed drain followed by a lost RELEASE is safe: the old holder retransmits, and the new waiter remains blocked. It is a liveness failure, not a coherence failure.

A lost GRANT is also safe: replicated state says the lock belongs to that requester, and a retry reaffirms the same generation rather than granting it elsewhere.

## Exact release sequence

The required order must be explicit:

```text
receive BAST/revoke
    -> stop new local users
    -> drain_meta_buffers
    -> drain_alloc_buflist
    -> drain_inode_buffers
    -> blkdev_flush
    -> send RELEASE(resource, generation)
    -> wait for RELEASE_ACK
```

The shard leader may grant an incompatible mode only after the RELEASE has been accepted and committed.

Never send RELEASE before `blkdev_flush` finishes. Never infer RELEASE from a socket disconnect.

Prioritize BAST, RELEASE, RELEASE_ACK, and retransmissions over new acquisitions. Congestion should increase acquisition latency, not prevent coherence completion.

---

# 4. Membership, liveness, and false-death handling

## UDP multicast alone is not enough

UDP multicast remains useful for:

- discovery;
- fast heartbeat hints;
- BAST hints;
- suspicion dissemination.

It is not sufficient as the authoritative membership mechanism because packet loss, switch multicast behavior, queue starvation, or asymmetric partitions can look like death.

Use a dedicated membership plane with:

- separate PAL sockets;
- reserved receive and transmit queues;
- a dedicated worker or scheduling class;
- no shared backpressure with lock traffic;
- direct unicast probes as a fallback to multicast;
- multiple independent observers before declaring suspicion;
- node incarnations to distinguish restart from delayed packets.

A small three- or five-voter consensus group can publish membership epochs because this is low-rate control traffic. It must not carry normal lock requests.

## SUSPECT is not DEAD

On missed liveness:

1. Mark the node SUSPECT.
2. Stop or restrict new grants that would conflict with locks it may hold.
3. Probe over independent network paths.
4. Allow reconnect/resume using the same incarnation during the grace period.
5. Declare it removable only after fencing is confirmed.

The current 15-second deferred-death behavior is directionally correct, but the transition from suspect to dead must be tied to fencing, not just time.

## Fencing is mandatory

No purely network protocol can safely distinguish a dead node from a partitioned node that can still write the shared LUN. Therefore:

> NET2 may not revoke an unreachable holder and grant its lock elsewhere until that holder has been fenced from the shared storage.

Acceptable fencing mechanisms include:

- SCSI persistent reservations;
- an external storage or power fencing agent;
- a storage-controller access revocation mechanism;
- a watchdog lease whose expiration reliably removes LUN access;
- a proven CAW/disk epoch mechanism, where CAW is reliable enough for fencing.

A timeout by itself is not fencing.

If no fencing mechanism exists, loss of a holder or shard quorum must freeze affected lock resources or the entire filesystem. Availability must be sacrificed for coherence.

## Recovery after holder failure

If a holder crashes during or before drain:

1. Do not treat the missing RELEASE as success.
2. Fence the node from the LUN.
3. Complete required journal/metadata recovery.
4. Invalidate or reconstruct its lock state.
5. Advance the resource generation.
6. Only then issue a new incompatible grant.

This is the failure-path equivalent of the normal drain-before-release contract.

## Network partitions

Only the membership partition with quorum and successful fencing authority may continue. Minority nodes must self-freeze and preferably self-fence when their control-plane lease expires.

A quorum decision without storage fencing is insufficient: the minority may still have LUN access.

---

# 5. CAW/network hybrid

A hybrid is valuable, but there are two distinct versions with different safety and performance properties.

## Safe, simple hybrid: network acceleration around ordinary CAW

Keep every disk slot transition authoritative and use NET2 for:

- immediate BAST delivery;
- owner/request notification;
- cached slot-location information;
- collision/probe hints;
- wakeups instead of polling;
- batching and coalescing.

The disk poll remains a low-rate backup.

This can substantially reduce BAST poll I/O and unnecessary FUA reads, but it cannot produce microsecond grants: every ownership transfer still needs the authoritative CAW operation.

It is the lowest-risk first implementation.

## Higher-performance hybrid: CAW envelope delegation

For larger gains, treat the disk slot as an **envelope delegation** held by a shard leader or delegation service:

1. The shard leader acquires the CAW slot and advances its generation.
2. While it owns that disk envelope, its replicated NET2 shard grants PR/EX sub-ownership to clients.
3. Client-to-client lock transitions happen through NET2 without changing the disk slot.
4. Before releasing the disk envelope:
   - revoke all network grants;
   - wait for every holder’s completed drain and RELEASE;
   - commit the empty-holder state;
   - write any required `dir_epoch`/`last_ex_slot` state;
   - execute the CAW disk release.

This directly preserves invariant 1: the on-disk envelope is never unlocked until all delegated holders have drained and flushed.

The fixed 65,536-slot layout need not grow. Existing fields can represent:

- envelope owner via the existing node bit;
- delegation generation via the existing generation;
- resource identity and directory coherence fields as today.

The network holder set exists in the replicated shard state rather than requiring additional on-disk slots.

### Failure handling for envelope delegation

If the envelope leader fails:

- replicas retain the network holder set and outstanding revocations;
- no replacement leader may steal the disk envelope merely because the old leader is unreachable;
- the old leader must first be fenced;
- the new leader CAWs the slot to a new generation;
- it reissues revokes or performs recovery before making incompatible grants.

If the entire shard replica set loses its holder state, all possible delegated holders must be fenced or brought into a recovery barrier before the slot can be reset. The stale disk envelope alone does not identify all network sub-holders.

### Important limitation

This mode changes the meaning of the slot’s holder from “current data accessor” to “current delegation authority.” It therefore needs:

- an explicit on-disk/protocol feature bit or version;
- updated recovery and diagnostic tools;
- strict rejection by older implementations;
- validation that `dir_epoch` and `last_ex_slot` are checkpointed before envelope release.

Do not silently reinterpret existing slots in a mixed-version cluster.

## When CAW itself is unreliable

The CAW envelope design is not a fallback for hardware on which CAW cannot be trusted. On that hardware, NET2 must use an external fencing mechanism and replicated network state.

Thus the practical product arrangement is:

- **CAW-capable hardware:** CAW plus NET2 notifications initially; optionally CAW envelope delegation later.
- **CAW-unreliable hardware:** pure NET2 plus mandatory external/storage fencing.
- **No reliable fencing available:** refuse unsafe recovery or freeze after ambiguous failure.

---

# Major failure modes and required response

| Failure | Correct response |
|---|---|
| Overlay link failure | Reroute and retransmit end-to-end; do not change lock ownership |
| Relay/node failure | Rebuild overlay; logical sessions resume by incarnation and sequence |
| Shard leader failure | Elect from replicas; old-term messages rejected; preserve holder state |
| Loss of shard quorum | Freeze resources in that shard |
| RELEASE lost | Retransmit; do not grant conflicting mode |
| GRANT lost | Reaffirm same generation; do not grant to another node |
| Holder unreachable | Mark suspect and block conflict; fence before revocation |
| Membership quorum lost | Freeze/self-fence, not “pick a side” locally |
| Control-plane congestion | Reserved queues/workers; never share lock-data backpressure |
| CAW envelope leader failure | Fence leader, recover delegated holders, advance generation |
| Total replica-state loss | Fence all possible holders and recover before resetting locks |
| Slot reuse/node restart | Incarnation and membership epoch prevent ABA |
| Shard remapping during traffic | Term/mapping epoch gate; old mapping cannot mutate state |

---

# Interaction with the existing invariants

- **Invariant 1:** Enforced both on normal network release and CAW envelope release. Disconnect is never an implicit release.
- **Invariant 2:** No additional disk slots are required. Enforce the existing per-mount held/delegated resource cap at or below 65,536.
- **Invariant 3:** Keep heartbeat-slot identity and 64-bit node masks. Add node incarnation and membership epoch alongside the slot identity.
- **Invariant 4:** Implement sockets, timers, persistence, threads, multicast, fencing, and storage operations through new or existing `mxfs_pal_*` interfaces.
- **Invariant 5:** NET2 version/mode is negotiated only while forming or joining. Joining nodes adopt the established transport and feature set. No runtime transport switching.
- **Invariant 6:** Copy GFS2/OCFS2’s drain/revoke/recovery safety model, but not their connection topology or single-master transport architecture.

---

# Why “just use corosync/kernel DLM” is not the answer

A standard DLM may supply mature lock semantics, but it does not automatically solve MXFS’s specific constraints:

- kernel APIs outside `mxfs_pal_*` violate the dual kernel/user-mode build requirement;
- conventional per-resource mastery still serializes a hot resource;
- common transports use direct peer connectivity or centralized communication paths that can reproduce the scaling wall;
- membership does not by itself fence a partitioned node from the shared LUN;
- existing MXFS slot generations, directory epochs, heartbeat-slot identity, and mount-time transport negotiation must be preserved;
- no external DLM can weaken MXFS’s exact drain and flush pipeline.

Parts of those systems can be studied for revoke/recovery semantics, but their transport cannot simply be dropped in.

## Implementation order

A sensible staged implementation is:

1. Add reliable end-to-end midcomms, incarnations, ACK/resend/dedup, and priority queues.
2. Separate membership/fencing from lock traffic.
3. Replace the full mesh with the bounded-degree overlay.
4. Add virtual shards and three-way replicated shard state.
5. Add PR delegation and hot-shard migration.
6. Use NET2 to eliminate normal CAW BAST polling.
7. Only after recovery is proven, add CAW envelope delegation.

This removes the known false-death and message-loss hazards first, then addresses topology and master concentration, and only afterward takes on the more invasive disk/network delegation optimization.
