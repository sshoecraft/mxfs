# DLM Protocol Specification

## Wire Format

All daemon-to-daemon messages are length-prefixed and begin with
`struct mxfs_dlm_msg_hdr`:

```
┌──────────┬──────────┬──────────┬──────────┐
│  magic   │ version  │   type   │  length  │
│  (4B)    │  (2B)    │  (2B)    │  (4B)    │
├──────────┼──────────┼──────────┴──────────┤
│   seq    │  sender  │      target         │
│  (4B)    │  (4B)    │      (4B)           │
├──────────┴──────────┴─────────────────────┤
│                epoch (8B)                 │
├───────────────────────────────────────────┤
│          message-specific payload         │
└───────────────────────────────────────────┘
```

- **magic**: 0x4D584653 ("MXFS")
- **version**: Protocol version (currently 1)
- **type**: One of `mxfs_dlm_msg_type`
- **length**: Total message length including header
- **seq**: Sender's monotonically increasing sequence number
- **sender**: Sender's node ID
- **target**: Target node ID (0 for broadcast-originated messages)
- **epoch**: Sender's current lease epoch

## Message Types

### Lock Operations

**LOCK_REQ** — Request a distributed lock
- Payload: `mxfs_dlm_lock_req` (resource ID, mode, flags)
- Sent to the master node (lowest node ID in cluster)

**LOCK_GRANT** — Lock has been granted
- Payload: `mxfs_dlm_lock_resp` (resource, granted mode, status)
- Sent from master to requester

**LOCK_DENY** — Lock request denied
- Payload: `mxfs_dlm_lock_resp` (resource, status=error code)
- Sent when NOQUEUE flag set and lock incompatible

**LOCK_RELEASE** — Release a held lock
- Payload: `mxfs_dlm_lock_release` (resource ID)
- May trigger grant of queued waiters

**LOCK_CONVERT** — Convert lock mode (upgrade or downgrade)
- Uses LOCK_REQ with MXFS_LKF_CONVERT flag

**LOCK_BAST** — Blocking AST (downgrade request)
- Payload: `mxfs_dlm_bast` (resource, requested mode)
- Sent from master to current holder when a conflicting request arrives
- Holder should downgrade or release within bast_timeout_ms

### Lease Management

**LEASE_RENEW** — Periodic lease renewal
- Payload: `mxfs_dlm_lease_msg` (duration, lock count)
- Sent to all peers at lease_renew_ms interval

**LEASE_ACK** — Acknowledgment of lease renewal
- Payload: `mxfs_dlm_lease_msg`
- Confirms the peer has recorded the renewal

**LEASE_EXPIRE** — Notification that a node's lease has expired
- Payload: `mxfs_dlm_lease_msg`
- Broadcast to all nodes when a peer is declared dead

### Node Membership

**NODE_JOIN** — Node joining the cluster
- Payload: `mxfs_dlm_node_msg` (name, port)
- Triggers handshake and lock table synchronization

**NODE_LEAVE** — Graceful node departure
- Payload: `mxfs_dlm_node_msg`
- Allows orderly lock release before disconnect

**NODE_ALIVE** — Piggybacked on lease renewal for efficiency

### Recovery

**JOURNAL_RECOVER** — Claim responsibility for replaying a dead node's journal
- Payload: `mxfs_dlm_journal_msg` (dead node, journal slot)
- Sent by the node taking over recovery duties

**JOURNAL_DONE** — Journal replay completed
- Payload: `mxfs_dlm_journal_msg`
- Signals that the dead node's resources are safe to reuse

### Cache Coherency

**CACHE_INVAL** — Invalidate cached data for a resource
- Payload: `mxfs_dlm_cache_inval` (resource, byte range)
- Sent when a lock holder has modified data and is releasing

## Lock Mastering

Currently using a single-master model: the node with the lowest ID in the
cluster is the master for all resources. The master maintains the
authoritative lock table. Non-master nodes forward lock requests to the
master and block until receiving a LOCK_GRANT or LOCK_DENY response.

When the master node dies, the next-lowest node ID becomes the new master.
Lock table state must be reconstructed from the surviving nodes' local
knowledge of their own held locks.

Future optimization: per-resource mastering via `hash(resource_id) %
active_node_count` to distribute lock traffic across nodes.

## Node Death Sequence

1. Node B's lease renewals stop arriving at Node A
2. Node A's monitor thread detects B missed renewals
3. After node_timeout_ms, A declares B dead
4. A broadcasts LEASE_EXPIRE for B to all peers
5. A calls `mxfsd_dlm_purge_node(B)` — releases all B's locks
6. A sends JOURNAL_RECOVER claiming B's journal slot
7. A triggers XFS journal replay for B's slot
8. A sends JOURNAL_DONE when replay completes
9. B's resources are now available for reuse
