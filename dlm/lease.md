# Lease Module (libmxfs/lease)

## Purpose
Tracks node liveness via lease renewals. A node is alive if and only if its lease is current. Lease expiry is the sole liveness detection mechanism -- expired lease triggers DLM purge and journal recovery.

## Architecture
Three threads (all at RT-priority):
- **Renew thread**: periodically sends a single UDP multicast heartbeat to the lease multicast group (239.66.83.1:7602). One packet replaces N TCP unicast sends, eliminating head-of-line blocking under DLM traffic congestion.
- **UDP recv thread**: listens for multicast lease heartbeats from other nodes. Validates magic/version/volume UUID and feeds renewals into the lease state machine.
- **Monitor thread**: checks all remote nodes (ACTIVE and JOINING) for lease expiry, transitions ACTIVE/JOINING -> SUSPECT -> DEAD

All three threads run at SCHED_FIFO (lowest RT priority) via `mxfs_pal_thread_create_rt()` to prevent starvation by CFS tasks under heavy I/O.

## Ported From
kernel/mxfs_lease.{c,h} -- delayed_work replaced with PAL threads + sleep loops, ktime_get_ns() replaced with mxfs_pal_time_ms().

## Key Design
- Node lease table: array of mxfs_node_lease (node_id, epoch, timestamps, state)
- State machine: UNKNOWN -> JOINING -> ACTIVE -> SUSPECT -> DEAD (JOINING also monitored for expiry, same as ACTIVE)
- Timestamps stored as milliseconds (PAL time is already ms, no conversion needed)
- Expire callback fired outside the lock to avoid deadlock
- Timing constants (after anti-flapping fix): duration 60000ms, renew 500ms, timeout 600000ms, monitor 2000ms
- Missed renewal counter: SUSPECT requires 150 consecutive misses (MXFS_LEASE_SUSPECT_MISSES), not a single missed check -- avoids false SUSPECT under I/O load. With 2s monitor interval, total time before SUSPECT: ~360s (60s duration + 150*2s missed checks).
- **Membership change cooldown**: mount.c tracks `last_membership_change` timestamp, checked by both `peer_disconnect_cb` (TCP disconnect path) and `lease_expire_cb` (lease timeout path). If a node removal was already processed within 30s (MXFS_MEMBERSHIP_COOLDOWN_MS), further removals from either path are deferred. This breaks the cascading flapping cycle where one TCP disconnect triggers DLM purge + cache invalidation storms that stall TCP on other peers, causing rapid-fire disconnects. The cooldown does NOT prevent TCP reconnection attempts.

### UDP Multicast Heartbeat
- Wire format: `struct mxfs_lease_udp_msg` -- magic (0x4D584C48 "MXLH"), version (1), node_id, volume_uuid[16], lease_duration_ms
- Port: 7602 (MXFS_LEASE_PORT), multicast group: 239.66.83.1 (MXFS_LEASE_MCAST)
- Broadcast mode supported as fallback (SO_BROADCAST to 255.255.255.255)
- Volume UUID filtering prevents cross-filesystem heartbeat interference
- Self-filtering by node_id prevents processing own heartbeats
- Endian: little-endian wire format via mxfs_cpu_to_le32/le16/le64

### Why UDP Instead of TCP
At 16+ nodes, the DLM creates 120 TCP peer connections. Under heavy DLM traffic (lock requests, BASTs, conversions), the TCP send buffers fill up, blocking lease renewal sends. Because lease renewals shared the same TCP connections as DLM messages, congested DLM traffic could delay lease sends past the suspect threshold, causing false node-death declarations and cascading failures.

UDP multicast solves this because:
1. A single multicast send replaces N unicast sends (O(1) vs O(N))
2. Lease traffic is completely decoupled from DLM TCP traffic
3. UDP is connectionless -- no send buffer backpressure from the receiver
4. The small heartbeat packet (36 bytes) is well under the UDP MTU

## Timing Rationale
- Duration:renew ratio = 120:1, giving ~120 renewal opportunities per duration window (500ms renew, 60s duration)
- Suspect threshold with miss counter: 150 consecutive missed monitor checks (2s each) = ~300s of continuous missed renewals after 60s duration window. Total ~360s (6 min) before SUSPECT.
- Dead nodes are detected much faster via TCP disconnect (seconds). The lease timeout is a safety net for the rare case where TCP disconnect is missed.
- The high threshold prevents cascading membership flapping: each false SUSPECT triggers cache flush + lock purge on all nodes, creating an I/O storm that starves renewals on more nodes.
- SUSPECT to DEAD timeout at 600s (10 min) provides ample margin for sustained I/O stalls under heavy concurrent writes
- RT-priority threads prevent scheduler starvation (the primary cause of 90-142s delays)
- Membership change cooldown (30s) in mount.c prevents rapid-fire node removals from the same I/O storm event

### Anti-Flapping Design
Under 4-node concurrent metadata I/O on a single ESXi host, the following cascade was observed:
1. Lease thread starved -> misses renewals -> node marked SUSPECT
2. Membership change -> cache flush + lock purge on all nodes -> I/O storm
3. I/O storm starves lease on more nodes -> more SUSPECT -> cascade until cluster dies
4. 679 missed lease renewals on test4, epoch reached 40+, 3 of 4 nodes crashed

Three-layer defense:
1. **High miss threshold (150)**: 5 minutes of continuous missed renewals before SUSPECT. Dwarfs any observed starvation burst.
2. **Fast renew interval (500ms)**: 120 renewal attempts per duration window instead of 60, giving more chances to succeed under I/O pressure.
3. **Membership change cooldown (30s)**: Covers both peer_disconnect_cb (TCP disconnect, primary trigger) and lease_expire_cb (lease timeout, safety net). A second node cannot be removed within 30s of the first via either path. This breaks the cascade at the membership change level. Does not prevent TCP reconnection attempts.

## Files
- lease.h: ~145 lines -- context struct, UDP wire format, callbacks, public API, timing constants
- lease.c: ~540 lines -- implementation

## Shutdown
`mxfs_lease_stop()` signals all threads:
1. Sets `running = false`
2. Broadcasts `shutdown_cond` condvar -- wakes renew and monitor threads
3. Calls `mxfs_pal_udp_shutdown()` on the UDP socket -- unblocks the recv thread from kernel_recvmsg
4. Joins all three threads (renew, monitor, UDP recv)

`mxfs_lease_destroy()` additionally closes the UDP socket.

Both renew and monitor threads use `mxfs_pal_cond_timedwait()` on `shutdown_cond` instead of `mxfs_pal_sleep_ms()`, allowing instant wakeup on shutdown instead of waiting up to the renewal interval.

## History
- 2026-02-15: Ported from kernel to portable C using PAL
- 2026-02-19: Fixed false SUSPECT under I/O load at 3+ nodes (Bug 29)
  - Added MXFS_LEASE_SUSPECT_MISSES=3 missed renewal counter
  - Monitor resets counter when renewal arrives on time
  - INFO-level log on each transient miss before SUSPECT
- 2026-02-19: Fixed unmount hang -- replaced uninterruptible sleep (msleep) with condvar timed wait in both renew and monitor threads; stop() broadcasts condvar before joining
- 2026-02-19: Fixed lease starvation under heavy I/O at 4+ nodes
  - RT-priority threads via mxfs_pal_thread_create_rt() (sched_set_fifo_low)
  - Timing: renew 5s->1s, duration 30s->60s, timeout 90s->180s->600s, suspect misses 3->6
  - Send budget: 500ms cap prevents blocked TCP send from consuming renewal interval
  - New PAL function mxfs_pal_thread_create_rt() added to pal.h and both PAL implementations
- 2026-02-19: Fixed lease monitor not detecting dead peers (Bug 30)
  - **Root cause 1**: JOINING nodes were never monitored for lease expiry. The monitor
    only checked ACTIVE state for missed renewals and SUSPECT state for timeout. A node
    that was discovered (registered as JOINING) but died before sending its first
    lease renewal would linger in JOINING state forever, never detected as dead.
    Fix: monitor now treats JOINING identically to ACTIVE for missed renewal detection.
  - **Root cause 2**: peer_disconnect_cb (TCP disconnect handler) called remove_node()
    which unregistered the peer from the lease system. This preempted the lease monitor
    from ever detecting the dead node via lease expiry. Since lease renewals are sent
    over TCP, the renew thread's TCP sends to the dead peer would eventually fail,
    triggering peer_disconnect_cb, which removed the node from lease monitoring before
    the 180s timeout could fire. Fix: peer_disconnect_cb now calls purge_node_dlm()
    instead of remove_node(), keeping the node in the lease table so the monitor can
    complete the ACTIVE->SUSPECT->DEAD transition. Only definitive events (graceful
    NODE_LEAVE, lease_expire_cb) unregister from lease.
  - **Why TCP keepalive also failed**: the 1-second lease renewal sends reset the TCP
    keepalive idle timer on every send, preventing keepalive probes from ever firing.
    With small 48-byte renewal messages, the TCP send buffer (128KB+) takes ~45 minutes
    to fill, so TCP send errors were extremely delayed.
- 2026-02-19: Increased lease timeout from 180s to 600s (10 minutes)
  - Under heavy 4-node concurrent write load, lease renewals can be delayed long enough
    to exceed the 180s hard timeout, causing nodes to be falsely declared dead
  - 600s provides sufficient margin for sustained write bursts while still detecting
    genuinely dead nodes within a reasonable timeframe
  - Only MXFS_LEASE_TIMEOUT_DEFAULT_MS changed; duration (60s) and renew interval (1s) unchanged
- 2026-02-20: Switched lease heartbeats from TCP unicast to UDP multicast
  - At 16+ nodes (120 TCP peer connections), DLM traffic congests TCP, blocking lease
    sends and causing false node-death declarations with cascading failures
  - Single UDP multicast packet (port 7602) replaces N TCP unicast sends
  - New UDP recv thread listens for heartbeats from other nodes
  - Removed send_cb/send_cb_data (TCP send callback) from lease context
  - Removed MXFS_MSG_LEASE_RENEW handler from mount.c DLM message handler
  - Removed lease_send_cb() from mount.c
  - Added mxfs_le64_to_cpu/mxfs_cpu_to_le64 to pal.h for wire format
  - Wire format: mxfs_lease_udp_msg with magic 0x4D584C48, version 1, volume UUID filtering
  - mxfs_lease_create() now takes volume_uuid, mcast_addr, lease_port, use_broadcast
  - UDP socket setup follows same pattern as discovery module (multicast join / broadcast)
- 2026-02-22: Fixed lease renewal starvation under heavy metadata I/O (Bug 47)
  - Under 4-node concurrent metadata stress (200 file creates per node in same directory),
    lease renewals delayed 70-87s. With SUSPECT_MISSES=6 and 2s monitor interval, nodes
    went SUSPECT after ~72s (60s duration + 6*2s misses), triggering membership flaps,
    cache purges, 228 duplicate dir entries and 362 lost files.
  - **Root cause**: UDP recv thread was normal CFS priority while renew/monitor were RT.
    Under heavy I/O, the recv thread got starved by block I/O completions and DLM message
    handling, leaving heartbeat packets unprocessed in the kernel socket buffer for 60+ seconds.
    Even though the sending node's RT renew thread sent packets successfully, the receiving
    node's CFS recv thread never processed them before the monitor counted 6 misses.
  - **Fix 1**: Upgraded UDP recv thread to RT priority (mxfs_pal_thread_create_rt).
    All three lease threads (renew, monitor, recv) now run at SCHED_FIFO low priority.
  - **Fix 2**: Increased MXFS_LEASE_SUSPECT_MISSES from 6 to 60 as defense-in-depth.
    Total time before SUSPECT: ~180s (60s duration + 60*2s = 120s of missed monitor checks).
    Exceeds DLM lock timeout (120s) and all observed starvation bursts. Dead node detection:
    SUSPECT at ~3 min, DEAD at 10 min (600s hard timeout unchanged).
- 2026-03-01: Fixed cascading membership flapping under heavy I/O
  - **Problem**: Under 4-node concurrent metadata I/O on a single ESXi host, lease heartbeat
    starvation causes cascading membership flapping. Missed renewals -> SUSPECT -> cache flush
    + lock purge -> I/O storm -> more missed renewals on other nodes -> death spiral. 679 missed
    lease renewals on test4, epoch reached 40+, 3 of 4 nodes crashed.
  - **Fix 1**: Increased MXFS_LEASE_SUSPECT_MISSES from 60 to 150. Total time before SUSPECT:
    ~360s (60s duration + 150*2s = 300s of missed monitor checks). Dead nodes are detected via
    TCP disconnect in seconds; lease timeout is a safety net, not primary detection.
  - **Fix 2**: Added membership change cooldown (MXFS_MEMBERSHIP_COOLDOWN_MS = 30s) in mount.c
    lease_expire_cb. If a node was removed within the last 30s, further lease expiry callbacks
    are skipped (logged and deferred). Breaks the cascade at the membership change level.
  - **Fix 3**: Reduced MXFS_LEASE_RENEW_DEFAULT_MS from 1000 to 500. Doubles renewal attempts
    per duration window (120 vs 60), giving the renew thread more chances to succeed under
    I/O pressure. Duration:renew ratio now 120:1.
  - **mount.h**: Added `last_membership_change` field to `struct mxfs_mount`
  - **mount.c**: Added MXFS_MEMBERSHIP_COOLDOWN_MS constant, cooldown logic in lease_expire_cb
- 2026-03-01: Bug 69 fix -- extended membership change cooldown to peer disconnect path
  - **Problem**: The 30s cooldown (Bug 68) only applied to lease_expire_cb, but the 4-node test
    showed 44 epoch changes driven primarily by TCP disconnects (peer read failures), not lease
    expirations (only 1 fired). Under heavy I/O, one node's stall causes DLM TCP timeouts on
    other nodes, triggering peer_disconnect_cb for each one. The DLM purge + cache invalidation
    from handling the first disconnect creates an I/O storm that stalls TCP on more peers,
    cascading into rapid-fire membership changes.
  - **Fix**: Added the same cooldown check to peer_disconnect_cb. Both peer_disconnect_cb and
    lease_expire_cb now check last_membership_change before proceeding. If within the 30s
    cooldown window, the disconnect is logged as a warning and skipped. The node will still be
    caught by lease expiry if it is truly dead (6-minute window). The cooldown does NOT prevent
    TCP reconnection attempts -- the peer subsystem handles reconnection independently after
    the callback returns (peer_connect_force on the send path).
  - peer_disconnect_cb now also stamps last_membership_change when it proceeds, so the cooldown
    is shared between both paths (a peer disconnect suppresses both subsequent disconnects AND
    subsequent lease expiries within the window, and vice versa).
  - **mount.c**: Cooldown check + timestamp update in peer_disconnect_cb, updated comments
  - **mount.h**: Updated last_membership_change comment to reflect both paths
- 2026-07-17 (NET2 §11 step 1, port registry): lease.h now `#include`s the new `include/mxfs/mxfs_ports.h` registry. `MXFS_LEASE_PORT` is redefined as `MXFS_PORT_LEASE_LEGACY` (still numerically 7602 — unchanged, and still dual-used with the CAW BAST UDP port on that legacy mount path) instead of a bare literal, with an explicit "do not unify" comment in the header. The registry also introduces `MXFS_PORT_LEASE_V5` (7603), the canonical port both v5 mount paths pass explicitly rather than reading `MXFS_LEASE_PORT` — the legacy/v5 port split is intentional. No behavior change. This is the only change to lease.h since the entry above (2026-03-01) — all of the DLM/CAW fairness, wedge-chain, and grant-nudge work that landed in the 0.11.x window (see CHANGELOG.md and state.md) is in dlm_caw.c and xfs/xfs_mxfs_dlm.c, not in the lease module; the "~62s disklock heartbeat" and "~10 min UDP lease" death-detection paths documented above (disklock.md) are unchanged in mechanism. Changes: lease.h.
