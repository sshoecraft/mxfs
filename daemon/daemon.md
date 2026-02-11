# mxfsd — Userspace Daemon

## Overview

mxfsd is the userspace daemon that runs on each node in an MXFS cluster.
All coordination complexity lives here: peer connections, DLM protocol,
lease management, journal recovery coordination, and kernel communication.

## Lifecycle

mxfsd is spawned by the mxfs.ko kernel module during `mount -t mxfs`.
The kernel calls `call_usermodehelper()` with command-line arguments
providing the device path, mountpoint, volume UUID, and optional mount
options (interface, port, multicast/broadcast address).

Startup sequence:
1. Parse `--device`, `--mountpoint`, `--uuid`, and optional `--iface`,
   `--port`, `--broadcast`, `--multicast` from kernel-provided args
2. Parse volume UUID from hex string (or read XFS superblock as fallback)
3. Load/generate persistent node UUID from `/etc/mxfs/node.uuid`
4. Build config from args (no config file)
5. Init syslog logging
6. Setup signals (SIGTERM/SIGINT for shutdown, SIGPIPE ignored)
7. Init subsystems (volume, scsi_pr, disklock, dlm, netlink, peer,
   discovery, journal, control socket)
8. Send `MXFS_NL_CMD_DAEMON_READY` via netlink to unblock kernel mount
9. Enter main loop: reconnect peers + usleep(250ms) + check running flag

On `umount`, the kernel sends SIGTERM. The daemon releases its journal
slot, shuts down subsystems in reverse order, and exits.

## Architecture

### Subsystems

- **mxfsd_main** — Kernel-spawned daemon entry point. Launched by
  mxfs.ko via `call_usermodehelper()` with args: `--device <dev>
  --mountpoint <mnt> --uuid <hex>` plus optional `--iface`, `--port`,
  `--multicast`, `--broadcast`. No daemonization (runs as forked process).
  No PID file. No config file mode. No stop/status commands.
  Signal handling: SIGTERM/SIGINT for shutdown, SIGPIPE ignored.
  Subsystem init order: log -> config -> volume -> scsi_pr -> disklock ->
  dlm -> netlink -> peer -> discovery -> journal. Reverse-order shutdown
  with init tracking for partial failure cleanup. After init, sends
  DAEMON_READY netlink message to kernel with PID, node ID, and volume
  UUID. Main loop: reconnect disconnected peers every ~5s, usleep(250ms).
  **Node UUID**: Persistent UUID stored at /etc/mxfs/node.uuid. Generated
  once using /dev/urandom (version 4 UUID), persisted to disk. Node ID
  derived via FNV-1a hash of the 16-byte UUID.
  **Discovery**: Always enabled. UDP multicast (default 239.66.83.1:7601)
  or broadcast. Discovery callback auto-adds peers and initiates TCP
  connections (lower-ID-initiates convention).
  **Three-layer fencing**: On peer disconnect: (1) SCSI PR preempt
  removes dead node's registration key (hardware fence), (2) disklock
  purge clears on-disk lock records, (3) DLM purge clears in-memory
  state. All lock grants are persisted to disk before the grant response
  is sent. Peer disconnect callback wires SCSI fencing + DLM purge +
  journal recovery + netlink notifications + epoch advance.
  **DLM dispatch**: Routes lock requests between kernel (netlink), peer
  daemons (TCP), and local control socket. Uses distributed per-resource
  mastering: each resource hashes (FNV-1a) to a master node from the
  sorted active node list. All nodes maintain the same sorted list so
  they agree on which node masters each resource. When a lock request
  arrives, the node checks if it is the resource master; if so it
  processes locally, otherwise it forwards to the computed master.
  Active node list is rebuilt on peer connect/disconnect and periodically
  in the main loop. Grant callback fires when queued locks are promoted
  — routes grant to local kernel (netlink) or remote peer (TCP).
  Pending request tracking with condition variables for blocking
  control socket clients.
  **Control socket**: Unix domain socket at /var/run/mxfsd.sock for local
  test tools (mxfs_lock). Binary protocol: ctrl_req (cmd, mode, flags,
  resource) / ctrl_resp (status, mode). Lock requests block until
  granted or denied (30s timeout).
- **mxfsd_config** — INI-style config parser handling [node], [peer],
  [volume], [timing], [logging] sections. Multiple [peer] and [volume]
  sections supported. Validates required fields (node id/name). All string
  fields bounded by buffer sizes. Reports parse errors with line numbers.
  (Retained for `mxfsd_config_set_defaults()` — config file loading no
  longer used in kernel-spawned mode.)
- **mxfsd_peer** — TCP connection management to peer daemons. Listener
  socket with SO_REUSEADDR on configurable bind address/port. Accept thread
  reads NODE_JOIN handshake to identify incoming peers; supports dynamic
  peer addition for unknown nodes (enables discovery mode without
  pre-registration). Receive thread uses poll() across all active
  peer sockets, reads length-prefixed messages (header then payload).
  Outgoing connect with DNS resolution fallback. Per-peer send_lock mutex
  for thread-safe writes. Automatic disconnect on read/write errors.
  Message framing via mxfs_dlm_msg_hdr length field.
- **mxfsd_dlm** — The DLM protocol engine. Hash table (FNV-1a) of lock
  entries protected by a pthread rwlock for read-heavy access. Processes
  lock requests checking compatibility against all granted holders on the
  resource. Supports NOQUEUE/TRYLOCK flags for non-blocking attempts.
  Lock release removes the entry and promotes queued waiters. Lock convert
  handles downgrades (always allowed, promotes waiters) and upgrades
  (checks compatibility, queues if blocked as CONVERTING). Node purge
  removes all locks for a dead node and promotes blocked waiters across
  all buckets. Epoch tracking with mutex-protected counter.
  **Distributed mastering**: Maintains a sorted active node list
  (mutex-protected). Each resource maps to a master via
  `FNV-1a(resource) % active_node_count` into the sorted list.
  Deterministic across all nodes since the sorted list is identical.
  `mxfsd_dlm_resource_master()` returns the master for any resource.
  `mxfsd_dlm_update_active_nodes()` replaces the list (sorts on update).
  `mxfsd_dlm_is_resource_master()` checks if the local node masters
  a given resource.
  **Grant callback**: When queued locks are promoted (after release or
  purge), collects promoted lock info while holding the rwlock, then fires
  callbacks outside the lock to avoid holding it during dispatch.
- **mxfsd_netlink** — Raw AF_NETLINK/NETLINK_GENERIC socket (no libnl
  dependency). Resolves "mxfs" genetlink family via CTRL_CMD_GETFAMILY.
  Receive thread dispatches incoming kernel messages through callback.
  NLA attribute helpers for building messages. Sends lock grant/deny,
  cache invalidation, node status, recovery start/done, and daemon ready
  commands. `mxfsd_netlink_send_daemon_ready()` sends PID, node ID, and
  volume UUID to the kernel to unblock `mxfs_fill_super()`.
  Gracefully handles kernel module not loaded (defers family resolution).
- **mxfsd_lease** — Lease-based node liveness with mutex-protected state.
  Renewal thread periodically refreshes local node timestamp. Monitor
  thread checks all remote nodes: transitions ACTIVE->SUSPECT when a
  renewal is missed (elapsed > duration), then SUSPECT->DEAD when timeout
  is exceeded. Fires expire callback outside the lock to allow DLM purge
  and journal recovery. Supports registering nodes, processing remote
  renewals (transitions JOINING/SUSPECT->ACTIVE), and lease validity
  checks. Interruptible sleep (250ms chunks) for clean shutdown.
- **mxfsd_journal** — Journal slot management and recovery coordination.
  Mutex-protected slot array. Each node claims a unique slot on startup.
  On node death: mark_needs_recovery -> begin_recovery -> finish_recovery
  state machine. Handles concurrent recovery attempts (returns -EBUSY).
  Slots are freed after successful recovery.
- **mxfsd_log** — Logging to file and/or syslog. Thread-safe via pthread
  mutex. Supports simultaneous file + syslog output. File output includes
  ISO-8601 timestamps with millisecond precision. Falls back to stderr when
  no outputs are configured. Level filtering via syslog constants
  (LOG_ERR..LOG_DEBUG). Line-buffered file output for timely writes.
- **mxfsd_volume** — Volume state tracking with mutex protection. Reads
  XFS superblock UUID from block devices to derive deterministic volume IDs.
  Supports add, mount/unmount state transitions, and lookup by ID or device
  path. Gracefully handles inaccessible devices at config time (retries
  on mount). Mount node tracking via bitmask.
- **mxfsd_scsi_pr** — SCSI-3 Persistent Reservations for hardware I/O
  fencing. Issues PERSISTENT RESERVE IN/OUT commands via SG_IO ioctl.
  Uses WRITE EXCLUSIVE — REGISTRANTS ONLY (type 5): all registered nodes
  can do I/O, unregistered/preempted nodes are fenced by the storage array.
  Operations: register key (REGISTER_AND_IGNORE for crash-safe re-registration),
  reserve (type 5), preempt (fence dead node), read keys, read reservation,
  unregister (clean shutdown). Full SCSI sense data decoding on errors.
  Thread-safe via mutex. Node registration key = (uint64_t)node_id.
- **mxfsd_disklock** — On-disk lock state persistence. Stores lock grants
  and node heartbeats in `.mxfs/lockstate` on the shared XFS volume.
  Uses O_DIRECT + O_SYNC for sector-aligned atomic I/O (512-byte records).
  File layout: 64 heartbeat slots (32KB) followed by 65536 lock record slots
  (~33MB). Lock slots use FNV-1a hash with linear probing. Static assertions
  verify struct sizes are exactly 512 bytes. Heartbeat writer thread runs
  every 2 seconds. On init, pre-allocates with fallocate() for contiguous
  allocation. Validates magic numbers on existing files. Purge operation
  scans all slots to clear a dead node's records. Read-all operation for
  lock table reconstruction during recovery/failover.

- **mxfsd_discovery** — UDP peer discovery over multicast or broadcast.
  Nodes periodically announce themselves (2-second interval) with a packet
  containing node UUID, node ID, TCP port, volume UUID, volume ID, and
  hostname. Receiver thread listens for announcements; fires a callback
  for each new peer discovered. Tracks already-seen peers to avoid duplicate
  callbacks (6-second expiry). Supports multicast (default 239.66.83.1)
  or broadcast mode. Interface binding via SO_BINDTODEVICE. Discovery port
  7601. Always enabled in kernel-spawned mode.

### Threading Model

- Main thread: signal handling, subsystem lifecycle, peer reconnect
- Peer accept thread: incoming TCP connections (with dynamic peer addition)
- Peer receive thread: reads DLM messages from peers, dispatches via msg callback
- Lease renewal thread: periodic lease renewal with peers
- Lease monitor thread: detects expired peer leases
- Netlink receive thread: messages from kernel module, dispatches via nl callback
- Control socket thread: accepts local tool connections, processes lock/unlock
- Disklock heartbeat thread: periodic heartbeat writes to shared storage
- Discovery sender thread: periodic UDP announcement broadcast
- Discovery receiver thread: listens for peer announcements

### Build

```
make -C daemon
```

Produces the `mxfsd` binary. Installed to `/usr/sbin/mxfsd`.

## Version History

- 0.1.0 — Initial project structure, stub implementations
- 0.1.1 — Implement mxfsd_log: file+syslog output, thread-safe, level filtering
- 0.1.2 — Implement mxfsd_config: INI parser, section handling, defaults
- 0.1.3 — Implement mxfsd_volume: XFS UUID-based volume IDs, state tracking
- 0.1.4 — Implement mxfsd_journal: slot management, recovery state machine
- 0.1.5 — Implement mxfsd_dlm: hash table, lock request/release/convert, node purge, epoch tracking
- 0.1.6 — Implement mxfsd_peer: TCP listener, accept/recv threads, message framing, handshake
- 0.1.7 — Implement mxfsd_lease: renewal/monitor threads, expire callback, suspect/dead transitions
- 0.1.8 — Implement mxfsd_netlink: raw genetlink, family resolution, recv thread, NLA helpers
- 0.2.0 — Implement mxfsd_main: CLI, daemonization, subsystem lifecycle, main loop
- 0.3.0 — Wire DLM message dispatch: peer message routing, netlink lock handling,
  master determination, grant callbacks, control socket, pending request tracking.
  Add mxfs_lock test tool. Cross-node lock contention tested on 2-node cluster.
- 0.3.1 — Replace single-master model with distributed per-resource mastering.
  Each resource hashes to a master node via FNV-1a over the sorted active node
  list. Removed is_master()/get_master_id(); all call sites now use
  mxfsd_dlm_resource_master()/mxfsd_dlm_is_resource_master(). Active node list
  rebuilt on peer connect/disconnect and periodically in the main loop.
- 0.4.0 — Three-layer fencing architecture (VMFS-style):
  Layer 1: SCSI-3 Persistent Reservations (mxfsd_scsi_pr) — hardware I/O fencing
  via SG_IO. WRITE EXCLUSIVE REGISTRANTS ONLY reservation; preempt on node death.
  Layer 2: On-disk lock state (mxfsd_disklock) — lock grants persisted to
  .mxfs/lockstate file with O_DIRECT sector-aligned I/O. Disk heartbeats.
  Survives daemon restarts; enables lock table reconstruction on failover.
  Layer 3: TCP DLM (existing) — fast in-memory lock negotiation.
  All lock grants written to disk before grant response is sent. Peer
  disconnect triggers SCSI preempt -> disk purge -> memory purge -> recovery.
  SCSI PR and disklock are optional — daemon degrades gracefully if the
  device doesn't support SCSI PR or no mount point is available yet.
- 0.5.0 — Config-free device-first startup with UDP peer discovery.
  New device mode: `mxfsd start /dev/sdb1` — no config file needed.
  Persistent node UUID at /etc/mxfs/node.uuid with FNV-1a hash for
  node ID derivation. UDP discovery (mxfsd_discovery) for automatic
  peer detection via multicast (239.66.83.1:7601) or broadcast.
  Discovery callback auto-adds peers and initiates TCP connections.
  Manual peer mode with `--peer host:port` (repeatable, skips discovery).
  New CLI options: --iface/-i, --broadcast/-b, --multicast/-m,
  --peer/-P, --port/-p. Legacy config mode preserved via --config/-c.
  Dynamic peer addition in accept thread — unknown nodes presenting
  valid NODE_JOIN handshake are auto-registered. Active node list now
  scans peer_ctx directly (works for both config and discovery modes).
  Main loop retries connections to dynamically-added peers.
- 0.5.1 — Fix: read XFS superblock UUID (sb_uuid at offset 32) from the
  device and populate discovery announce volume_uuid field. Without this,
  all nodes had all-zero volume UUIDs and would match any peer regardless
  of which XFS volume they serve. Fix: --multicast flag no longer
  incorrectly enables broadcast mode.
- 1.0.0 — Kernel-spawned lifecycle: mxfsd is now launched by mxfs.ko
  during mount via call_usermodehelper(). Removed: standalone CLI
  (start/stop/status), daemonization, PID file, SIGHUP config reload,
  config file mode, manual peer mode. New: --device, --mountpoint, --uuid
  args from kernel. DAEMON_READY netlink message signals kernel that daemon
  is initialized. Mountpoint passed to disklock for immediate disk lock
  persistence. Discovery always enabled. File reduced from 1840 to ~1560
  lines. Added mxfsd_netlink_send_daemon_ready() to mxfsd_netlink.c.
