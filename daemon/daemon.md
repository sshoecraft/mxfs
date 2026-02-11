# mxfsd — Userspace Daemon

## Overview

mxfsd is the userspace daemon that runs on each node in an MXFS cluster.
All coordination complexity lives here: peer connections, DLM protocol,
lease management, journal recovery coordination, and kernel communication.

## Architecture

### Subsystems

- **mxfsd_main** — CLI (start/stop/status commands) with getopt_long.
  Signal handling (SIGTERM/SIGINT for shutdown, SIGHUP for config reload,
  SIGPIPE ignored). Double-fork daemonization with stdio redirect to
  /dev/null. PID file at /var/run/mxfsd.pid for stop/status. Subsystem
  init order: log -> config -> volume -> dlm -> netlink -> peer -> lease
  -> journal. Reverse-order shutdown with init tracking for partial
  failure cleanup. Peer disconnect callback wires DLM purge + journal
  recovery + netlink notifications + epoch advance. Main loop with
  250ms sleep for signal responsiveness.
  **DLM dispatch**: Routes lock requests between kernel (netlink), peer
  daemons (TCP), and local control socket. Master determination via
  lowest node ID. Non-master nodes forward lock requests to master;
  master processes locally via DLM engine. Grant callback fires when
  queued locks are promoted — routes grant to local kernel (netlink) or
  remote peer (TCP). Pending request tracking with condition variables
  for blocking control socket clients.
  **Control socket**: Unix domain socket at /var/run/mxfsd.sock for local
  test tools (mxfs_lock). Binary protocol: ctrl_req (cmd, mode, flags,
  resource) / ctrl_resp (status, mode). Lock requests block until
  granted or denied (30s timeout).
- **mxfsd_config** — INI-style config parser handling [node], [peer],
  [volume], [timing], [logging] sections. Multiple [peer] and [volume]
  sections supported. Validates required fields (node id/name). All string
  fields bounded by buffer sizes. Reports parse errors with line numbers.
- **mxfsd_peer** — TCP connection management to peer daemons. Listener
  socket with SO_REUSEADDR on configurable bind address/port. Accept thread
  reads NODE_JOIN handshake to identify incoming peers. Receive thread uses
  poll() across all active peer sockets, reads length-prefixed messages
  (header then payload). Outgoing connect with DNS resolution fallback.
  Per-peer send_lock mutex for thread-safe writes. Automatic disconnect on
  read/write errors. Message framing via mxfs_dlm_msg_hdr length field.
- **mxfsd_dlm** — The DLM protocol engine. Hash table (FNV-1a) of lock
  entries protected by a pthread rwlock for read-heavy access. Processes
  lock requests checking compatibility against all granted holders on the
  resource. Supports NOQUEUE/TRYLOCK flags for non-blocking attempts.
  Lock release removes the entry and promotes queued waiters. Lock convert
  handles downgrades (always allowed, promotes waiters) and upgrades
  (checks compatibility, queues if blocked as CONVERTING). Node purge
  removes all locks for a dead node and promotes blocked waiters across
  all buckets. Epoch tracking with mutex-protected counter.
  **Grant callback**: When queued locks are promoted (after release or
  purge), collects promoted lock info while holding the rwlock, then fires
  callbacks outside the lock to avoid holding it during dispatch.
- **mxfsd_netlink** — Raw AF_NETLINK/NETLINK_GENERIC socket (no libnl
  dependency). Resolves "mxfs" genetlink family via CTRL_CMD_GETFAMILY.
  Receive thread dispatches incoming kernel messages through callback.
  NLA attribute helpers for building messages. Sends lock grant/deny,
  cache invalidation, node status, and recovery start/done commands.
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

### Threading Model

- Main thread: signal handling, subsystem lifecycle
- Peer accept thread: incoming TCP connections
- Peer receive thread: reads DLM messages from peers, dispatches via msg callback
- Lease renewal thread: periodic lease renewal with peers
- Lease monitor thread: detects expired peer leases
- Netlink receive thread: messages from kernel module, dispatches via nl callback
- Control socket thread: accepts local tool connections, processes lock/unlock

### Build

```
make -C daemon
```

Produces the `mxfsd` binary.

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
