# MXFS Implementation Tasks

Status key: `[ ]` = pending, `[~]` = in progress, `[x]` = done

## Phase 1: Foundation (no dependencies)

- [x] **T01** — Implement `daemon/mxfsd_log.c`
  - File+syslog output, thread-safe via mutex, level filtering
  - Read `daemon/mxfsd_log.h` for interface
  - Update `daemon/daemon.md` when done

- [x] **T02** — Implement `daemon/mxfsd_config.c`
  - Parse INI-style config (see `config/volumes.conf.example`)
  - Populate `struct mxfsd_config` from file
  - Read `daemon/mxfsd_config.h` for interface
  - Update `daemon/daemon.md` when done

## Phase 2: Networking (depends on Phase 1)

- [x] **T03** — Implement `daemon/mxfsd_peer.c`
  - TCP listener, outgoing connections, reconnect logic
  - Message framing: length-prefixed with `mxfs_dlm_msg_hdr`
  - Accept thread, receive thread
  - Read `daemon/mxfsd_peer.h` and `include/mxfs/mxfs_dlm.h` for interface
  - Update `daemon/daemon.md` when done

- [x] **T04** — Implement `daemon/mxfsd_netlink.c`
  - Open genetlink socket, resolve "mxfs" family
  - Send/receive messages to/from kernel module
  - Receive thread for incoming kernel messages
  - Read `daemon/mxfsd_netlink.h` and `include/mxfs/mxfs_netlink.h`
  - Update `daemon/daemon.md` when done

## Phase 3: DLM Core (depends on Phase 1)

- [x] **T05** — Implement `daemon/mxfsd_dlm.c`
  - Hash table for lock resources
  - Lock request/release/convert processing
  - Queue management for blocked requests
  - Node purge on death
  - Epoch tracking
  - Compatibility matrix already implemented — build on it
  - Read `daemon/mxfsd_dlm.h` and `include/mxfs/mxfs_dlm.h`
  - Update `daemon/daemon.md` when done

- [x] **T06** — Implement `daemon/mxfsd_lease.c`
  - Renewal thread: periodic lease renewal to all peers
  - Monitor thread: detect expired peer leases
  - Expire callback triggers DLM purge + journal recovery
  - Read `daemon/mxfsd_lease.h`
  - Update `daemon/daemon.md` when done

## Phase 4: Recovery & Volumes (depends on Phases 2-3)

- [x] **T07** — Implement `daemon/mxfsd_journal.c`
  - Journal slot claim/release
  - Mark dead node's slot for recovery
  - Begin/finish recovery coordination
  - Read `daemon/mxfsd_journal.h`
  - Update `daemon/daemon.md` when done

- [x] **T08** — Implement `daemon/mxfsd_volume.c`
  - Volume tracking, add from config
  - Mount/unmount state management
  - Lookup by ID and device path
  - Read `daemon/mxfsd_volume.h`
  - Update `daemon/daemon.md` when done

## Phase 5: Kernel Module (can parallel with Phase 2-4)

- [x] **T09** — Implement `kernel/mxfs_netlink.c`
  - Register genetlink family "mxfs"
  - Define ops for each MXFS_NL_CMD_*
  - Send lock requests to daemon, receive grants/denials
  - Receive cache invalidation commands
  - Read `include/mxfs/mxfs_netlink.h`
  - Update `kernel/kernel.md` when done

- [x] **T10** — Implement `kernel/mxfs_hooks.c`
  - Hook into XFS inode lock/unlock paths
  - Hook into XFS extent allocation
  - Hook into XFS AG lock paths
  - Forward lock requests through netlink to daemon
  - Block calling thread until DLM response
  - Read `include/mxfs/mxfs_dlm.h` for lock types
  - Update `kernel/kernel.md` when done

- [x] **T11** — Implement `kernel/mxfs_cache.c`
  - Invalidate page cache ranges on DLM notification
  - Handle full-inode and partial-range invalidation
  - Read kernel pagemap.h API
  - Update `kernel/kernel.md` when done

- [x] **T12** — Implement `kernel/mxfs_main.c`
  - Wire init: netlink_init → hooks_init → cache_init
  - Wire exit: reverse order
  - Error handling / rollback on partial init failure
  - Update `kernel/kernel.md` when done

## Phase 6: Integration (depends on all above)

- [x] **T13** — Implement `daemon/mxfsd_main.c`
  - CLI argument parsing (start/stop/status, --config)
  - Signal handling (SIGTERM/SIGINT → clean shutdown, SIGHUP → reload)
  - Daemonization (fork, setsid, redirect stdio)
  - Subsystem init in order: log → config → volume → dlm → netlink → peer → lease → journal
  - Subsystem shutdown in reverse order
  - Main loop
  - Update `daemon/daemon.md` when done

- [x] **T14** — Verify full daemon compiles and links clean
  - `make daemon` with zero warnings
  - Fix any cross-module issues

- [x] **T15** — Verify kernel module compiles clean (if headers available)
  - `make kernel` or verify syntax/structure is correct
  - Fix any issues

## Phase 7: DLM Integration & Testing (depends on Phase 6)

- [x] **T16** — Wire DLM message dispatch in mxfsd_main
  - DLM grant callback (fires when queued locks promoted)
  - Peer message callback (routes LOCK_REQ/GRANT/DENY/RELEASE)
  - Netlink callback (kernel lock/unlock requests)
  - Master determination (lowest node ID)
  - Non-master forwards to master, master processes locally
  - Pending request tracking for blocking control socket clients
  - Control socket (/var/run/mxfsd.sock) for mxfs_lock test tool
  - Update `daemon/daemon.md` when done

- [x] **T17** — Build mxfs_lock test tool (tools/mxfs_lock.c)
  - Lock/unlock via control socket
  - Accepts mode names (NL/CR/CW/PR/PW/EX) or numeric

- [x] **T18** — 2-node cluster integration test
  - Local master lock/unlock: PASS
  - Cross-node lock (non-master → master): PASS
  - Cross-node EX contention (queue + grant after release): PASS

## Phase 8: Fencing & Persistence (depends on Phase 7)

- [x] **T19** — Implement distributed per-resource mastering
  - Replace single-master (lowest node ID) with hash-based per-resource mastering
  - FNV-1a(resource) % active_node_count → sorted active node list
  - Remove is_master() / get_master_id(), add mxfsd_dlm_resource_master()
  - Update all call sites in mxfsd_main.c
  - Active node list rebuilt on connect/disconnect
  - Update `daemon/daemon.md` when done

- [x] **T20** — Implement SCSI-3 Persistent Reservations (mxfsd_scsi_pr.c)
  - SG_IO ioctl for PERSISTENT RESERVE IN/OUT
  - WRITE EXCLUSIVE REGISTRANTS ONLY reservation (type 5)
  - Register, reserve, preempt, unregister, read keys/reservation
  - Full SCSI sense data decoding
  - Create `daemon/scsi_pr.md` when done

- [x] **T21** — Implement on-disk lock state (mxfsd_disklock.c)
  - .mxfs/lockstate file on shared XFS volume
  - O_DIRECT + O_SYNC for sector-aligned atomic 512-byte records
  - 64 heartbeat slots + 65536 lock record slots
  - FNV-1a hash with linear probing for lock records
  - Heartbeat writer thread (2-second interval)
  - Pre-allocation with fallocate()
  - Create `daemon/disklock.md` when done

- [x] **T22** — Integrate fencing layers into mxfsd_main
  - Wire SCSI PR init/register/reserve on startup
  - Wire disklock init + heartbeat start
  - All lock grants persisted to disk before grant response
  - All lock releases cleared from disk after in-memory release
  - Peer disconnect: SCSI preempt → disk purge → memory purge → recovery
  - Clean shutdown: unregister SCSI PR, stop heartbeat
  - Version bump to 0.4.0
  - Update daemon/daemon.md, TASKS.md, INFO.md

## Phase 9: Discovery & Config-Free Startup (depends on Phase 8)

- [x] **T23** — Implement UDP peer discovery module (mxfsd_discovery.c)
  - Multicast (239.66.83.1:7601) and broadcast modes
  - Periodic announcement with node UUID, node ID, TCP port, volume UUID
  - Receiver thread with duplicate tracking and peer callback
  - Interface binding via SO_BINDTODEVICE
  - Create daemon/mxfsd_discovery.h and daemon/mxfsd_discovery.c

- [x] **T24** — Rewrite mxfsd_main CLI for config-free startup
  - Device mode: `mxfsd start /dev/sdb1 [options]`
  - Config mode: `mxfsd start --config <path> [options]`
  - Persistent node UUID at /etc/mxfs/node.uuid (version 4, FNV-1a hash)
  - New CLI options: --iface/-i, --broadcast/-b, --multicast/-m,
    --peer/-P, --port/-p
  - Discovery integration with peer callback for auto-add
  - Manual peer mode (--peer flags, skips discovery)
  - Dynamic peer addition in peer accept thread
  - Active node list scans peer_ctx directly
  - Version bump to 0.5.0
  - Update daemon/daemon.md, TASKS.md, INFO.md

- [x] **T25** — Fix discovery volume UUID and multicast mode bugs
  - Read XFS sb_uuid (offset 32) from device into discovery announce packet
  - Without this fix, volume_uuid was all-zero — nodes matched any peer
  - Fix --multicast flag incorrectly enabling broadcast mode
  - Version bump to 0.5.1

## Phase 10: Stacking Filesystem Refactor (depends on Phase 9)

- [x] **T26** — Rewrite kernel headers and data structures
  - Rewrite `kernel/mxfs_internal.h` with stacking FS structs (mxfs_sb_info,
    mxfs_inode_info, mxfs_dentry_info, mxfs_file_info) and accessor macros
  - Add MXFSD_PATH, MXFS_DAEMON_STARTUP_TIMEOUT_S, MXFS_MNT_* to mxfs_common.h
  - Add MXFS_NL_CMD_DAEMON_READY, MXFS_NL_ATTR_UUID, MXFS_NL_ATTR_DAEMON_PID
    to mxfs_netlink.h

- [x] **T27** — Create kernel stacking core (mxfs_super.c, rewrite mxfs_main.c)
  - Create `kernel/mxfs_super.c`: mount/unmount, fill_super, inode cache,
    dentry ops, statfs delegation, UUID-to-volume-ID conversion
  - Rewrite `kernel/mxfs_main.c`: register_filesystem("mxfs"), init order:
    inode_cache -> netlink -> cache -> register_filesystem

- [x] **T28** — Create VFS operation files (mxfs_inode.c, mxfs_file.c, mxfs_dir.c)
  - Create `kernel/mxfs_inode.c`: three inode_operations tables (dir, regular,
    symlink) delegating to XFS via VFS helpers
  - Create `kernel/mxfs_file.c`: file_operations delegating to lower XFS file
  - Create `kernel/mxfs_dir.c`: directory file_operations with readdir wrapper

- [x] **T29** — Rewrite daemon for kernel-spawned lifecycle
  - Rewrite `daemon/mxfsd_main.c`: remove CLI (start/stop/status),
    daemonization, PID file, SIGHUP reload, config file mode. Accept
    --device, --mountpoint, --uuid from kernel. Signal ready via netlink.
  - Add `mxfsd_netlink_send_daemon_ready()` to mxfsd_netlink.c

- [x] **T30** — Add DAEMON_READY handler and daemon spawn/kill to kernel
  - Add DAEMON_READY handler to `kernel/mxfs_netlink.c`
  - Refactor to per-mount portid (removed global daemon_portid)
  - Update RECOVERY_START/DONE for per-SBI state
  - Add `mxfs_cache_find_sbi_by_volume()` to mxfs_cache.c
  - Add `mxfs_spawn_daemon()` / `mxfs_kill_daemon()` to mxfs_super.c
  - Wire daemon lifecycle into fill_super/kill_sb

- [x] **T31** — Add DLM lock integration to all VFS operations
  - Wrap inode operations with DLM locks (create/lookup/link/unlink/symlink/
    mkdir/rmdir: EX on parent; rename: EX on both dirs in ino order;
    permission: CR; getattr: PR; setattr: EX)
  - Wrap file operations (open: CR, read: PR, write: EX, fsync: EX)
  - Wrap directory operations (readdir: PR)
  - Add recovery wait to all locked operations

- [x] **T32** — Version bump, documentation, build verification
  - Version bump 0.5.1 -> 1.0.0 (VERSION, mxfs_common.h, mxfs_main.c)
  - Rewrite kernel/kernel.md for stacking FS architecture
  - Update daemon/daemon.md for kernel-spawned lifecycle
  - Update INFO.md file layout, architecture description
  - Update TASKS.md with Phase 10 refactor tasks
