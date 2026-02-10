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
