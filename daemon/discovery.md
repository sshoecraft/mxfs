# mxfsd_discovery — UDP Peer Discovery

## Overview

The discovery module provides automatic peer detection for MXFS nodes over UDP. Nodes periodically broadcast an announcement packet containing their identity and volume UUID. Other nodes listening on the same group address detect these announcements and, if the volume UUID matches, fire a callback to trigger TCP connection establishment.

This replaces static configuration-based peer lists, allowing nodes to form lock groups dynamically.

## Files

- `daemon/mxfsd_discovery.h` — Public interface, packet format, context structure
- `daemon/mxfsd_discovery.c` — Implementation (socket setup, sender/receiver threads, seen list)

## Protocol

### Announcement Packet

| Field          | Type       | Description                         |
|----------------|------------|-------------------------------------|
| magic          | uint32     | `0x4D584644` ("MXFD")               |
| version        | uint16     | Protocol version (currently 1)      |
| flags          | uint16     | 0x01 = has_volume                   |
| node_uuid      | uint8[16]  | Persistent node UUID                |
| node_id        | uint32     | Derived from node UUID              |
| tcp_port       | uint16     | TCP port for DLM traffic            |
| pad            | uint16     | Reserved                            |
| volume_uuid    | uint8[16]  | XFS superblock UUID                 |
| volume_id      | uint64     | Derived from volume UUID            |
| hostname       | char[64]   | Human-readable name for logging     |

### Transport

- **Default**: UDP multicast group `239.66.83.1` port `7601`
- **Alternative**: UDP broadcast to a specified address on port `7601`
- Announcements sent every 2 seconds
- Multicast TTL = 1 (link-local only)
- Multicast loopback enabled for single-host testing

## Architecture

### Threads

1. **Sender thread** — Sends the local announcement packet every `MXFS_DISCOVERY_INTERVAL_MS` (2 seconds). Sleeps in 100ms increments so it can exit quickly when `ctx->running` is set to false.

2. **Receiver thread** — Polls the UDP socket with 500ms timeout. On each received packet:
   - Validates magic and version fields
   - Ignores packets from self (by comparing node_uuid)
   - Ignores packets with non-matching volume_uuid
   - Checks the seen list; if this is a new peer, fires the peer callback
   - Updates last_seen_ms for known peers

### Seen List

An array of `(node_id, last_seen_ms)` pairs, protected by a mutex. The callback only fires the first time a peer is observed. The list capacity is `MXFS_MAX_NODES` (64).

### Modes

- **Multicast (default)**: Joins multicast group via `IP_ADD_MEMBERSHIP`. If an interface is specified, binds multicast output to that interface via `IP_MULTICAST_IF`.
- **Broadcast**: Sets `SO_BROADCAST` and sends to the specified broadcast address (e.g., `192.168.120.255`).

## API

```c
/* Initialize discovery context and create UDP socket */
int mxfsd_discovery_init(struct mxfsd_discovery_ctx *ctx,
                          const struct mxfsd_discovery_announce *local,
                          const char *mcast_addr,   /* NULL = "239.66.83.1" */
                          uint16_t port,            /* 0 = 7601 */
                          const char *iface,        /* NULL = all interfaces */
                          bool use_broadcast);

/* Start sender and receiver threads */
int mxfsd_discovery_start(struct mxfsd_discovery_ctx *ctx);

/* Stop threads (blocks until joined) */
void mxfsd_discovery_stop(struct mxfsd_discovery_ctx *ctx);

/* Stop threads + close socket + destroy mutex */
void mxfsd_discovery_shutdown(struct mxfsd_discovery_ctx *ctx);

/* Register callback for new peer detection */
void mxfsd_discovery_set_peer_cb(struct mxfsd_discovery_ctx *ctx,
                                  mxfsd_discovery_peer_cb cb, void *data);
```

## Lifecycle

```
mxfsd_discovery_init()          — create socket, configure mcast/bcast
mxfsd_discovery_set_peer_cb()   — register new-peer callback
mxfsd_discovery_start()         — launch sender + receiver threads
    ... runs until shutdown ...
mxfsd_discovery_stop()          — stop threads
mxfsd_discovery_shutdown()      — close socket, cleanup
```

## Integration

The daemon's main startup code calls `mxfsd_discovery_init()` after reading the local volume's XFS superblock UUID. The peer callback typically calls `mxfsd_peer_add()` and `mxfsd_peer_connect()` to establish a TCP DLM connection to the newly discovered node.

## Constants

| Name                           | Value          |
|--------------------------------|----------------|
| `MXFS_DISCOVERY_MAGIC`         | `0x4D584644`   |
| `MXFS_DISCOVERY_VERSION`       | `1`            |
| `MXFS_DISCOVERY_PORT`          | `7601`         |
| `MXFS_DISCOVERY_MCAST`         | `239.66.83.1`  |
| `MXFS_DISCOVERY_INTERVAL_MS`   | `2000`         |
| `MXFS_DISCOVERY_TIMEOUT_MS`    | `6000`         |

## History

- v0.5.0 — Initial implementation: multicast/broadcast discovery with sender/receiver threads and seen-list deduplication.
- v0.5.1 — Fix: populate volume_uuid from XFS superblock so discovery only matches nodes on the same volume. Fix: --multicast no longer incorrectly enables broadcast mode.
