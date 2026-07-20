# Discovery Module (libmxfs/discovery)

## Purpose
Automatic peer discovery over UDP multicast or broadcast. Nodes periodically announce themselves; other nodes with the same XFS volume UUID detect each other and trigger TCP connection establishment.

## Architecture
Two PAL threads replace kernel delayed_work + kthread:
- **Sender thread**: periodically sends discovery announcement via UDP
- **Receiver thread**: receives UDP packets, validates, fires callback for new peers

## Ported From
kernel/mxfs_discovery.{c,h} — kernel sockets, delayed_work, kthreads replaced with PAL UDP, threading, mutex APIs.

## Key Design
- Wire-compatible announcement packet (mxfs_discovery_announce) using little-endian fields
- Magic: 0x4D584644 ("MXFD"), Version: 1
- Default: multicast 239.66.83.1:7601, interval 2000ms
- Seen list tracks known peers by node_id + timestamp
- Volume UUID matching: ignores announcements from different volumes
- Self-ignore via node_uuid comparison
- PAL recvfrom provides sender IP as string (no %pI4 needed)

## Files
- discovery.h: 98 lines — announce struct, context, public API
- discovery.c: 287 lines — implementation

## Broadcast Mode

When `use_broadcast=true`, the sender targets `255.255.255.255` instead of the
multicast group. The socket has `SO_BROADCAST` set. The receiver socket binds
to the discovery port and receives both multicast (if group joined) and
broadcast packets, so the same recv path handles both modes.

Broadcast is required in nested ESXi environments where VMware's vmnet internal
switch does not forward multicast between guest VMs. It is an explicit opt-in
(`-o broadcast`) — never the default — to avoid generating unexpected broadcast
traffic on production networks.

See docs/discovery.md for the full operator guide including environment matrix
and mount option reference.

## Shutdown
`mxfs_discovery_stop()` uses three-pronged signaling:
1. Sets `running = false`
2. Broadcasts `shutdown_cond` condvar -- wakes sender thread from its timed wait
3. Calls `mxfs_pal_udp_shutdown()` on the socket -- unblocks recv thread from `kernel_recvmsg()`
4. Joins both threads (now return promptly)

The sender thread uses `mxfs_pal_cond_timedwait()` on `shutdown_cond` instead of `mxfs_pal_sleep_ms()`, allowing instant wakeup on shutdown.

## History
- 2026-02-15: Ported from kernel to portable C using PAL
- 2026-02-17: Documented broadcast requirement for nested ESXi; added environment guide
- 2026-02-19: Fixed unmount hang -- replaced uninterruptible sleep with condvar timed wait in sender thread; added UDP socket shutdown in stop() to unblock recv thread immediately
