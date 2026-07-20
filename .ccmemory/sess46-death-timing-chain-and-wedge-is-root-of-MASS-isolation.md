---
name: sess46-death-timing-chain-and-wedge-is-root-of-MASS-isolation
description: sess46(ccloop): EXACT 8/tcp MASS death chain — node stalls >25s (TCP_USER_TIMEOUT) → disconnect → 40s grace → declared dead → round work lost. Root =…
metadata:
  type: project
---

## sess46 — EXACT death-timing chain for the 8/tcp MASS (node-isolation) loss

### The chain (traced through peer.c + kern.c, RULE 4):
1. A node STALLS (stops servicing/ACKing TCP) for a sustained period under the
   8-node concurrent create storm.
2. **TCP_USER_TIMEOUT = 25000ms** (pal/linux/kern.c ~1939, `icsk_user_timeout`)
   aborts the connection after 25s of unacknowledged data (deliberately set
   UNDER the 30s DLM lock-wait timeout, "Bug 105", for fast real-death detect).
   Keepalive (10s idle + 3×3s = ~19s) is the other detector.
3. The abort → peer's `mxfs_pal_tcp_recv`/`_send` HARD error (-ECONNRESET) →
   `peer_handle_disconnect` (peer.c:104,140). `mxfs_peer_send` retries 3× (1.7s)
   and does NOT tear down on transient -ETIMEDOUT/-EAGAIN (sess40 flap-fix) — only
   a HARD error tears down. So the stall must exceed ~25s to trip it.
4. `v5_peer_disconnect_cb_tcp` marks SUSPECT + self-fence (freezes EX) and starts
   the **tcp_death_grace_ms=40000** timer. If the node reconnects within 40s,
   death is cancelled (but it was still EX-frozen + couldn't do its creates).
5. If no reconnect in 40s → "did not reconnect within 40000 ms — declaring dead,
   recovering locks." The dead node's round work is never published → its entries
   are durably missing (the MASS loss, e.g. node5 lost ~54, node6 ~22).

### ROOT = a >25-40s NODE WEDGE. The host is NOT oversubscribed (56 CPUs, load
~4.5), so a 40s stall is a genuine kernel-level wedge (D-state in an UNBOUNDED
synchronous wait), NOT CPU starvation. Captured node 1992015415: disconnect
t=48.5s → declared dead t=88.5s = ~40s wedge.

### PRIME SUSPECT for the wedge: `mxfs_ail_drain_inode_sync(ip)` at dir-EX
release (xfs_mxfs_dlm.c ~8724) has deadline=0 = UNBOUNDED; it waits
`!in_ail && pincount==0`. If xfsaild is starved by the 8-node create storm, this
can block the releasing node indefinitely → wedge → false death.

### DO NOT just bound the release drain: sess32 v0.3.141-142 bounded ail_push +
proceeded-to-release-on-timeout → VIOLATED Invariant 1 → stale peer reads →
REVERTED. (Architectural-Invariant 1 in CLAUDE.md.) The wedge must be eliminated
by making the drain PROGRESS (un-starve xfsaild / cheaper handoff), not by
releasing early.

### NEXT (RULE 4, decisive): build a LIVE per-node watchdog (the dead node's
dmesg is wiped on reboot). Options: a kernel thread that, if any mxfs DLM/drain
op exceeds ~15s, dumps the blocked task's stack (`sched_show_task`/`dump_stack`)
+ which lock/inode/op; OR lower the kernel hung-task threshold; OR a survivor-side
"last DLM message heard from node X at op=..." log so the survivor records what X
was doing when it went silent. Confirm whether the wedge is at RELEASE-drain
(node draining for a peer) or at its own EX-ACQUIRE wait. Then fix the wedge root.

See [[sess46-REFRAME-8tcp-dominant-failure-is-node-isolation-wedge-not-doublegrow]].
</body>
