---
name: reference-a-tcp-mounts-node-id-is-random-per-mount-so-no-remount-renews-its-old-lease-entry
description: REFERENCE (s62): a TCP mount's node id comes from 16 random bytes at each mount; only the bootstrap RESUME arm reuses one. A same-id/new-incarnation…
metadata:
  type: reference
tags: [lease, node-id, tcp, incarnation, reference]
---

# A TCP mount's node id is random per mount

Read in session 62 (0.89.69) while deciding whether the lease receiver's
incarnation-mismatch guard (`P-LEASE-INCARNATION-MISMATCH`, dlm/lease.c) needs a lap.

- `dlm/v5_mount.c:16262` fills `ctx->node_uuid` from `mxfs_pal_get_random_bytes`; `:16265`
  derives `ctx->node_id` from it. Every lap console shows a different id per mount
  (`STAGE identities:` lines across s13x-s15x).
- The only reuse of an id on TCP is the bootstrap RESUME arm (`:16417-16425`,
  `P-BOOT-RESUME-IDENTITY`): a mount adopts the provisional identity of a whole-cluster
  term owner that died with the term CLAIMED. Under the waiter rule nobody else is a member
  during a claimed term, so no peer holds a lease entry under that id.
- `node_id_override` (debug module parameter) is the one way to force a repeated id.
- A clean unmount's GOODBYE unregisters the lease entry at each peer (`:1929`) and retires the
  id (`v5_note_dead_node_locked`, "id never returns").
- A crashed slotted node's entry stays until recovery completes (`v5_tcp_declare_dead`
  defers the unregister, `:10902-10908`); that is ~72 s (62 s stale window + replay), while a
  rebooted guest answers ssh at ~120-150 s (boot-wait polls=22-26).

So "a rebooted node renews the old entry with a new incarnation" cannot happen on this
transport: the new mount has a new id and the old entry is either gone or recovered first.
Do not build a lap for it; cite this reading instead.
