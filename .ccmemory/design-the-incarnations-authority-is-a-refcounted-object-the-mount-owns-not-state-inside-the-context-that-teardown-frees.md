---
name: design-the-incarnations-authority-is-a-refcounted-object-the-mount-owns-not-state-inside-the-context-that-teardown-frees
description: DESIGN (Astra s88, 0.89.21): struct mxfs_authority holds the ONE copy of the lease state, is allocated by the mount before the DLM and freed after al…
metadata:
  type: project
---

## The shape

`struct mxfs_authority` (dlm/disklock.h) is a separate reference-counted
allocation holding the single copy of `{state, deadline_ms, anchor_ms,
closed_at_ms, last_ok_ms, close_reason, withdraw_pending, incarnation, node,
slot}`.

- The **mount** allocates it in `xfs_fs_fill_super` *before* calling
  `mxfs_v5_dlm_init`, so the gate has an answer from the first instant a
  clustered mutation is possible, and drops its reference in `xfs_mount_free`,
  after every producer, workqueue, timer and I/O completion is gone.
- The **v5 DLM context** and the **disklock context** each take their own
  reference and write renewals and closures through to it.
- `mxfs_disklock_create()` takes it as a fourth argument; NULL means "make
  your own" and is the user-mode build's path.
- `mp->m_mxfs_clustered` is a mount property set once, never cleared. The gate
  is `if (!m_mxfs_clustered) return true;` then `mxfs_authority_ok(auth)`, with
  a missing object on a clustered mount **refused** and counted.

## Why not the obvious alternatives

**Not state inside the disklock context**, because teardown frees that context
while the mount is still submitting — and the mount can outlive it (the P304
departure-quarantine path deliberately leaks the DLM context with the module
pinned, so the reverse can happen too, hence the refcount rather than plain
mount ownership).

**Not two mirrored copies** (one in the disklock, one in the mount). Astra's
ruling names the failures: a renewal completion racing a close; an old renewal
overwriting newer state; state and deadline read from different updates;
shutdown closing one copy while producers use the other. `READ_ONCE()` gives
neither a coherent snapshot nor a lifetime.

**Not a per-work-item epoch stamp**, because in MXFS an incarnation IS a
mount and the work already retains a reference to it — mount identity supplies
the stamping implicitly. That substitution is sound only while the work never
resolves authority through "the current context for this device / journal slot
/ node id", and while mount memory cannot be recycled under a live callback.
If either stops holding, the stamp becomes necessary.

## The counters it publishes

`P291-AUTH-TAIL tail_admit=… tail_refuse=… no_authority=… tail_blind=…`, once
per unmount. `tail_admit` is the **positive control**: submissions made after
the DLM was detached and admitted because the lease was still live. An ordinary
unmount produces exactly one — the unmount record's iclog. `no_authority` must
always be zero.

Ruling: `docs/rulings/mount-owned-authority-and-what-a-lease-does-not-restore.md`.
