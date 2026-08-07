---
name: ccloop-c7ee71c6-sess58-item6A-fixed-plus-fence-honesty-defect
description: sess58: GPT item 6A FIXED (0.11.402) — residue gate fails the mount instead of stalling. Also found+fixed a real defect: fence errors were reported a…
metadata:
  type: reference
tags: [foreign-replay, mount, recovery, deadlock, step4a, fencing, scsi-pr, in-progress]
---

# sess58 — item 6A fixed, plus a fence-reporting defect found on the way

Build **0.11.402**, srcversion `1112F9EDFD340DB0379A7F7`, compiles clean.
**STILL DO NOT BOARD** — GPT items 6B, 3, 4, 2/5, 6C, 6D, 6H and item 1 are
open. 6A and item 1's investigation are done.

## Correction to sess57's characterisation of 6A

GPT called it "mount never returns". Verified in code: it is **not** an
infinite hang. `mxfs_dlm_caw_lock`'s wait loop (dlm_caw.c:2519) breaks at
`MXFS_CAW_WAIT_TIMEOUT_MS` = 120000 unless `holders_alive_fn` says every
blocker is heartbeating — and a residue slot is by definition frozen — then
returns `-ETIMEDOUT` (dlm_caw.c:3147). Hard cap
`MXFS_CAW_WAIT_HARDCAP_MS` = 480000.

So the real shape is: **each blocked acquire inside `xfs_log_mount_finish`
stalls 120 s and then fails the mount**. Still a hard RULE-0 failure and
still must be fixed — but the fix does not have to break an unbreakable
deadlock, only refuse to enter a known-doomed path.

## NEW DEFECT FOUND (code-proven, not in GPT's 8)

`v5_pr_fence_dead_node` (dlm/v5_mount.c) returned **`false` only on
`-ESTALE`**. Every other error from `mxfs_scsipr_fence_node` — including the
READ KEYS failure that the function itself logs as *"cannot classify;
skipping preempt"* (dlm/scsipr.c:210-216) — was returned to the caller as a
**successful fence**. Callers then replayed that node's journal slice, which
is exactly what every comment on that path says must never happen to a node
that may still be writing.

Fixed: split into `v5_pr_fence_dead_node_rc()` returning the errno
(`-ESTALE` = self-fence/terminal, other non-zero = transient failure, 0 =
fenced) with the old bool wrapper kept for the three legacy call sites. The
two deliberate zero-returns inside `mxfs_scsipr_fence_node`
(`-EOPNOTSUPP`, `P-PR-ADVISORY` when `count < live_members`) still count as
fenced — on those topologies D1 (EBADE on write) + lease/disklock carry the
fencing duty, and failing them would make every recovery on the tcm_loop VM
rig unresolvable. **This defect is why the 6A residue path is reachable in
practice at all**, so the two fixes are load-bearing together.

## What landed for 6A

1. `dlm/dlm_caw.c` + `.h` — new `mxfs_dlm_caw_footprint_scan(ctx, node_mask,
   &nex)`. Read-only batched census (same 32-slot batching as the purge) of
   every slot carrying any footprint of the mask, using the existing
   `caw_purge_candidate(s, mask, false)` predicate: holder in ANY mode,
   waiter, or open-holder. Returns the slot count, `*out_ex` the EX/PW
   subset, and **`-EIO` if any slot could not be read** (`P227-FOOTPRINT-
   UNREAD`) — an unread slot may hold anything, so an incomplete census is
   an error, never a zero. Logs `P227-FOOTPRINT`.
2. `dlm/v5_mount.c` — bounded fence retry in `v5_settle_resolve`:
   `V5_FENCE_RETRIES`=5 x `V5_FENCE_RETRY_MS`=1000, breaking early on
   `-ESTALE` (terminal — we are the fenced node). Cheap against the 62 s
   confirm window already paid.
3. `dlm/v5_mount.c` + `.h` — `mxfs_v5_dlm_mount_residue_blocking(ctx,
   &residue, &nslots, &nex)` → 0 = residue owns nothing, 1 = it owns
   something, <0 = could not tell (caller treats as 1).
4. `xfs/xfs_mxfs_dlm.c` — barrier now returns `int`. New step **(b2)**
   between the cohort resolve and the replay loop: if the residue is
   blocking, `xfs_alert` naming the mask/count/EX-count and **return -EIO**.
   A non-blocking residue logs and proceeds.
5. `xfs/xfs_mount.c` — call site checks the return and
   `goto out_free_metadir`. Verified correct unwind for that point:
   `m_metadirip` is still NULL and `rip` is not yet held, so it reduces to
   `xfs_inodegc_flush` + `xfs_unmount_flush_inodes` + `xfs_log_mount_cancel`
   (labels at xfs_mount.c:1276/1299/1300; `out_rele_rip` is ABOVE it at
   1272 so `rip` is correctly not touched).

Rationale recorded in the barrier's header comment: a mount that fails in
seconds with a named cause beats one that stalls minutes and fails anyway.

## Item 1 (flush_epoch) — analysed, NOT yet fixed

`mxfs_blkdev_flush_epoch` (xfs/xfs_mxfs_dlm.c:1337) skips
`blkdev_issue_flush` entirely when `mxfs_fua_disable` is set (default since
sess94) and only bumps the epoch counter. Its rationale (read in full) is a
**coherency** argument — plain reads are served from the shared target cache
so a completed write is already peer-visible — and an explicit **per-modify
cost** argument (2-30 ms each, "the dominant metadata-op cost").

Neither argument covers the barrier's use, which needs **durability**: if we
publish "slice recovered" and purge the CAW manifest while the recovered
buffers sit only in the target's write cache, a target power loss loses the
recovery AND the manifest. The per-op cost argument plainly does not apply
to a once-per-mount barrier.

**Planned fix (next session):** add `mxfs_blkdev_flush_durable(mp)` that
ALWAYS issues `blkdev_issue_flush` then bumps the epoch, and use it at the
barrier's steps (a)/(c) and in the recovery-completion publication path.
Leave `mxfs_blkdev_flush_epoch` alone for the per-modify callers.

## Next session order

1. Item 1 fix as above (small, designed).
2. Item 6D — `mxfs_v5_dlm_recovery_complete` (dlm/v5_mount.c:1651 region)
   runs caw purge → lease unregister → clear_recovery_pending → disklock
   purge/zero HB → beacon with **no failure checks**; a failed CAW purge or
   flush must block publication.
3. Item 2/5 — `mxfs_dlm_invalidate_cached_views` must return
   complete/incomplete-busy/fatal and only clear `pag_dlm_cached` /
   `bast_pending` / `release_pending` / `lineage_open` on complete.
4. Then 6B, 3, 4, 6C, 6H (6H may be a separate open defect — cross-checks
   `compiled-foreign-replay-crash-consistency`'s "non-comparable per-node
   LSNs").
5. RULE-5 consult on the whole set before any rig cycle.
