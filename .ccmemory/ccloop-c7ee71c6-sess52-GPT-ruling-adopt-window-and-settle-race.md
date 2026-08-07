---
name: ccloop-c7ee71c6-sess52-GPT-ruling-adopt-window-and-settle-race
description: sess52 GPT RULE-5 ruling on step-4a: ctx-&gt;held alone is NOT a safe adopted-vs-orphan discriminator; adopt must CAS to serialise against the settle…
metadata:
  type: reference
tags: [foreign-replay, D-FOREIGN-REPLAY, step4a, gpt-ruling, dlm_caw, adopt-window, design]
---

# sess52 — step-4a hardening after GPT review

Supersedes the settle design in
[[ccloop-c7ee71c6-sess51-step4a-design-manifest-is-EX-only]] (the sess51
*manifest-is-EX-only* finding itself stands and is confirmed).
Campaign: [[compiled-foreign-replay-authority-tokens]].

## The hazard I found in the sess51 plan (before consulting)

sess51's settle step said "purge our own retained EX/PW bits". That is
WRONG as a blanket action. By settle time some retained EX bits have been
**legitimately re-adopted by the live mount**: retained EX on AG=3 →
`xlog_recover` acquires AG=3 EX → fast path grants (`our_mode==EX`) → FS
sets `pag_dlm_cached=true` on unlock. A blanket purge strips the on-disk
bit while the FS still believes it holds AG=3 cached → this node writes
AG-meta with no authority and a peer can acquire EX concurrently. That is
the D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY failure class, created by
the fix for a different defect.

## GPT's ruling (RULE 5)

Approved the adoption idea; **rejected "`ctx->held` with no extra
protocol"**. Mandatory pieces:

1. **`track_held()` in both `caw_lock` fast paths.** Must not be
   best-effort — tracking failure must fail the acquisition.
2. **Serialise settle against acquire.** Named the fatal race verbatim:
   `acquire observes retained EX` → `settle sees untracked, clears EX` →
   `acquire track_held(), returns success` ⇒ the node holds only a local
   fiction. "A batched snapshot followed by clearing is not sufficient."
3. **Close the `single_node`/`mem_lock` bypass** during adoption.
4. **Audit inode + ICLUSTER BAST paths** — do not infer safety from the
   AG `pag_dlm_cached` gate.
5. **Identity-safe skip test** (resource/generation, not just index).
6. **Durable REPLAYED before any manifest-destructive purge**; on any
   recovery/durability failure leave the manifest intact and FAIL the
   mount — never "clean up" retained EX/PW.
7. **CLAIM C through full D2 including fencing**, never a weaker
   mount-local purge. Confirm the same incarnation is frozen for the
   full lease interval, not one immediate re-read.
8. **Do NOT restamp `ex_grant_epoch` on adoption.** Adoption inherits
   the previous incarnation's authority; restamp only on a real new or
   conversion grant.

## Resolution chosen for #2 (no global lock)

Do not add an rwlock — the acquire retry loop can run to the 8-minute
wait hardcap, so a read lock held across it would block settle's write
lock and hang the mount.

Instead: **make adoption CAS.** In the fast path, when
`ctx->mount_adopt_window` is true AND the slot is not in `ctx->held`,
convert the no-CAS fast path into a real CAS (bump `generation`, leave
`ex_grant_epoch` alone) then `track_held`. Adoption and the settle purge
then compete on the same slot:
- adopt wins → settle's CAS returns `-EAGAIN`, it re-reads, slot is now
  tracked → skip. Correct.
- settle wins → adopt's CAS fails, retries from the top, sees our bit
  gone, takes the normal full acquire path (fresh grant, new epoch).
  Correct — replay is already finished by settle time, so the lost old
  epoch costs nothing.

Gated on `mount_adopt_window` so the hot steady-state path is unchanged.

## Code facts that answered GPT's audit items

- **Q2 is airtight for a stronger reason than `pag_dlm_cached`.**
  `mxfs_v5_dlm_set_bast_notify` / `set_ag_bast_notify` /
  `set_iclus_bast_notify` are registered ONLY in `mxfs_dlm_cache_init`
  (`xfs_mxfs_dlm.c:41889-41900`), which runs at `xfs_super.c:3080`
  **after** `xfs_mountfs`. During `xlog_recover` all three callbacks are
  NULL, so `v5_bast_cb` dispatches nothing — **no BAST path can revoke
  authority during recovery at all**, tracked or not.
- **ICLUSTER is inert**: `int mxfs_icluster_dlm;` (`xfs_mxfs_dlm.c:41944`)
  defaults 0 and no ICLUSTER resource is ever acquired.
- **`single_node` is safe, contrary to GPT's concern**:
  `mxfs_dlm_caw_flush_held_to_disk` (`dlm_caw.c:7082`, sess25 fix)
  deliberately does NOT promote in-memory holds to disk — it drops them
  and `mxfs_dlm_peer_joined_flush` invalidates the FS-side cache. So a
  single_node hold is never represented by an on-disk bit, and purging
  an untracked retained bit cannot strip one.
- **Untracked release works**: `mxfs_dlm_caw_unlock_gen` (`:4653`)
  locates the slot via `find_slot(resource)`, not `ctx->held`.
- **The inode BAST orphan path helps rather than hurts**:
  `mxfs_dlm_bast_notify` (`xfs_mxfs_dlm.c:18807`) releases the on-disk
  slot when `xfs_iget(INCORE)` misses — i.e. it independently reclaims
  exactly the un-adopted leftovers settle targets.
- Our OWN slice needs no step-4b REPLAYED record: a successful
  `xlog_recover` updates the log head/tail, so already-replayed records
  fall outside the active range. 4b remains required for FOREIGN slices
  (CLAIM C), which settle only *routes* into D2 — it never purges them.

## Shipped in this session (0.11.398 tree, build clean)

`dlm/dlm_caw.{c,h}` only — the primitive, no callers yet, so runtime
behaviour is byte-for-byte unchanged:
- `MXFS_CAW_PURGE_KEEP_EX` / `MXFS_CAW_PURGE_SKIP_TRACKED` flags +
  `mxfs_dlm_caw_purge_dead_nodes_ex()`; old entry point is a `flags=0`
  wrapper.
- `caw_purge_candidate()` helper; `is_tracked_held()`.
- KEEP_EX skips the `holders_ex`/`holders_pw` clears AND explicitly
  blocks `caw_tombstone_slot` (it zeroes `ex_grant_epoch`).
- SKIP_TRACKED tested twice — at candidacy and again after the
  authoritative re-read inside the CAS retry loop (closes the adopt race
  from the settle side).
- `ctx->mount_adopt_window`, `ctx->mount_retained`,
  `mxfs_dlm_caw_set_adopt_window()`, `mxfs_dlm_caw_retained_count()`.

## Remaining edit list for 0.11.399

1. `dlm/dlm_caw.c` `mxfs_dlm_caw_lock`: adopt-CAS + `track_held` in the
   `our_mode == mode` (`~:3795`) and `our_mode >= mode` (`~:3925`) fast
   paths, gated on `mount_adopt_window && !is_tracked_held()`.
2. `dlm/v5_mount.c:1769` step 4 → `_ex(..., KEEP_EX)`, then
   `set_adopt_window(true)` if `retained_count() > 0`.
3. `dlm/v5_mount.c:1839` step 6.5 → record `ctx->mount_stale_mask`,
   do not purge.
4. `dlm/v5_mount.c`: factor the D2 tail of `v5_lease_expire_cb`
   (`:1141-1190`) into `v5_start_slice_recovery(ctx, slot, node)`;
   new `mxfs_v5_dlm_mount_settle(ctx)` = own-slot
   `_ex(SKIP_TRACKED)` → `set_adopt_window(false)` → per stale bit
   re-verify frozen → fence → `v5_start_slice_recovery`.
   Node id per slot: `mxfs_disklock_get_slot_node_id` (`disklock.h:537`).
5. `xfs/xfs_mxfs_dlm.c`: `mxfs_dlm_mount_recovery_settle(mp)` — the
   `mxfs_dlm_peer_joined_flush`-style barrier (double `xfs_log_force`
   SYNC + `xfs_ail_push_all_sync` + `mxfs_blkdev_flush_epoch`) then the
   v5 call.
6. `pal/linux/xfs_super.c:3080-3086` — call it after
   `mxfs_dlm_cache_init(mp)` (needs `dead_node_notify` registered) and
   before `mxfs_init_all_perag_data(mp)`.
