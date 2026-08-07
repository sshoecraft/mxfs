---
name: ccloop-c7ee71c6-sess99-authority-install-wired-acquire-half
description: sess99: step 5.3(d) ACQUIRE half wired (0.11.432, builds clean) — gen snapshot + install at the routed acquire chokepoint, iclus tenure continuity, r…
metadata:
  type: reference
tags: [sess99, step5.3, authority-token, foreign-replay, D-FOREIGN-REPLAY-UNGATED-IMAGES]
---

# sess99 — step 5.3(d) acquire half WIRED (0.11.432)

Build **0.11.432**, `srcversion 619FFAF4EB078599367EFA5`, **builds clean** (only the
tree's pre-existing `fserror_event`/`xfs_fs_report_error`/`xfs_aops.c` warnings).
**NOT deployed, NOT rig-verified.** Rig still prepped at 0.11.427.

This is item (2) of the sess98 "Next, in order" list — the acquire side of the sess96
ruling. Item (1) (begin_release at release-BEGIN sites) is **NOT done yet**; the
mode-lowering backstop from sess98 is still the only revoke besides the routing change.

## What landed

**The acquire chokepoint is `mxfs_dlm_inode_lock_routed()`** — both arms (iclus-routed
and per-inode) funnel through it, so one edit covers every real acquire. It now takes a
`gen_snap` parameter and, under `i_dlm_lock`, does routing-flip revoke → install.

`mxfs_dlm_ilock_begin` samples `auth_gen_snap = ip->i_mxfs_auth_gen` under `i_dlm_lock`
at the `i_dlm_acq_inflight++` / ACQUIRING transition (xfs_mxfs_dlm.c ~28242) — i.e.
*before* descending into the DLM, which is what makes the re-check at install a real
stale-completion guard. Probe/nudge callers pass the new sentinel
`MXFS_AUTH_GEN_NONE` (`~(uint64_t)0`, in xfs_inode.h) and `mxfs_dlm_authority_install()`
skips entirely for them — an acquire that made no provenance claim can never install.

### The ICLUSTER continuity argument (the part worth keeping)

`mxfs_iclus_lock()` FAST PATH runs **no CAS at all** (`ic->disk_mode >= mode && !busy`
→ pure-memory admit), so most cluster-routed acquires have no grant result to install.
Solution: `struct mxfs_iclus` gains `uint64_t auth_epoch`, set from the granting CAS's
`mxfs_grant_result.grant_epoch` in the same `ic->lock` section that raises `disk_mode`,
and zeroed in the same section at all **three** `disk_mode = MXFS_LOCK_NL` release sites.

That is **not** the resource-keyed cache the sess96 ruling rejected. `ic` IS the object
holding the grant: `disk_mode > NL` is true for exactly the interval between the CAS that
set `auth_epoch` and the release that clears it, both endpoints serialised by
`ic->lock` + `ic->busy`. A reader that observes `(disk_mode, auth_epoch)` in ONE
`ic->lock` section has first-hand evidence of a *continuously held* tenure — which the
hash bucket could not supply. New helper `mxfs_iclus_auth_snapshot_locked(ic, gres, fresh)`
mints the result; `fresh=false` ⇒ `reaffirm=1`, so the fast-path population stays
measurable and distinct from just-granted.

### Routing change = authority-tenure transition (ruling coverage gap iii)

Both arms revoke on a backing flip, then **absorb only their own gen bump**:

    if (!ip->i_dlm_routed_iclus) {
        bool mine = (ip->i_mxfs_auth_gen == gen_snap);
        mxfs_inode_authority_revoke_locked(ip, __LINE__);
        if (mine) gen_snap = ip->i_mxfs_auth_gen;
    }

The `mine` test is load-bearing: if a THIRD party had already moved the counter,
re-snapshotting would erase that evidence and let a stale completion install.

### Publish worker (ruling coverage gap i)

The `pub_defer_claim` fallback in `mxfs_dlm_publish_drain_loop` now snapshots `dip`'s gen
before its own `mxfs_iclus_lock(EX)` and installs from that claim's result — the
UNPUBLISHED_EX → DURABLE_EX promotion the ruling required, from the worker's own CAW
result rather than a mode comparison.

## API changes (callers updated)

- `mxfs_iclus_lock(mp, ino, mode)` → `(mp, ino, mode, struct mxfs_grant_result *gres)`.
  Callers passing NULL: the P13 visnudge PR-nudge, and BOTH `xfs_inode.c` inactivation
  sites (~4513 and ~4564 — note the local `extern` decl there must be updated too, and
  `struct mxfs_grant_result;` was forward-declared at the top of `xfs_mxfs_dlm.h`).
- `mxfs_dlm_inode_lock_routed(ip, mode)` → `(ip, mode, gen_snap)`.

## KNOWN GAP — install currently refuses the unpublished case it was meant to fix

In the routed arm the unpub de-list happens AFTER the `i_dlm_lock` section, so
`ip->i_dlm_unpublished` is still true at install time and the install refuses with
`mxfs_auth_ref_unpub_n`. Do **not** "fix" this by moving the de-list earlier: the
`conv_pi` predicate reads `i_dlm_unpublished`, and clearing it first makes `conv_pi` true
for freshly-created inodes, costing a wasted device CAS per create (the comment there
says exactly that). The lock order `i_dlm_lock` → `m_mxfs_unpub_lock` is **unused today**
(every existing site drops `i_dlm_lock` first, and nothing takes `i_dlm_lock` inside
`m_mxfs_unpub_lock` — verified by grep of all 14 `m_mxfs_unpub_lock` sites), so nesting
them in that order is available and is the clean fix.

## Next, in order

1. Close the unpub gap above (nest the de-list inside the `i_dlm_lock` section).
2. `begin_release_locked` at the release-BEGIN sites — re-verified inventory at 0.11.432:
   `xfs_mxfs_dlm.c` DEMOTING stores at **18334 / 19575 / 19667 / 19810 / 19960 / 28165 /
   29252** (all 7 verified under `i_dlm_lock`), plus `mxfs_clayer/pinned_resource.c`
   **90 / 126** (needs a non-static wrapper — clayer must build in user mode),
   `mxfs_dlm_evict`, and `xfs/xfs_inode.c` 5331/5334/5337. Line numbers shift on every
   edit — re-grep `i_dlm_state = MXFS_DLM_ISTATE_DEMOTING`.
3. The **re-affirm path** (sess98's blocker): RELEASING is sticky, so an aborted release
   (P15-REL-ABORT leaves `mode == EX`) is permanently non-proving. One fresh slot read
   through `caw_grant_result_fill` with `reaffirm=1`, hung off the throttled P108
   held-verify clock `i_dlm_heldchk_j`, installed when a fast-path ilock finds
   `auth_state != MXFS_AUTH_DURABLE_EX`. NOTE: this must land BEFORE step 2, or step 2
   creates a large permanently-non-proving population.
4. Expose the 11 `mxfs_auth_*` counters via debugfs (`mp->m_debugfs`, next to
   `recovery_blocked` registered in `mxfs_dlm_cache_init`), then **deploy and measure** —
   installs vs the six refusal reasons. Four sessions (95-98) have now shipped
   build-clean-but-unmeasured code; the ruling explicitly asked for this population.
5. Certificate copy-out + format-time peek, then `mxfs_buf_derive_owner()` into the
   `mxfs_tokcls_unknown` arm of `pal/linux/xfs_buf_item.c`.

Still-open release blockers from sess96, unchanged: uint32 epoch **wrap** policy, and
**transaction/CIL tenure crossing**.
