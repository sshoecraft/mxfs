---
name: ccloop-c7ee71c6-sess100-authority-population-MEASURED-on-rig
description: sess100: step 5.3 authority population MEASURED on the 32-node rig (0.11.434 DEPLOYED) — 13153 unpublished vs 321 installs; the routed publish path D…
metadata:
  type: reference
tags: [sess100, step5.3, authority-token, foreign-replay, D-FOREIGN-REPLAY-UNGATED-IMAGES, MEASURED]
---

# sess100 — the step-5.3 authority population, MEASURED on the rig

Build **0.11.434**, `srcversion DF3DA841AE97BB178733D62`, **built clean, DEPLOYED to
all 32 nodes** (`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster`, 191 s). This ends the
sessions-95-to-99 run of build-clean-but-unmeasured code.

`rsync_paired` re-boarded on it: **PASS 32/32, 14 s / 60 s budget**, so the acquire-side
wiring costs nothing measurable.

## What landed

1. **The sess99 unpub gap is closed.** The de-list now happens INSIDE the
   `i_dlm_lock` section of `mxfs_dlm_inode_lock_routed()`, after `conv_pi` is computed
   from the pre-de-list value and before the install — so the wasted-CAS gate is intact
   and the install no longer refuses the promotion it exists to perform. Lock order
   `i_dlm_lock` -> `m_mxfs_unpub_lock` re-verified against all 10 `m_mxfs_unpub_lock`
   sections: none takes `i_dlm_lock`.
2. **`/sys/kernel/debug/mxfs/<dev>/inode_authority`** — the 13 counters, registered
   beside `recovery_blocked` in `mxfs_dlm_cache_init`.
3. **Two counter splits that the first measurement forced.** `no_snapshot` (probe/nudge
   acquires, so the denominator is the whole acquire population) and `shared` (a VALID
   but PR/CR grant, split out of `novalid` — one is correctly non-proving, the other is
   a plumbing hole, and conflated the first drowns the second).
4. **`tests/auth_counters.sh <n> [snapshot]`** — parallel read of all 32 nodes, per-node
   table + aggregate, optional delta against a saved snapshot.

## THE MEASUREMENT — rsync_paired delta, 32 nodes

    judged acquires   525      installs 321 (61%)     refused 204 (38%)
      refusals:       novalid 204 (100%)   shared 0   stalegen 0   unpublished 0
      relinquish:     revoke 1   release_begin 0   backstop 1
      unpublished_noted  13153        (411 per node, uniform)

Read that last line against the installs: **13153 inodes entered UNPUBLISHED_EX and 321
tenures were installed cluster-wide.** ~2.4%. A gate keyed on DURABLE_EX would refuse
~97.6% of the images a create-heavy workload produces.

## ROOT OF THE 13153 — the routed publish path is a DEMOTE, not an acquire

Line-read of `mxfs_dlm_publish_drain_loop` (xfs_mxfs_dlm.c ~30421, the `pub_routed`
arm). For a cluster-routed child the publish worker deliberately does NOT claim a
cluster EX — sess5 measured that claim wedging the bast pipeline (470 s
P-WAIT-EXTEND) and losing races to EDEADLK. What it runs instead is the child's own
demote pipeline: writeback + durable dinode + **local NL** + iclus release sweep.

So the created-file lifecycle never passes through a durable tenure at all:

    create -> grant_local_new -> UNPUBLISHED_EX (non-proving)
           -> publish        -> demote to NL   (non-proving)

Only the `pub_defer_claim` fallback — taken when a live local holder aborts the demote —
claims EX, and that is the minority path. sess99 wired the install there; it is working
(it is a large part of the 321), it is just rare BY DESIGN.

**This is not a wiring bug to fix by adding more install sites.** It is the architecture
answering the ruling's question with a number: at the instant a node dies, its
freshly-created inodes are either UNPUBLISHED_EX or already NL. Neither proves.

## The design question this raises (RULE 5 material, not yet consulted)

An UNPUBLISHED_EX inode is one **no peer can hold** — its inode number came from an AG
allocation that IS covered by an AG grant with a real epoch (`P228-TOKCLASS` shows
`ag=15263 of n=16384` formats authorized that way). So the image is safe to apply; it
simply cannot prove it through the per-inode channel. The candidate answer is that
UNPUBLISHED_EX images should be gated by the **AG** tenure that allocated the inode,
not by a per-inode tenure that by design never exists. Bring the numbers above to the
consult — do not implement either way first.

## Secondary finding — `novalid` is 100% of refusals and `shared` is 0

Not PR grants. `gres` is NULL / `!valid` / `grant_epoch == 0` on every refusal. Since
`caw_grant_result_fill` only sets `valid` when `ex_grant_epoch != 0`, and
`mxfs_iclus_auth_snapshot_locked` bails on `ic->auth_epoch == 0`, the live hypothesis is
that `ic->auth_epoch` is 0 for most cluster-routed acquires — i.e. the CAS that granted
the cluster left `lg.valid` false. Split `novalid` three ways (nogres / notvalid /
noepoch) to settle it; that is a one-edit measurement.

## Also confirmed by measurement

`release_begin == 0` and `revoke == backstop` exactly, cluster-wide — every revoke today
comes from the sess98 mode-lowering backstop. That is the wiring state sess99 described,
now measured rather than asserted.

## Next, in order

1. RULE-5 consult with the numbers above: is the per-inode tenure the wrong gate for the
   UNPUBLISHED_EX population, and is the AG tenure the right one?
2. Split `novalid` three ways; re-run rsync_paired; confirm or refute the
   `ic->auth_epoch == 0` hypothesis.
3. The re-affirm path (sess99 item 3) still must land BEFORE `begin_release` wiring
   (sess99 item 2), or sticky RELEASING creates a large permanently-non-proving
   population.
