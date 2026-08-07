---
name: ccloop-c7ee71c6-sess28-REFUTED-creator-baseline-stamp-is-a-noop
description: REFUTED by measurement: sess27's "fully scoped" creator-baseline publish stamp is a no-op — the epoch is 0 at every publish site. Do not re-walk.
metadata:
  type: project
tags: [mxfs, refuted, creator-baseline, D-SILENT-MKDIR-LOSS, sess28]
---

# sess28 — sess27's "fix fully scoped" creator-baseline stamp is a NO-OP

sess27 handed over `mxfs.publish_baseline_stamp` as "the most actionable
critical item in the ledger… root PROVEN, fix FULLY SCOPED, both stamp points
identified." It was implemented in full this session and **measured to change
nothing**. Do not re-walk it.

## What was implemented (so the work isn't repeated either)

`mxfs.creator_baseline_stamp` (ships **0**), stamping the baseline at the moment
an inode takes its first real EX grant, at **four** sites — sess27 named three
and missed the one that matters:

| site | where | fires for |
|---|---|---|
| 1 | `mxfs_dlm_publish_inode()` | rename/link force-publish, symlink |
| 2 | async publish worker | `i_mxfs_reused_create` dirs (**19/run**) |
| 3 | `mxfs_dlm_publish_drain_loop()` (BAST-driven) | dirs, non-routed arm (**4/run**) |
| **4** | **the sess107 unpublished-modify backstop in `mxfs_dlm_ilock_begin`** | **a fresh self-created dir's first EX op (~30 µs after mkdir)** (**2/run**) |

**The sess27 locking blocker was real but did not need a side table.** The
recorded constraint — `mxfs_v5_dlm_inode_grant_gen()` takes a sleeping mutex
(`caw_grant_meta_seq`, `dlm/dlm_caw.c:1120`) while SITE 2's stamp point runs
under `spin_lock(&mp->m_mxfs_unpub_lock)` — is solved by **hoisting the QUERY
above the spinlock** (the EX grant is already held, so no peer can move either
value) and doing only scalar stores inside it. No `orphan_clock`-style side
table, no reference dance.

## Why it is a no-op

**The epoch read at publish is ZERO EVERY TIME.** 2/caw, 50+ publishes per run:
`site=2 ×19, site=3 ×4, site=4 ×2 — all bep=0`. A freshly created inode's slot
has no handoff history yet, so stamping 0 over 0 changes nothing.

**The sentinel is not where the damage is.** The damage is that the epoch the
*consumers* later read belongs to a **previous incarnation** of the same inode
number — see `ccloop-c7ee71c6-sess28-ROOT-dir-epoch-is-per-inode-number-not-incarnation`.

## Kept / removed

- **KEPT:** the `P210-CREATOR-BASELINE` probe, made **unconditional** so it is a
  knob-independent exposure counter for the real fix's A/B; and the explicit
  `i_dlm_creator_base_state` lifecycle (`UNSET`/`SEEN`/`VALID`) — GPT's
  "never established must be a STATE, not the numeric 0".
- **REMOVED:** `mxfs.create_baseline_trackers`. sess27 proved it dead code; it
  was *also* a latent sleep-in-atomic (it called
  `mxfs_v5_dlm_inode_grant_gen()` under `spin_lock(&ip->i_dlm_lock)`). A knob
  that cannot change behaviour is worse than no knob — sess21's A/B "compared"
  two identical arms because of it.

## Method note

A code-reading design handed over as "fully scoped" still has to be measured
before it is believed. The instrument that settled it in one build was printing
the **site id and the value being stamped** in the probe, rather than only
counting that the path was reached.
