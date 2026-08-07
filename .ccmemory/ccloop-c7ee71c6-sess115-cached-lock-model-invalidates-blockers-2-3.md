---
name: ccloop-c7ee71c6-sess115-cached-lock-model-invalidates-blockers-2-3
description: sess115: PROVEN by code — MXFS CAW locks are cached per-mount grants with NO per-acquire release, so tenure[] is not a refcount and sess114 blockers…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess115, samenode-waiter, code-facts, cached-lock-model]
---

# sess115 — the cached-lock model, and why sess114 blockers 2/3 cannot be built as ruled

Tree UNCHANGED this session: VERSION **0.11.441**, srcversion
`B385712E9A1F9A025F1D3C1`, still the STOP-SHIP core, fleet still on 0.11.440.
**No edits were made** — this session was proof work that stopped an
implementation that would have wedged the cluster.

Prior: `…sess114-GPT-ruling-cancelling-accepted-10-more-blockers`,
`…sess114-lreq-plan-and-partial-landing`.

## FACT A (decisive) — tenure[] is NOT a reference count

MXFS CAW locks are **per-mount CACHED grants with no per-acquire release**.

- `mxfs_dlm_caw_lock(resource, mode)` means "ensure this node holds ≥ mode".
  Its most common outcome is the **memory-only already-held shortcut**
  (`dlm_caw.c:4680-4722`, already-held-higher `:4790-4828`) — writes nothing
  to the slot, `rc = 0`, `goto out`.
- `out:` is `:5456`; the common tail `:5480-5506` calls
  `lreq_finish(..., held_mode)` with `held_mode != NL`, and `lreq_finish`
  does `e->tenure[held_mode]++` (`:2736`).
- The ONLY decrements of `tenure[]` in the whole tree: the convert's
  `tenure[conv_from]--` (`:7020`) and `lreq_release_all`'s `memset` (`:2816`).
- `mxfs_dlm_caw_unlock` is a **BAST-driven whole-node EVICTION**, never
  paired 1:1 with an acquire (own comment `:5686`; AG side
  `mxfs_v5_dlm_ag_unlock` called only from `mxfs_dlm_bast_work_fn` and
  `mxfs_dlm_ag_release_work_fn`).

**Therefore `tenure[m]` is a monotone tally of grants at mode m since the last
eviction.** On a hot cached AG lock it reaches thousands. The sess114 plan's
`refs = sum(tenure); refs > 1 ⇒ do not issue the disk clear` would make
**every eviction a no-op and permanently wedge the cluster** — nothing would
ever decrement it, because there is no per-thread release.

**DO NOT IMPLEMENT the `refs` reduction from
`…sess114-lreq-plan-and-partial-landing`.** That memory's "blocker 2+3
collapse" section is superseded by this one.

## FACT B — the AG whole-node clear already has a stronger exclusion, shipped

`xfs/xfs_mxfs_dlm.c`:
- `:39483` `pag->pag_dlm_demoting = true` — the SINGLE release-commit site,
  under `pag_dlm_lock`.
- `:32531-32544` `mxfs_ag_dlm_wait_demote()` — every local AG acquire parks on
  `pag_dlm_demote_wq` while it is set.
- `mxfs_v5_dlm_ag_unlock` runs strictly inside that window (`:39812`, `:41376`).
- The flag clears and the wq wakes only AFTER the unlock returns (`:39821`,
  `:41385`).

So **no local AG acquire can be in flight across an AG eviction** — sess114
blocker 1's sequence is unreachable for AG resources.

## FACT C — the inode park and its ONE exemption

Local INODE acquires park while `i_dlm_state` ∈ {DEMOTING, ACQUIRING, BAST}
(`xfs_mxfs_dlm.c:28137-28141`), with exactly one exemption:
`!mxfs_is_demoter(ip)` — the demoting thread self-reentering during its drain
(trailing `xfs_irele` → evict → `xfs_inactive`). That is a **single thread**,
which cannot be inside its own drain-acquire and its own unlock at once.

**Residual exposure = ICLUSTER.** One `MXFS_LTYPE_ICLUSTER` resource covers a
16KB inode cluster (up to 32 inodes), so demoters of DIFFERENT inodes in the
same cluster are DIFFERENT threads on the SAME CAW resource, and the per-inode
`i_dlm_state` park does not serialize them. ICLUSTER unlocks exist and take the
wall-clock-bounded retry path (`MXFS_CAW_UNLOCK_DEADLINE_MS`).

## FACT D — the unlock's existing mid-unlock re-grant defence, and its hole

Every grant path calls `caw_grant_seq_prebump()` immediately before its slot
CAS (`:3611, :4350, :5159, :6873, :6912`); the **adopt arm** (recognizing a
peer's direct handoff — writes nothing to the slot) calls it at `:3337` when it
decides to adopt. The unlock checks `caw_grant_meta_seq() != rel_seq0` at the
top of each retry (`:5638`) and as the last instruction before its CAS
(`:5984`) → `regrant_abort`.

**Hole:** for the adopt arm the disk bit is set by a PEER's CAS at an arbitrary
time; our prebump only lands when a local thread later *notices* it. Between
the unlock's `:5984` check and its CAS, an adopter's prebump can land unseen
and the unlock's CAS then clears the adopted bit.

Also confirmed (the sess114 open question): the sess135 guard at `:5661-5670`
(`node_held_mode == NL && !waiters && !yield_to` → treat as already released)
does **NOT** cover a grant landing mid-unlock — it fires only when our bit is
in no bitmap, and a fresh grant *sets* the bit, so the retry loop re-reads it
and clears it.

## Open consult (fired at the relay boundary, answer not yet seen)

A RULE-5 consult carrying FACTS A-D was sent asking GPT to rule per item:
(1) accept FACT A and withdraw blocker 2; (2) the correct requirement in its
place — my position is the registry's sound scope is exactly what it does
today, gate `caw_drop_own_waiter`, because XFS's per-resource state machine is
the real enforcement point; (3) the correct blocker-3 rule given `tenure[EX]`
is sticky until eviction (a "refuse to weaken while tenure[EX] > 0" rule
self-deadlocks — only the downgrade would clear it); (4) whether ICLUSTER
concurrency and the FACT D adopt window need the RELEASING op; (5) whether
snapshot-subtract in `lreq_release_all` is still required under FACT B/C.

**Next session: read that answer first** (re-ask if the background task result
is gone — the prompt is reconstructable from FACTS A-D above), then implement
against the corrected ruling. Do not implement blockers 2/3 as sess114 wrote
them.
