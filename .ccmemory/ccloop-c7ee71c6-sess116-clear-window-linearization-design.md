---
name: ccloop-c7ee71c6-sess116-clear-window-linearization-design
description: sess116: the MINIMAL linearization that satisfies the sess115 ruling — clr_active/clr_seq/pub_seq on the lreq entry; only memory-only grants and rele…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess116, samenode-waiter, design, implementation-plan]
---

# sess116 — the clear-window linearization (implements the sess115 ruling)

Rulings this implements: `…sess115-GPT-ruling-blockers-2-3-WITHDRAWN-two-new`
(blocker 1's surviving linearization half + NEW blocker 2 provisional
adoption). Facts it rests on: `…sess115-cached-lock-model-invalidates-blockers-2-3`.

**Design only — NOT written to the tree at the time of this note.**

## The reduction (this is the load-bearing argument)

The ruling requires: *a destructive disk clear must be linearized against local
grant/join/adopt publication*. Enumerate every way a local grant becomes
believed-held, and ask what already linearizes it against a clear CAS:

| publication site | linearized today? |
|---|---|
| slow-path grant CAS (`:4350`, `:5159`, `:6873`, `:6912`) | **YES** — it writes the slot, so a concurrent clear CAS miscompares and retries. Plus `others >= 1` protects it from give-up plans until `lreq_finish`, since the grantee is a joined attempt for the whole window. |
| already-held shortcut (`:4680`, `:4790`) | **NO** — memory-only, writes nothing. Partially covered by `caw_grant_meta_store_unless_releasing` + `caw_release_mark`, but `grant_meta` is a **no-chain hash** (`MXFS_CAW_GRANTMETA_SIZE`) so a colliding foreign resource can evict the `releasing` mark. Aliasing hole. |
| direct-handoff adopt arm (`:3337`) | **NO** — the peer's CAS set the bit; we write nothing (FACT D). |
| `lreq_release_all` after the unlock CAS | **NO** — blanket `memset(tenure)` eats a tenure published after the release began. |

So the fix surface is exactly three memory-only publications plus
`release_all`. Everything else is already linearized by the disk CAS. This is
why the big op-state protocol (CANCELLING/RELEASING/ADOPTING with blocking) is
not needed — a **validation** is enough and is cheaper.

## The construction

Add to `struct mxfs_caw_lreq` (`dlm_caw.c:~1578`):

```c
    uint32_t clr_active;   /* destructive clear windows in flight */
    uint64_t clr_seq;      /* committed destructive clears (monotone) */
    uint64_t pub_seq;      /* tenure publications (monotone) */
```

- `lreq_clr_begin(ctx, resource, &pub_seq0)` — find-**or-create** the entry
  (creation is required: otherwise a `lreq_join` racing in mid-window would
  snapshot a fresh entry with `clr_active == 0` and publish through the clear),
  `clr_active++`, `pin++`, return `pub_seq` in the out-param.
- `lreq_clr_end(ctx, e, committed)` — `if (committed) clr_seq++`,
  `clr_active--`, `pin--`, `lreq_gc`, `cond_broadcast`.
- `lreq_clr_snap(ctx, resource, &s)` — capture `{seq, quiet = (clr_active==0)}`
  at the moment the slot image is read.
- `lreq_clr_still_good(ctx, resource, &s)` — `s.quiet && e && e->clr_active==0
  && e->clr_seq == s.seq`. No registry ⇒ true (legacy).

**The gc race cannot bite the snapshot:** every publication site runs inside
`mxfs_dlm_caw_lock`/`_convert` after `lreq_join`, and `lreq_gc` refuses to free
an entry with `attempts != 0`. So the entry is stable and non-NULL across
snapshot→validate.

## Where each piece goes

1. **`caw_drop_own_waiter`** — open a window after the initial plan says there
   is work; **re-derive `lreq_plan` on every retry iteration** (the plan is
   currently evaluated once, so a tenure published between the plan and a
   post-miscompare re-read is not seen); `lreq_clr_end(committed = a clear CAS
   actually landed)`. If the window cannot be opened (alloc failure with a
   registry present) → refuse the clear and record owed (fail-closed).
2. **`mxfs_dlm_caw_unlock_gen`** — `lreq_clr_begin` at entry next to the
   existing `caw_release_mark(true)`; `lreq_clr_end` at `out:`. Capture
   `pub_seq0` there. On alloc failure proceed under the legacy
   `caw_release_mark` exclusion and log — refusing an unlock wedges the cluster
   (BAST storm) and would be a worse trade than the residual aliasing hole it
   already has.
3. **`lreq_release_all(ctx, resource, pub_seq0)`** — clear `tenure[]` only when
   `e->pub_seq == pub_seq0`; otherwise keep it, bump a counter, log
   `P248-LREQ-REL-KEPT`. Both orders are then correct: a publication before
   `release_all` is a real grant and must survive; one after is unaffected.
   Fail-closed residue (stale-high tenure) only makes later plans refuse — a
   liveness leak the owed mechanism collects, never a corruption.
4. **`lreq_finish`** — bump `pub_seq` with the tenure raise, in the same
   critical section as the `attempts--` (unchanged requirement); **blocker 6**:
   if this call would make us the last attempt (`e->attempts == 1`) and
   `e->clr_active != 0`, wait on `ctx->lreq_cond` **before** decrementing, so
   the in-flight clearer keeps seeing `others >= 1` and cannot orphan owed work
   it has not recorded yet; then decrement and evaluate owed. Bounded: clear
   windows are bounded by the CAS retry loop.
5. **Shortcut arms ×2 and the adopt arm** — `lreq_clr_snap` right after the
   slot read that produced `cur_slot` (acquire loop: after `find_slot_skip` at
   `:4176` / the `our_mode` derivation at `:4580`; wait loop: after `read_slot`
   at `:3102`); `lreq_clr_still_good` immediately before `rc = 0; goto out;` —
   on failure `continue` the loop. That is the ruling's "stays provisional and
   retries after". Side effects already taken (`caw_grant_meta_store`, the
   `grant_seq` bump) are harmless on retry — a seq bump only makes a concurrent
   unlock abort, which errs toward leaving the bit set.

## Blocker 7 is already satisfied

The ruling's holder test — `others == 0 && tenure[m] == 0 for every m in the
mask` — is already what `lreq_plan` does, because the clear touches exactly one
holder bitmap (`giveup_mode`). No change owed there.

## Still owed after this (unchanged from the sess115 ruling)

- NEW blocker 1: **ICLUSTER resource-granularity quiescence** — an XFS-layer
  fix, not reachable from `dlm_caw.c`.
- Audits: every AG admission path observes `pag_dlm_demoting`; every 1:1 inode
  admission path observes `i_dlm_state`; any generic/direct CAW path bypassing
  the XFS gates.
- Blockers 4/5/8 (debt: never drop a record, real claim cookie, wall-clock
  deadlines), 9 (post-upgrade old-holder-bit residue), 10 (withdrawal fences
  local I/O first).
- Doc fix: stop naming `tenure[]` as if it meant references — it is
  epoch-scoped historical accounting; the only sound use is the fail-closed
  "this node was granted m in the current cached epoch" predicate.
- Closure test (RULE 6) is still the sess113 debugfs exerciser with its
  negative control. A green board cannot close this.
