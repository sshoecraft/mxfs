---
name: ccloop-c7ee71c6-sess112-lreq-registry-LANDED-0.11.441
description: sess112: the sess111-ruled per-(node,resource) local request registry is LANDED (0.11.441, builds clean, NOT deployed) + a 4th defect found en route.
metadata:
  type: reference
tags: [mxfs, dlm-caw, blocker6, lreq-registry, step5.3, reconcile]
---

# sess112 — local request registry LANDED (0.11.441), NOT deployed

Prior: `ccloop-c7ee71c6-sess111-GPT-ruling-blocker6-REJECTS-held-table-guard`
(the design ruling this implements — read it first).

**Build: VERSION 0.11.441, srcversion `750BDB5F2A229A3B8438947`, builds clean**
(only the two pre-existing warnings: compiler-differs, `mxfs_dlm_lkt_dump`
missing-prototype). **NOT deployed. NOT boarded. Nothing measured.**
Fleet is still running 0.11.440 / `DF0E1ABC1CEA16331E2DF6C`.

## What landed

All in `dlm/dlm_caw.c` + `dlm/dlm_caw.h`. No XFS-side changes.

**`struct mxfs_caw_lreq`** — one entry per live (node, resource), chained off
`ctx->lreq[MXFS_CAW_LREQ_BUCKETS=1024]` under `ctx->lreq_lock` (a plain mutex;
every caller is already a sleeping context doing LUN I/O, and unlike
`orphan_clock` this table is never touched from `mxfs_dlm_bast_process`).
Fields: `attempts`, `writers`, `tenure[MXFS_LOCK_MODE_COUNT]`, `pin`, and the
owed-cleanup set (`owed_slot`, `owed_holder_mask`, `owed_waiters`,
`owed_waiters_ex`, `owed_fails`).

**CHAINED, NOT DIRECT-MAPPED — deliberately.** `grant_meta` / `slot_hints` /
`orphan_clock` are caches where a collision evicts and the reader falls back
to a safe answer. This is not a cache: a missing entry reads as "no other
local attempt is live", which is exactly the false statement that authorises
the wrongful clear. So eviction is unavailable and **allocation failure
REFUSES the acquisition** (`-ENOMEM`, `P247-LREQ-NOMEM`) — GPT ruling item 6,
never "overflowed and continue".

**Functions:** `lreq_bucket` / `lreq_find` / `lreq_gc` / `lreq_join` /
`lreq_plan` / `lreq_finish` / `lreq_release_all`.

**`caw_drop_own_waiter` is now `int` and takes `(ctx, slot_idx, resource, e,
giveup_mode)`.** It calls `lreq_plan` ONCE up front (mutex is never held
across I/O), then clears only the permitted bits:
- `waiters` only when we are the LAST live local attempt;
- `waiters_ex` when the last WRITE-capable attempt leaves — **even if readers
  remain**. That downgrade is the point: an over-high `waiter_mode` is the
  measured 16-node reader-starvation wedge;
- `holders[giveup_mode]` refused outright when `tenure[giveup_mode] > 0`
  (a committed local tenure owns it — the corruption-class save,
  `ctx->lreq_guard_hits`), and deferred when another attempt is live and may
  be mid-adoption (`ctx->lreq_defer_hits`).

**The observe-to-track window cannot open**, and it does NOT need the ruling's
ADOPTING/CANCELLING state + condvar: an adopter is by construction a JOINED
ATTEMPT for the whole of its validate-and-publish sequence, so `attempts` is
already > 1 before it reads the image it adopts on. The reconciler does not
need to see the adoption, only that somebody else is still in the room.
*(This substitution is MINE, not GPT's — it is the one design decision in this
session that has not been through a RULE-5 consult. Consult it with the real
diff before boarding.)*

**Nothing refused is lost:** it is recorded OWED on the entry and re-collected
by the LAST attempt out (`lreq_finish` → `P246-LREQ-OWED`), which also covers
the symmetric case where two abandoning attempts each see the other live and
both refuse.

**Wiring:** `mxfs_dlm_caw_lock` and `mxfs_dlm_caw_convert` join before any
on-disk registration and call `lreq_finish` at `out:`; `caw_wait_for_grant`
gained an `lreq` parameter and passes it to its timeout reconcile. Tenure is
retired ONLY on a confirmed clear — the unlock CAS success arm, the
"nothing to unlock" arm, `force_release_self` (both arms), and teardown.
`held_mode` prefers `gres->mode` (mode the granting IMAGE showed us holding)
over the requested mode: an acquire may ask PR and find its own EX bit up, and
it is the EX bit a later give-up must not clear. Convert retires `conv_from`
before publishing the new mode.

**Probes:** `P244` (guard counter, via `ctx->lreq_guard_hits`),
`P245-RECONCILE-EXHAUST`, `P246-LREQ-OWED`, `P247-LREQ-NOMEM`,
`P248-LREQ-LEAK` (entries surviving teardown = some release path never told
the registry its bits were gone).

## A FOURTH defect found en route — filed

`D-RECONCILE-SLOT-IDENTITY-UNCHECKED` (**critical**). `caw_drop_own_waiter`
validated only `magic == MXFS_CAW_MAGIC` before clearing bits at a REMEMBERED
slot index — live magic is satisfied by ANY live slot, including one
tombstoned and re-claimed for a DIFFERENT resource, where our node bit is a
live registration for THAT resource. Reachable from two of the three call
sites (grant-wait timeout holds an index up to a full acquire timeout; the
claim-exhaustion site passes an index the acquire may never have registered
on). The function did not even take a `resource` argument, so the check was
unrepresentable, not merely omitted. Fixed in the same change (memcmp against
`resource`); **verification owed**.

## Ledger

29 open of 68, 17 critical. `D-SAMENODE-WAITER-CANCEL-COLLISION`,
`D-RECONCILE-EXHAUSTION-SILENT`, `D-TRACK-PUBLISH-ORDERING` all had their
`next` rewritten to say what landed and what verification is owed; none
closed — RULE 6 needs a test that exercises the cause, and none has run.

## NEXT SESSION — start here

1. **RULE-5 consult with the actual diff**, specifically on the
   "joined-attempt implies exclusion" substitution above and on the
   convert-path tenure move (`conv_from`).
2. **Deploy 0.11.441 to 32/caw and board it.** Baseline to preserve: the
   sess111 census measured `P3A-DEMOTER-SLOWACQ`, `P6H-ABORT-RECONCILE`,
   acquire-timeout, `P-CAWEXH`, `P91-CLAIMEXH` all **0 on every node** against
   ~970 adopts/node — so the new probes should also be ~0 under a healthy
   board, and any nonzero P247/P248 is a bug in this change, not a discovery.
   Watch RULE 0 wall times: the join/finish pair adds a mutex round trip per
   acquire.
3. **Build the test that exercises the cause** — the demoter exemption
   (`!mxfs_is_demoter(ip)` on the `ISTATE_ACQUIRING` park, `xfs_mxfs_dlm.c`
   ~28141 / ~28415) is the natural lever for forcing two live local attempts
   on one resource.
