---
name: ccloop-c7ee71c6-sess113-lreq-verified-code-facts-and-design
description: sess113: the two code facts that make the CANCELLING-vs-JOIN reduction sound, the exerciser design, and an unverified waiter_mode asymmetry.
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess113, code-facts, test-design]
---

# sess113 — verified code facts for the lreq rewrite, and the exerciser design

Companion to `…sess113-GPT-ruling-lreq-registry-STOP-SHIP` (the ruling).
**Tree unchanged this session except `tests/criteria/OPEN_DEFECTS.json`** —
still 0.11.441, srcversion `750BDB5F2A229A3B8438947`. Fleet still on 0.11.440.
0.11.441 **must not be deployed as it stands**.

## Two facts VERIFIED by inspection — they shrink the required fix

**FACT 1 — adoption runs on the attempting thread.** `P6H-ADOPT` fires at
`dlm/dlm_caw.c:3348`, inside `caw_wait_for_grant()`, which is called by the
acquiring/converting thread itself. There is **no callback thread that adopts
on an attempt's behalf**. Therefore the ruling's *hole 2* — one logical attempt
with a grant-callback adopting while its own timeout cancels — is
**inapplicable to this codebase**: for a given attempt, adopt and cancel are the
same thread, sequentially. This is what lets the fix be
**CANCELLING-vs-JOIN exclusion** rather than the full
WAITING/ADOPTING/ACTIVE/CANCELLING/RELEASING machine.

**FACT 2 — the `writers` mode→bitmap invariant holds.** `waiters_ex` is set at
`dlm_caw.c:5292` (acquire) and `:6921` (convert), both guarded by exactly
`(mode == MXFS_LOCK_EX || mode == MXFS_LOCK_PW)` — which is exactly
`mxfs_mode_can_write()` (`include/mxfs/mxfs_dlm.h:47`). So the registry's
`writers` counter tracks precisely the set of local requests `waiters_ex`
represents, and the `waiters_ex` DOWNGRADE is well-founded on that axis.
**Replace the two open-coded conditions with `mxfs_mode_can_write()`** so they
cannot drift from the counter.

**FACT 3 — `recompute_waiter_mode()` is a pure derivation.** It reads only
`slot->waiters` and `slot->waiters_ex` and never uses the previous
`waiter_mode` as an input hint, so the ruling's re-elevation concern does not
apply. It returns only NL / EX / PR.

## UNVERIFIED, worth a look — waiter_mode setter/recompute asymmetry

The *setters* (5294, 6923) do a monotone raise
`if (mode > new_slot->waiter_mode) new_slot->waiter_mode = mode;` over the FULL
mode enum, while `recompute_waiter_mode()` collapses to NL/EX/PR only. A CR/CW
waiter therefore raises `waiter_mode` to its own mode, and the next reconcile or
unlock by ANY node silently rewrites it to PR. Not obviously corruption (grant
compatibility is decided from the holder bitmaps, not `waiter_mode`; the
consumer is `defer_for_waiter`), but the two functions disagree about what the
field means. **Check the enum order and what `defer_for_waiter` does with a
non-EX/PR value before deciding whether this is a defect.**

## The RULE-6 closure test — why the board cannot be it

sess111 measured on all 32 nodes at 0.11.440: `P6H-ABORT-RECONCILE = 0`,
`P3A-DEMOTER-SLOWACQ = 0`, `P-CAWEXH`/`P91-CLAIMEXH = 0`, zero
"disk lock acquisition timed out". **The reconcile arm is never entered under a
passing board**, so a green board proves nothing about this defect and RULE 6
will not accept it.

**Build a deterministic exerciser instead.** A debugfs trigger under
`mp->m_debugfs` (idiom: `xfs/xfs_mxfs_dlm.c:43024`, `DEFINE_SHOW_ATTRIBUTE`;
the dir is created at `pal/linux/xfs_super.c:2034`) driving the registry
against a **real slot on the real LUN** — no mock, the sequencing is the
harness. It must replay:

- **A** — two joined attempts, one defers holder-clear as owed, the other is
  granted and publishes; assert the granted holder bit **survives** the owed
  pass.
- **B** — plan staleness: canceller's plan computed while alone, tenure commits
  during its retry loop; assert the bit **survives**.
- **C** — a thread joins between `lreq_finish`'s decrement and the deferred
  pass; assert its bits **survive**.
- **NEGATIVE CONTROL** — a single attempt gives up with nothing else live;
  assert the bit **IS cleared**. Without this, "the bit survived" is
  indistinguishable from "the test never ran", and the whole exercise is
  vacuous (cf. `ccloop-c7ee71c6-sess27-three-vacuous-evidence-bugs-in-the-board`).

## Ledger

Four entries had sess112 next-steps claiming the fix had LANDED with only
verification owed. All four rewritten this session to record the STOP-SHIP:
`D-SAMENODE-WAITER-CANCEL-COLLISION` (carries the full implementation design),
`D-RECONCILE-EXHAUSTION-SILENT`, `D-RECONCILE-SLOT-IDENTITY-UNCHECKED`,
`D-TRACK-PUBLISH-ORDERING`. Ledger unchanged at **29 open of 68, 17 critical**.
A backup of the pre-edit file is at `tests/criteria/OPEN_DEFECTS.json.backup`.
