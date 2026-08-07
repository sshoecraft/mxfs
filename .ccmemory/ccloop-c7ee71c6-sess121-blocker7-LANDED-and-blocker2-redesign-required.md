---
name: ccloop-c7ee71c6-sess121-blocker7-LANDED-and-blocker2-redesign-required
description: sess121: ruling blocker 7 (force-release precondition) LANDED as an enforced attestation; blocker 2 got a new GPT ruling requiring a real redesign. s…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess121, blocker7, blocker2, stop-ship, forcerel-attest]
---

# sess121 — blocker 7 landed; blocker 2 redesign is specified but NOT written

Build: VERSION still `0.11.441` (landing incomplete, not revved). srcversion
`C3127EAA4E9A2D59061A79D` → `AC4899E877E72D996AEF7B0`. `make modules` exits 0,
no errors, no new warnings. STILL STOP-SHIP — fleet stays on 0.11.440.

Continued D-SAMENODE-WAITER-CANCEL-COLLISION (ledger #16) rather than starting
at #1, same reason as sess119/120: the tree is mid-landing under the sess118
stop-ship ruling and leaving it half-wired is strictly worse.

## Blocker 7 — LANDED

"`mxfs_dlm_caw_force_release_self` needs an EXPLICIT precondition."

The sole caller (`xfs_mxfs_dlm.c` P72 orphan reclaim, via
`mxfs_v5_dlm_inode_force_release_self`) DOES establish quiescence — I verified
the shape by reading it:

- `i_dlm_state == DEMOTING` — `ilock_begin` waits on DEMOTING, so this node's
  acquire fast path is held off; the `MXFS_SET_DEMOTER` claim KEEPS it DEMOTING
  across the scan+clear. → new users blocked.
- `i_dlm_mode == NL` — no local grant believed held; **and this is why mode==NL
  is load-bearing**: a release sets NL only AFTER its Phase-2 durability drain
  (bast_process drains → sets NL → unlocks), so a stuck-DEMOTING orphan at NL
  has already destaged this tenure. A DEMOTING+EX stuck holder may NOT have
  drained and is excluded by the mode test. → writeback drained.
- `ex_holders == 0 && pr_holders == 0 && pin_count == 0` → no dependent users.
- `!work_busy(dwork)` + strikes + demoter age → no live release path.

So the requirement was satisfied — it was just UNEXPRESSED and UNENFORCED, which
is the actual defect: a second caller added later satisfies it by accident or
not at all, and the failure mode is silent corruption across every slot on the
probe chain.

**What landed:** `enum mxfs_forcerel_basis` + `struct mxfs_forcerel_attest` in
`include/mxfs/mxfs_dlm.h`, threaded through
`mxfs_v5_dlm_inode_force_release_self` → `mxfs_dlm_caw_force_release_self`.
`caw_forcerel_precondition()` refuses with `-EINVAL` + `P252-FORCEREL-PRECOND`
(naming `att->site`) on an absent or incomplete attestation. QUIESCED requires
all four evidence booleans; TERMINAL (fenced/shutting down) is the ruling's one
exemption and needs none.

Two placement facts worth keeping:
- The struct lives in `include/mxfs/mxfs_dlm.h`, NOT `dlm_caw.h` — the attesting
  caller is in the XFS layer, which reaches the DLM through the `v5_mount`
  facade and must not include the CAW header. Putting it in `dlm_caw.h` first
  produced `struct declared inside parameter list` warnings and then hard
  errors in `xfs_mxfs_dlm.c`.
- The XFS caller fills the evidence fields **from the values it actually reads
  under `i_dlm_lock`**, not from literals. That is the whole point — a caller
  that hardcodes them has written a false statement, and it should be legible
  at the call site.

The precondition is checked BEFORE the `single_node` early return, so an
attestation-less caller is named even on a mount where the call is a no-op.

## Blocker 2 — new GPT ruling, redesign required, NOT started

See `ccloop-c7ee71c6-sess121-GPT-ruling-blocker2-owed-redesign` for the full
text. Summary of what the next session must build:

1. Target-scoped intent publication + window open in ONE `lreq_lock` critical
   section.
2. **`lreq_plan()` must become PURE** (no owed side effects) — that is what
   actually closes the Q3(b) audit item.
3. `lreq_finish` must NOT start a second clearer while `clr_active != 0`; it
   leaves the published work and wakes the worker.
4. Owed GENERATION per target — my "retraction on disk proof" was ruled unsound
   without it (A's read predates B's newer intent, A erases B's obligation).
5. Retract only on matching target + unchanged generation + a plan that
   CURRENTLY permits discharging it (never retract a bit the plan still refuses
   just because it happens to be clear).
6. **NEW RELEASE BLOCKER: the single overwriteable `owed_slot`** cannot express
   two outstanding targets — keyed per-target records {resource, slot, slot
   generation}, or demote `owed_slot` to a hint and resolve canonically.
7. Dedicated cleanup worker — **NOT the BAST poll thread** (a 1000-CAW loop
   there delays lock revocation and risks dependency cycles). Immediate wakeup +
   periodic fallback scan, bounded dispatch, backoff, escalation that never
   drops the record.
8. Teardown must drain owed work or withdraw membership — stopping the kthread
   is not enough.

Blockers 1 (residual post-validation demotion window; largest, needs XFS-layer
quiescence or a `use_begin`/`use_end` API) and 2 remain open. 3,4,5,6,7,8 and
ruling item (i) are landed.

## Method note

`make modules 2>&1 | grep -E "error|warning:" | head -20` **MASKED a hard build
failure** this session — `head` truncated before the error lines. Always capture
the build to a file and check `$?`, then grep the file.
