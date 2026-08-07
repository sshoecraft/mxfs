---
name: ccloop-c7ee71c6-sess108-handoff-mint-LANDED-and-defects-table
description: sess108: ruling blockers 1+2+7 LANDED (0.11.438, builds clean, NOT deployed) — direct handoff mints, explicit grantee, 64-bit +1 sequence, tombstone…
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, dlm-caw, direct-handoff, defects-sh]
---

# sess108 — the producer half of the sess107 ruling is LANDED

**0.11.438, builds clean, srcversion `DFB2E368EE9A5CA7617E19A`. NOT DEPLOYED,
NOT MEASURED.** Prior: `…sess107-GPT-ruling-direct-handoff-mint-10-blockers`
(the 10 release blockers) and `…sess106-P241-MEASURED-direct-handoff-mints-no-epoch`
(the root).

## What landed — ruling blockers 1, 2, 7 + my tombstone caveat

All in `dlm/dlm_caw.c`.

1. **Blocker 7 — the epoch SOURCE is no longer `s->generation`.**
   New `caw_next_grant_epoch(prev)` → `prev + 1`, skipping 0 forever. A durable
   per-resource 64-bit sequence serialized by the slot C&W. Kills both failures
   of the zero-extended uint32: the 2^32 repeat and the mint-zero at the wrap.
   This is the fix for the ledger entry **D-EX-GRANT-EPOCH-NOT-UNIQUE-TENURE-ID**
   (still OPEN — code-proven only, no test exercises the cause yet).

2. **Blocker 2 — `caw_grant_epoch_update(s, grantee_slot, mode)`.** `ctx` is
   gone from the signature; the grantee is explicit and can never be implied.
   All 6 pre-existing call sites pass `ctx->node_slot` (all self-grants).
   Also switched the EX/PW test to `mxfs_mode_can_write()` (the sanctioned
   sess105 helper) instead of the open-coded `== EX || == PW`.

3. **Blocker 1 — the direct-handoff arm mints.** `mxfs_dlm_caw_unlock_gen`,
   the `mxfs_caw_direct_handoff && !streak_yield` block: the hand-rolled
   `dir_epoch++` / `last_ex_slot = w_slotno` is replaced by
   `caw_grant_epoch_update(new_slot, (uint8_t)w_slotno, MXFS_LOCK_EX)`.
   Same helper as every self-promote — there is now ONE mint policy.

4. **Ruling ordering item — nominee validation before installing.** New
   `caw_handoff_nominee_ok(cur, new)`: `yield_to` must be exactly one bit, the
   slot number in range and != `MXFS_CAW_EX_SLOT_NONE`, and the bit must be a
   registered EX-class waiter **in `cur_slot`** (the image the CAS compares
   against). A rejected nomination is NOT an error — the ticket is left and the
   waiter claims it itself (pre-sess37 path: correct, just slower).

5. **My caveat to the ruling — the tombstone now CARRIES `ex_grant_epoch`.**
   `caw_tombstone_slot` preserves it and `caw_claim_inherit_epoch` restores it
   on a same-resource re-claim. Without this the `+1` sequence RESTARTS at 1
   after every tombstone+reclaim, reintroducing exactly the false match the
   "zero epoch is never valid" rule exists to prevent. Deliberately NOT cleared
   on the `is_free` reset path (which does clear dir_epoch/last_ex_slot):
   monotonic across an inode-number reuse is what prevents a stale record from
   matching the new incarnation.

6. **P6H-HANDOFF now logs `gep=` (the minted `ex_grant_epoch`).** The old line's
   `epoch=` is `dir_epoch` and must not be read as the token — that trap already
   cost sess106 a moment. This is the measurement channel for the verification.

7. Three stale comments corrected (`caw_grant_result_fill`, the KEEP_EX purge
   guard in dlm_caw.c, `dlm_caw.h:747`) — all three asserted "a tombstone zeroes
   ex_grant_epoch", which is no longer true.

## What is NOT done — the remaining blockers, in order

- **Blocker 3 (next up)** — the `P6H-ADOPT` arm (`caw_wait_for_grant`, the
  `reg_gen && gen > reg_gen && waiter-bit-gone && holder-bit-set` block) still
  does `rc = 0; goto out;` with **no `caw_grant_result_fill`**. That is sess106
  defect 1 and it is what P241 measures as `st_unset` on all 32 nodes. Fill from
  the adopted image and validate per ruling item 3: holder bit present, waiter
  bit gone, mode as expected, `last_ex_slot == this node`, `ex_grant_epoch != 0`.
  **Fail closed = DO NOT ADOPT** — fall through and let the normal grant CAS
  self-promote and mint properly (that is "reacquired through a correct
  transition", ruling item D). Never `rc == 0` with a stale/zero token.
- **Blocker 4** — reject write-capable grants with zero/stale epochs; PR must
  expose no write epoch (already true via `MXFS_GAUTH_NONWRITE_MODE`), and every
  PR→EX/PW conversion must mint (the convert path at ~6219 does).
- **Structural defense B** — enforce `rc == 0` ⇒ fully-initialized result: WARN
  at the single exit of the lock/wait paths when `rc == 0 && gres->status ==
  MXFS_GAUTH_UNSET`.
- **Blocker 5** — `xfs/xfs_mxfs_dlm.c:35083` still re-reads the AG token via
  `mxfs_v5_dlm_ag_grant_epoch` as a separate post-acquire I/O into
  `pag->pag_mxfs_grant_epoch`, which `xfs_buf_item_format_segment` stamps
  lock-free into every buffer-log record. Thread the acquire's grant result;
  drop the lookup.
- **Blocker 6** — the adopt-vs-reconcile linearization. GPT's sharpest line:
  *"if the existing abort reconcile can remove a live node's holder based only
  on an abandoned waiter observation, direct handoff is not safe, with or
  without the epoch fix."* Audit `caw_drop_own_waiter`; reconcile must compare
  expected epoch/generation + holder mode, not merely the node bit.
- **Blockers 8/9/10** — mixed-version gate (maps onto D-MIXED-VERSION-UNGATED-REPLAY,
  and a LOCAL module param is insufficient), audit every first-install-EX
  transition, confirm the replayer binds epochs to the right resource
  (the (resource identity, epoch) tuple — never a global scalar).

## Verification owed once blocker 3 lands

Deploy 0.11.4xx to 32/caw, re-measure P241: pass condition is `st_unset → 0`
with the install/advance buckets taking over, `gep=` nonzero and ADVANCING on
P6H-HANDOFF lines, and the dir_reuse/dirent walls unchanged (the handoff is the
pace-setting path — RULE 0).

## Also this session — `defects.sh` output reshaped (USER REQUEST)

Default is now a **showstat-style table, one line per defect**, severity order:
`# | SEVERITY | ID | STATUS | UPDATED | SUMMARY` with a `Total: 25 — 15 critical,
…` line and the board-figure footer. The summary is always truncated (several
ledger summaries run past 700 chars). `UPDATED` regex-extracts an ISO date from
whichever of updated/closed/found/opened has one — the field is free-form, so it
never invents one (`—` when absent).

- **`-d` / `--detail`** = the previous output (summary paragraph + next step).
- `-1` is now an alias for the table; `-f`, `-t`, `-q`, `-j`, `-a`, `-c`, `-s`
  unchanged. A bare id/phrase argument still auto-switches to full entries, but
  an EXPLICIT mode flag now wins over that (tracked by `mode_set`).
