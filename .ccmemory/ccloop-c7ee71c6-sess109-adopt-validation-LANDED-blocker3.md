---
name: ccloop-c7ee71c6-sess109-adopt-validation-LANDED-blocker3
description: sess109: ruling blocker 3 + structural defense B LANDED (0.11.439, builds clean, NOT deployed) — the adopt arm validates and fills; reg_epoch is the…
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, dlm-caw, direct-handoff, adopt]
---

# sess109 — blocker 3 (adopt validate+fill) and defense B are LANDED

**0.11.439, builds clean, srcversion `C616B99414D30367BE092A7`. NOT DEPLOYED,
NOT MEASURED.** Prior: `…sess108-handoff-mint-LANDED-and-defects-table` (the
producer half), `…sess107-GPT-ruling-direct-handoff-mint-10-blockers` (the
ruling), `…sess106-P241-MEASURED-direct-handoff-mints-no-epoch` (the root).

All edits in `dlm/dlm_caw.c`. `xfs/` untouched this session.

## Blocker 3 — the P6H-ADOPT arm now validates, then fills

`caw_wait_for_grant()` gained a **`uint64_t reg_epoch`** parameter alongside
`reg_gen`: the slot's `ex_grant_epoch` in the image our *waiter registration*
CAS-ed in. Both call sites pass `new_slot->ex_grant_epoch` (the registration
CAS does not touch the field, so it is the pre-grant value):
`mxfs_dlm_caw_lock` ~4866 and `mxfs_dlm_caw_convert` ~6416.

In the adopt block (`reg_gen && gen > reg_gen && waiter-bit-gone &&
holder-bit-set`), before anything else:

- `ad_held = node_held_mode(cur_slot, ctx->node_bit)` — the mode we ACTUALLY
  hold in that image, never the requested mode (the `caw_grant_result_fill`
  contract; an acquire may request PR while the image shows our EX bit).
- If `mxfs_mode_can_write(ad_held)`, three checks, first failure wins:
  1. `last_ex_slot != ctx->node_slot` → `why=last_ex_slot`
  2. `ex_grant_epoch == 0` → `why=zero_epoch`
  3. `ex_grant_epoch <= reg_epoch` → `why=unminted`
- Any rejection ⇒ **DO NOT ADOPT** (no `rc = 0`). Logs
  `P6H-ADOPT-REFUSE type=… id=… mode=… held=… why=… gep=… reg_gep=… lex=… self=… gen=… reg_gen=…`.
- Otherwise `caw_grant_result_fill(gres, resource, cur_slot, ad_held, true)`
  — from the EXACT adopting image, **reaffirm=1** (this tenure was minted by
  the RELEASER's CAS, not ours). `P6H-ADOPT` now carries `held= gep= reg_gep= st=`.

### Why `reg_epoch` is the load-bearing check (not in GPT's list)

GPT's item-3 list is holder bit / waiter bit / mode / `last_ex_slot == us` /
`epoch != 0`. **All five pass for a pre-sess108 releaser** — the old code set
`last_ex_slot = w_slotno` and left `ex_grant_epoch` at the RELEASING node's
(nonzero) value. `> reg_epoch` is the only available discriminator: the epoch
is a per-resource +1 sequence that (since the sess108 tombstone carry) only
ever increases within one resource lineage, so *strictly greater* means
exactly "a new tenure was minted since we queued". EQUAL = a releaser set our
holder bit without minting (mixed version — this closes the **new-grantee /
old-releaser** half of blocker 8 at the grantee, for free). LESS = the slot
lineage restarted under us. Both fail closed.

### Why refusing does not wedge

Falling through reaches the existing `node_held_mode != NL && !is_compatible`
arm ~15 lines below → **-EDEADLK**. `is_compatible()` does NOT exclude our own
bit, and an EX/PW self-hold is never compatible with an EX/PW request, so the
refusal path always lands there for exactly the modes it can fire on (the
check is gated on `mxfs_mode_can_write(ad_held)`; a PR adopt is
`MXFS_GAUTH_NONWRITE_MODE` and never validated). -EDEADLK routes through
`mxfs_dlm_ilock_begin`'s BAST pipeline: drain + clear the on-disk bit +
`i_dlm_mode=NL`, then re-acquire, where the normal grant CAS mints properly.
That is the ruling's "reacquired through a correct transition".

## Structural defense B — `rc == 0` ⇒ initialised result, enforced

`P242-GRANT-UNSET-{WAIT,LOCK,CONV}` at the single `out:` of
`caw_wait_for_grant`, `mxfs_dlm_caw_lock` and `mxfs_dlm_caw_convert`: WARN
(capped 200) when `rc == 0 && gres && gres->status == MXFS_GAUTH_UNSET`.
The in-memory fast paths (`single_node`, `mxfs_inode_caw_local/_skip`) return
directly and never reach those labels, so they cannot false-trip it.

## Blocker 4 — reviewed, already satisfied

PR never mints (`caw_grant_epoch_update` gates on `mxfs_mode_can_write`) and a
PR result carries `MXFS_GAUTH_NONWRITE_MODE` with `grant_epoch = 0`.
Write-capable + zero epoch is tagged `MXFS_GAUTH_WRITE_ZERO_EPOCH` and is
non-proving. Both PR→EX/PW transitions mint: the compat-add arm in
`mxfs_dlm_caw_lock` (~4749 region) and the convert arm (~6426 region).

## NEXT — blocker 5, fully scoped, no edits made yet

`xfs/xfs_mxfs_dlm.c:35083` still re-reads the token as a SEPARATE post-acquire
I/O. Exact plan (verified by reading, not written):

1. Add `struct mxfs_grant_result *gres` to **`mxfs_v5_dlm_ag_lock`**
   (`dlm/v5_mount.c:4972`) and **`mxfs_v5_dlm_ag_lock_nb`** (`:5045`) —
   prototypes at `dlm/v5_mount.h:345-346`. Both currently pass literal `NULL`
   into `mxfs_dlm_caw_lock`. Call `mxfs_grant_result_init(gres)` at the top of
   each, BEFORE the `!ctx` / `withdrawn` early returns.
2. **Only 3 call sites**, all in one function in `xfs/xfs_mxfs_dlm.c`:
   `34947` (nonblock arm), `34966` (the P1-AGWAIT nb probe), `35048` (the
   blocking fall-through). All three flow into the SAME epoch block at
   `35075-35098`, so one `struct mxfs_grant_result ag_gres` local serves all.
   Order is safe: a failed nb probe re-inits gres, then the blocking call fills it.
3. Replace the `mxfs_v5_dlm_ag_grant_epoch(dlm, pag_agno(pag), &grant_epoch)`
   call at `35083` with the threaded result, and **validate the binding**:
   `mxfs_grant_result_proving(&ag_gres) && ag_gres.kind == MXFS_LTYPE_AG &&
   ag_gres.resource == pag_agno(pag)` ⇒ `ag_gres.grant_epoch`, else 0.
   That resource check is the point — GPT: "reading a nonzero current epoch is
   not enough; it must be tied to the grant THIS acquire returned."
4. TCP keeps working unchanged: `mxfs_dlm_lock` fills nothing, gres stays
   UNSET ⇒ epoch 0 ⇒ fail closed, exactly what the `-ENODEV` return produced.
5. Leave `mxfs_v5_dlm_ag_grant_epoch` itself in place only if another caller
   exists — grep said `xfs_mxfs_dlm.c:35083` is the ONLY one, so delete it
   with its `dlm/v5_mount.h:360` prototype.

Then blocker 6 (adopt-vs-reconcile linearization — audit `caw_drop_own_waiter`),
then 8/9/10.

## Verification owed (unchanged, now including the refuse arm)

Deploy to 32/caw and re-measure P241. Pass condition: `st_unset → 0`,
`gep=` nonzero and ADVANCING on P6H-HANDOFF, `P6H-ADOPT` showing
`st=1 (WRITE_EPOCH)` with `gep > reg_gep`, `P242-GRANT-UNSET-*` silent, and
the dir_reuse/dirent walls unchanged (direct handoff is the pace-setting
path — RULE 0). A nonzero `P6H-ADOPT-REFUSE why=unminted` count on a
uniformly-0.11.439 fleet would mean a mint site is still missing — that is
the measurement that would send blocker 9 back to the top.
