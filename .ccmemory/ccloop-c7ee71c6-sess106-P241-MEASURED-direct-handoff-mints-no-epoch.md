---
name: ccloop-c7ee71c6-sess106-P241-MEASURED-direct-handoff-mints-no-epoch
description: sess106: 0.11.437 DEPLOYED + P241 MEASURED — the NONE population is ROOTED. Direct EX handoff grants without minting ex_grant_epoch and returns no gr…
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, dlm-caw, root-cause]
---

# sess106 — the sess104 NONE population is ROOTED (two defects)

**0.11.437 (`CF3F5A492DC3B80F80761B3`) DEPLOYED to 32/caw and MEASURED.**
Prior state: `ccloop-c7ee71c6-sess105-refusal-split-and-authtry-LANDED`.

## Board lap — no RULE-0 regression, 4/4 PASS

| criterion | sess106 | sess104 baseline | budget |
|---|---|---|---|
| rsync_paired | 14s | 16s | 60s |
| cache_coherency | 23s | 23s | 60s |
| dir_reuse_coherency | 113s | 103s | 120s |
| dirent_durability | 63s | 64s | 240s |

All 32/32 nodes pass each. dir_reuse +10s at hostload 15.08 — inside budget,
watch it, not yet a signal.

## P241 fired on ALL 32 nodes with one unanimous shape

    P241-AUTHTRY ino=… mode=5 try=16 try_mode=0 try_ep=0
                 try_line=26492 try_gen=1 gen=1 line=32350 unpub=0

    P241-AUTHTRY nonewr_samegen=7117 nonewr_stalegen=0 by_try: st_unset=7117   (test1)
    P241-AUTHTRY nonewr_samegen=8    nonewr_stalegen=0 by_try: st_unset=8      (every other node)

Decoded — every field is discriminating:

- `try=16` = `MXFS_AUTH_TRY_STATUS_BASE + MXFS_GAUTH_UNSET`. **The grant result
  was NEVER FILLED.** Not a read grant (`st_nonwr`=18), not a zero-epoch write
  grant (`st_wrzero`=19). Unfilled.
- `try_mode=0 try_ep=0` — consistent: `mxfs_grant_result_init` values.
- `line=32350` = `mxfs_dlm_inode_init()`. The last SUCCESSFUL authority
  transition on these inodes is **inode allocation**. No install ever succeeded.
- `try_gen == gen == 1` and `nonewr_stalegen=0` fleet-wide → the auth generation
  never left its init value, so **no revoke ever happened**. This KILLS the
  sess104 ruling's leading hypothesis (backstop revoked, next acquire failed to
  reinstall) and its "missing post-revoke retry" row.
- `mode=5` = `MXFS_LOCK_EX` at dirty time. We genuinely hold EX and stamp NONE.
- `try_line=26492` = the non-routed arm of the inode acquire,
  `mxfs_dlm_authority_install(ip, &gres, gen_snap, false, __LINE__)` immediately
  after `mxfs_v5_dlm_inode_lock*()` returned **rc == 0**.

So: an acquire SUCCEEDS and produces no grant result at all. This is a row the
ruling's classification table did not have.

## Defect 1 — the adopt path returns rc=0 without filling the result

`caw_wait_for_grant`, **dlm/dlm_caw.c:2756-2794** (the `P6H-ADOPT` arm). When the
slot generation advanced past our registration, our waiter bit is gone, and our
holder bit at the requested mode IS set, we were granted by someone else. It does
`caw_grant_seq_prebump` + `track_held` + `caw_grant_meta_store`, sets `rc = 0`
and **`goto out` with no `caw_grant_result_fill`**. Init values survive → UNSET.

Audited exhaustively: it is the ONLY rc==0-without-fill exit reachable on the
rig. All four `rc = 0` sites in `mxfs_dlm_caw_lock` (3952 claim-empty, 4102
already-held, 4208 mode-subsumes, 4589 compat-add) fill; the wait path's other
exits (3053, 3165) are error/timeout. The entry early-returns that skip the fill
(`mode==NL`, `single_node`, `mxfs_inode_caw_skip/local`) are all off at 32/caw.

Rig rate: **463–936 P6H-ADOPT per node.** Hot path, not a corner.

## Defect 2 (the serious one) — direct EX handoff mints NO grant epoch

`mxfs_dlm_caw_unlock_gen`, **dlm/dlm_caw.c:5148-5170**, guarded by
`mxfs_caw_direct_handoff` (**default 1**, dlm_caw.c:113). The RELEASER promotes
the nominated waiter itself:

    new_slot->holders_ex |= wbit;        /* grantee's EX bit, set by the releaser */
    new_slot->waiters &= ~wbit;
    new_slot->waiters_ex &= ~wbit;
    new_slot->yield_to = 0;
    if (w_handoff) new_slot->dir_epoch++;
    new_slot->last_ex_slot = (uint8_t)w_slotno;

It maintains `dir_epoch` and `last_ex_slot` — and **never touches
`ex_grant_epoch`**. Compare `caw_grant_epoch_update()` (dlm_caw.c:940-959), which
every self-promote CAS calls:

    if (mode == EX || PW) {
        if (handoff) s->dir_epoch++;
        s->last_ex_slot   = ctx->node_slot;
        s->ex_grant_epoch = s->generation;   /* <-- ABSENT from the direct handoff */
    }

**Proof it is the only writer:** `grep -rn "ex_grant_epoch *=" --include=*.c
--include=*.h .` over the whole tree returns exactly ONE assignment,
dlm_caw.c:956, inside `caw_grant_epoch_update`. The direct-handoff block does not
call it. The PR batch-promote at 5119-5147 has the same shape (benign for PR —
`mxfs_mode_can_write(PR)` is false — but the EX arm is not).

Consequence: after a direct EX handoff the slot's `ex_grant_epoch` still names
the **RELEASING node's ended tenure**. Live on the rig: `caw_direct_handoff=1`,
**1502 P6H-HANDOFF on test1**, 159-191 on the others. (The `epoch=` field in the
P6H-HANDOFF line is `dir_epoch`, NOT `ex_grant_epoch` — do not read it as
evidence the grant epoch moved. `gen=456 epoch=31` is generation vs dir_epoch.)

### Why the obvious fix is WRONG

Filling `gres` from the adopted slot image at the P6H-ADOPT site — mirroring the
`reaffirm=true` already-held fill at 4098 — would stamp this node's durable write
images with the **previous node's grant epoch**. That is precisely the false-
attribution failure the sess96 ruling (`…sess96-GPT-ruling-step5.3-producer-
REJECTS-cache`) was written to prevent. Defect 2 must be fixed FIRST, or defect
1's fix manufactures false authority.

The two are one root: **the direct handoff transfers a tenure without minting the
tenure's identity, so the grantee has nothing true to install.** It is a producer
defect in exactly the seam step 5.3 is about. It also means every existing
consumer that reads `ex_grant_epoch` to name the current EX tenure has been
reading a stale value on every directly-handed-off grant since the direct-handoff
optimization landed.

## Next steps, in order

1. **RULE-5 consult before implementing** — the fix has real hazards and the
   sess96 ruling already rejected one epoch-source design. Questions to put:
   can the RELEASER legitimately mint the grantee's epoch (it holds the CAS, but
   `caw_grant_epoch_update` derives the epoch from `ctx->node_slot`, i.e. the
   wrong node)? Does `s->generation` remain a sound epoch source when the
   minting CAS is not the grantee's? What happens on abort/reconcile of a landed
   direct grant? Does the PR batch arm need the same treatment for a later
   PR→EX conversion? Is an ADOPTED grant acceptable as durable write authority
   at all, or must the grantee re-CAS to mint its own epoch (costing the
   handoff's entire performance benefit — the direct handoff exists to kill a
   ~900ms 9-node admission storm, see the 5109-5119 comment)?
2. Implement, build, deploy, re-measure P241 — the pass condition is `st_unset`
   going to 0 and the `install`/`advance` buckets taking over, with the
   dir_reuse/dirent walls unchanged (the handoff is the pace-setting path).
3. Then the sess104 ruling's item 4 (centralized release-publication primitive),
   still unstarted.
