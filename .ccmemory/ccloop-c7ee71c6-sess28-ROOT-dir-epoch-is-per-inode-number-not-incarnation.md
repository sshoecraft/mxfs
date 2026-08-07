---
name: ccloop-c7ee71c6-sess28-ROOT-dir-epoch-is-per-inode-number-not-incarnation
description: ROOT PROVEN + FIXED: the CAW dir_epoch belongs to the inode NUMBER, so every staleness compare was cross-incarnation. mxfs.dir_epoch_incarn_gate.
metadata:
  type: project
tags: [mxfs, dlm, dir-epoch, incarnation, D-SILENT-MKDIR-LOSS, rule4, sess28]
---

# sess28 — the dir epoch is a property of the inode NUMBER, not of an incarnation

Build **0.11.243** (`C3D864E1F8AB80753D23D6C`); A/B measured on **0.11.242**
(`C6D909C4133BA6731C55251`).

## The defect

`caw_tombstone_slot()` and `caw_claim_inherit_epoch()` (`dlm/dlm_caw.c` ~897/920)
**deliberately** carry a slot's `dir_epoch` across an idle gap, and
`mxfs_v5_dlm_inode_dir_epoch()` serves it from a per-**resource** `grant_meta`
cache that survives the inode being freed and re-created. So every consumer's

    master_epoch > ip->i_dlm_dir_valid_epoch

compares a **dead incarnation's** handoff lineage against a **live
incarnation's** baseline. Same invalid-comparison class sess27 proved for
`di_gen` in `RELOAD-TYPEFLIP-STALE-SKIP`.

## The trace that proved it (2/caw, test2, ino 2099630, one scoped window)

    119   P9-NLEDGE reset4create ino=2099630              <- incarnation A created
    126   P210-CREATOR-BASELINE site=2 bep=0              <- A published AT EPOCH 0
    ...   P70-BP EXIT=full / P-DIRBAST ...                <- A handed off (slot epoch ->2)
    1363  EVICT-RING-FLAG incore_gen=2916713347 freed_gen=2916713348   <- A FREED
    1383  P9-NLEDGE reset4create ino=2099630              <- incarnation B created
    1410  P195-STALE-BASE-ALREADY-DIRTY grant_epoch=2 valid_epoch=0
            self_created=1 baseline_unset=1 comm=mkdir

B is brand new, created by this node, and at line 1410 is still
`i_dlm_unpublished` — **no DLM grant of its own at all** — yet reads
`grant_epoch=2` out of A's stale grant_meta.

## Why it is a data-loss bug, not noise

The comparison is then *permanently* true for B, and `P32E-DIREPOCH-FENCE`
(`mxfs.dir_epoch_flush_fence`, **ships 1**) skips flushes of B's directory.

**The shipped asymmetry to remember:** the CONSUMER of the baseline ships
ENABLED while the only maintainer that would advance it on a handoff
(`mxfs.dir_epoch_adopt`) ships **DISABLED**, because sess49 proved enabling it
causes an AG double-free and FS shutdown. *A fence with no maintainer eventually
refuses everything.*

## The fix — `mxfs.dir_epoch_incarn_gate` (ships 1; 0 = negative control)

- New field `i_dlm_dir_valid_incarn` = the `i_generation` the baseline was
  established under; stamped at all **11** `i_dlm_dir_valid_epoch` assignment
  sites (5 files), 0 at inode init.
- New predicate `mxfs_dir_epoch_superseded()` (`xfs_mxfs_dlm.c`, declared in
  `xfs_mxfs_dlm.h`) replaces the raw compare in **both** consumers —
  `P32E` (`xfs_inode.c`) and the `P194`/`P195` gate (`libxfs/xfs_dir2.c`).
- Returns false when `i_dlm_unpublished` (no grant for this incarnation).
- On an incarnation mismatch it **re-bases** onto the live incarnation, but only
  while `i_mxfs_self_created` holds (cleared by `mxfs_dlm_bast_notify` on the
  first peer BAST) → no peer update can be laundered (GPT's sess27 constraint).
- **The adopt path is untouched**, so sess49's regression is not in play.

## Paired A/B — one build, knob flipped at runtime, fresh mkfs per arm

| cond | arm | dirent_publish_integrity | P195 | exposure | rebases |
|---|---|---|---|---|---|
| 2/caw | gate=0 | FAIL 1/2 sbm=3 | 3 | 50 | 0 |
| 2/caw | gate=0 | FAIL 1/2 sbm=1 | 1 | 54 | 0 |
| 2/caw | gate=1 | **PASS 2/2** | **0** | 53 | 19 |
| 2/caw | gate=1 | **PASS 2/2** | **0** | 55 | 16 |
| 8/caw | gate=0 | FAIL 7/8 sbm=1 | 1 | 165 | 0 |
| 8/caw | gate=1 | **PASS 8/8** | **0** | 184 | 9 |

`exposure` = `P210-CREATOR-BASELINE`, **deliberately not gated on the fix** —
so the passing arm is provably entering the same state. Every rebase was
`P211-EPOCH-REBASE` with `old_incarn != incarn`, e.g. `ino=2099632 cur_ep=2
old_ep=0 old_incarn=1838689591 incarn=403668081 comm=mkdir`.

Full 2/caw board on the shipped default: **31 of 32 PASS**, `open_defects` the
only red (RULE 6 policy).

**Residual, stated not hidden:** `i_generation` is `get_random_u32()`, so "same
incarnation" is a 32-bit equality with a 2^-32 false match. Not an ordering claim.

## Still open

This resolves the **P195/P194 precursor**, not the byte-exact LOSS
(`nlink=33 visible=31`) that names D-SILENT-MKDIR-LOSS. `P32E` fired **0** times
in every window measured here, so the fence→loss link was not itself exercised.
Next: `sf_mkdir_storm.sh` 60 rounds / 32 nodes, paired on this knob.
