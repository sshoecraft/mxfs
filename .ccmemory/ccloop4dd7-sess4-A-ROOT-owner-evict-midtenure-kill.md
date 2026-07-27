---
name: ccloop4dd7-sess4-A-ROOT-owner-evict-midtenure-kill
description: sess4 ROOT PROVEN+FIXED v0.11.58: mxfs_dir_evict_owned_data_blocks ran MID-TENURE (self-echo gen bump) destroying undestaged dir mods → b57r5 leaf/da…
metadata:
  type: project
tags: [ccloop-4dd7, root-cause, owner-evict, dir-coherency]
---

# ccloop-4dd7 sess4 ROOT #1 — owner-evict mid-tenure kill of undestaged dir blocks (PROVEN, FIXED v0.11.58 = BDEC514F)

## Symptom (b57r5, 5th ladder round on v0.11.57)
test2: `Metadata corruption detected at xfs_dir2_leaf_removename+0x4fc, xfs_dir3_leaf1 block 0x50` →
`xfs_dir_removename rc=-117` (dp=131 name=d2_10) → dirty xfs_trans_cancel in xfs_remove → shutdown →
P-WITHDRAW-RELALL 14 grants. The ONLY corruption exit in removename: `bestsp[db] != bf[0].length`
(leaf tail bests vs data block bestfree — cross-buffer consistency).

## Proof chain (all b57r5_test2.live, 16:06:02)
- test2 held EX(131) CONTINUOUSLY .131→.219 (test1 granted at .130 P51-SENDGRANT gg=5208; test1 BAST .160;
  test2's release reached test1 only at .219 — AFTER the -117 at .218789). test1 never wrote daddr 72/80
  (only P133-DIRINO-WR daddr=128).
- Data block 72 in-core content (P50-RD/P68 fingerprints): fresh platter read at .131844 (fresh=1)
  22@0x400c15 → local rm s19 .165 (21@0x400b86) → local add s16 .179 (22@0xe00c06) → local rm s11 .1959
  (21@0xe00b7a, P9-LFREE) → **REGRESSED to 22@0x400c15 by .201854** (exact .131 platter image; fresh=0).
  Platter unchanged throughout — 4 committed local mods DESTROYED in-core.
- Killer: `P43-OWNEREVICT ino=131 seen=2 evicted=2` at .179754, .195771, .198833 — mxfs_dir_evict_owned_data_blocks
  (xfs_mxfs_dlm.c ~1335) ran repeatedly MID-TENURE. Its kill arm = xfs_buf_item_done (in_ail 1→0) +
  clear XBF_DONE + b_mxfs_dir_gen=0 — matches observed .1988 signature exactly. Skip guard checked
  !DONE/STALE/pin/delwri/DIRTY but NOT undestaged (lseq!=wseq) — header doc PROMISED undestaged-left,
  code didn't implement it.
- P5-UNDEST-SALVAGE resurrections (restore DONE, content intact in b_addr) won kills #1-2; after kill #3 a
  salvage-bypassing read path cold-read the platter between .199070-.201681 → data regressed. Leaf 80 kept
  the modified image (own salvage + P21S-EVICTSKIP-LEAF) → leaf/data divergence → bests mismatch.
- Why mid-tenure: fast-path caller (~22170) re-runs the whole handoff-refresh (reload + drain_evict +
  evict_owned) on EVERY acquire while dir_gen != loaded_gen; a local modify's self-echo gen bump
  (1159→1160 at .165) keeps that true for the rest of the tenure. P51-HANDOFF-UNDERFIRE also shows
  grant-gen advancing spuriously under a continuous hold (hgg=4422 cached=4419 handoff=FALSE).

## FIX (v0.11.58)
mxfs_dir_evict_owned_data_blocks loop guard: added `|| mxfs_dir_buf_is_undestaged(bp)` to the skip arm
(+ P48-OWNEREVICT-DIRTYSKIP print now includes undest/lseq/wseq). Safe: prior-tenure bases are destaged
(Inv 1 drained at our release ⇒ lseq==wseq) so the readdir=799-class evict still runs; only this-tenure
committed-unwritten content is spared. Destaged in-AIL zombies still retired.

## Env note
clyde was rebooted by user 10:43 (wiped /tmp incl. old scratchpad logdir.txt); LIO rebuilt via
scripts/lio_tcm_setup.sh setup; VMs restarted. Logs: tests/logs/vmrig_dialloc_20260724_130107Z.
Ladder: b57r1-r4 CLEAN, b57r5 escalated (this root). difree-ESTALE fix VERIFIED live in b57r3
(P-DIFREE-DBL agino=134 → IFREE-REVALIDATE-SKIP clean, freecount consistent). Ladder resets at b58 (v0.11.58).
