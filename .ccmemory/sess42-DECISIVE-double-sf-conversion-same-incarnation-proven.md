---
name: sess42-DECISIVE-double-sf-conversion-same-incarnation-proven
description: sess42 PROVEN (non-perturbing P42-SFCONV, build B8C2149E): dir_reuse loss = node1 converts sf->block TWICE for the SAME incarnation (i_gen=2915315106…
metadata:
  type: project
---

## sess42 PROVEN (non-perturbing) — dir_reuse_coherency loss = DOUBLE shortform->block conversion of the SAME incarnation

### DECISIVE EVIDENCE (build B8C2149E, P42-SFCONV detector — NO disk I/O, does NOT perturb the race; clean dmesg):
Round 15 FAILED (both nodes readdir=186, missing node1_f1..f14). On **test1 (node1)**, ino=131 incarnation **i_gen=2915315106** has TWO P42-SFCONV conversions:
- `[31185.359951] P42-SFCONV ino=131 ... i_gen=2915315106 addname="node1_f12" comm=dd`
- `[31191.408075] P42-SFCONV ino=131 ... i_gen=2915315106 addname="node1_f25" comm=dd`
Same incarnation (i_gen), ~6s apart, both within round-15 create (test1 create-start 31185.337, verify-done 31196.463). Every OTHER round shows ONE conversion per (distinct) i_gen. ⇒ **node1 converts shortform->block TWICE for the same dir incarnation.**

### MECHANISM (now proven, ties together sess36/37 lineage [[sess42-SYNTHESIS-block0-split-is-double-sf-conversion-lineage]]):
1. node1 adds f1..~f12, shortform overflows, xfs_dir2_sf_to_block converts -> allocates block0, writes f1..f14.
2. Between f12 and f25 the in-core dir REVERTS block->shortform (a stale reload/adopt of a shortform on-disk image — P33-FROMDISK-DIRSHRINK class: disk shortform-empty adopted over block-format in-core; the sess90 RELOAD-SIZE-DROP-SKIP guard FAILS to block this case).
3. node1 re-overflows the (reverted) shortform at f25 -> xfs_dir2_sf_to_block AGAIN -> re-allocates/re-inits block0 -> xfs_dir3_data_init ZEROES the block holding f1..f14 ([[sess36-PROVEN-datainit-zeroes-live-block0-root]], the P31E daddr=120 zeroing). node1_f1..f14 durably lost.

This is SELF-INFLICTED on node1 (rank1, the dir owner), driven by a block->shortform reload revert mid-tenure — NOT primarily a cross-node race (though the peer's churn triggers the revert). P-DOUBLEGRANT=0 (no concurrent EX). 

### FIX (RULE 4, next): block the block->shortform REVERT for a multi-node dir with live block-format content. Two places:
1. RELOAD (mxfs_dlm_reload_inode / xfs_inode_from_disk adopt, xfs_mxfs_dlm.c ~6480-6540 RELOAD-SIZE-DROP-SKIP): REFUSE to adopt a SHORTFORM/smaller on-disk image when in-core is block-format with nx>=1 and live size, for the SAME incarnation (i_generation unchanged). The current guard misses block->shortform (fmt change) within one incarnation.
2. CONVERSION (xfs_dir2_sf_to_block): for a multi-node shared dir, before converting, assert the dir was NOT already block-format this incarnation; if a P42-SFCONV already fired for this i_gen (or on-disk is block-fmt same gen), do NOT re-init block0 — adopt the existing block0.
VERIFY: re-run drc_cap2 (now clears dmesg), grep P42-SFCONV for any ino with TWO same-i_gen lines (must be 0) AND drc-FAIL=0 across >=3 runs.

### TREE: B8C2149E = E8C6B4B6 (held-check stall fix KEEP) + P42-SFCONV detector + drc_cap2 dmesg-clear. Detector is KEEP (cheap, decisive, non-perturbing). [[sess42-FIX-held-check-mode-blind-false-negative-PR]] [[dmesg-follow-ringbuffer-staleness-trap-drc-cap2-fix]]
</body>
