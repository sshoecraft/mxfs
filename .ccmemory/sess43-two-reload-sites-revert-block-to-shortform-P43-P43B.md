---
name: sess43-two-reload-sites-revert-block-to-shortform-P43-P43B
description: sess43: dir_reuse 2/tcp block0 double-conversion has TWO reload revert sites in mxfs_dlm_reload_inode — early dip-check (P43) AND post-spin snapshot…
metadata:
  type: project
---

## sess43 — dir_reuse_coherency 2/tcp: the block→shortform revert has TWO sites; one guard was not enough

### Confirmed (RULE 4) the sess42 root with a targeted fix + measurement
sess42 proved: loss = node1 runs `xfs_dir2_sf_to_block` TWICE for the SAME incarnation (i_gen), re-initing block0 → zeroes node1_f1..f14. The revert block→shortform between the two conversions is a RELOAD adopting a shortform on-disk image.

### FIX1 (build 8E2F4890): P43-DIR-FMTREVERT-SKIP in mxfs_dlm_reload_inode (~line 6713)
Refuse to adopt a shortform on-disk image when in-core is block-format DIR (if_format!=LOCAL) for the SAME incarnation (di_gen==gen). Checks the LIVE `dip` (cluster buffer) BEFORE the `down_write_trylock` spin.
**Result (drc_cap2, 24 rounds): PARTIAL.** P43 fired 8×, but drc-FAIL still occurred. 3 same-incarnation DOUBLE conversions STILL slipped through (i_gen=64444403 f12+f27; 559594266 f12+f25; 2647256890 f12+f28). Failure SIGNATURE CHANGED: rounds 14/16/17 readdir shortfall (183/184/186 of 200); rounds 18-24 readdir=200 (data preserved!) but lookup_fail=9 PERSISTS (leaf-hash holes — likely downstream of a round-17 double-conversion leaf corruption surviving rm-rf via inode/daddr reuse).

### ROOT of the residual (PROVEN via raw timeline, i_gen=559594266 f12→f25 window):
Right before the 2nd P42-SFCONV: `P62-RELOAD-FORK-SHRINK ino=131 incore_fmt=2 incore_nx=1 incore_size=4096 disk_fmt=1 disk_nx=0 disk_size=6` — the destructive shrink runs at a SECOND site in the SAME function (mxfs_dlm_reload_inode), on the post-spin SNAPSHOT (`dip = snap`, line 6993), which the early P43 check (live `dip`, pre-spin) cannot see. Per sess87: a peer rewrites the SHARED cluster buffer DURING the `down_write_trylock` spin (up to 1000 iters, cond_resched), so early `dip` reads BLOCK (P43 passes) while `snap` captures SHORTFORM → P62 → xfs_idestroy_fork + xfs_inode_from_disk reverts in-core to shortform → 2nd sf_to_block.

### FIX2 (build 226E02D6, UNVERIFIED at handoff): P43B-DIR-FMTREVERT-SNAP-SKIP
Same condition as P43 but on the IMMUTABLE snapshot, placed right after `dip = snap` (line ~6995), before xfs_idestroy_fork. Cleanup mirrors RELOAD-VERIFY-BAIL (kfree snap; xfs_buf_relse(bp); up_write(&ip->i_lock); i_dlm_stale=false; return). merge_ours not yet allocated there.

### VERIFY NEXT: drc_cap2; expect P43B fires, ZERO (ino,i_gen) with 2 P42-SFCONV, drc-FAIL=0. Decisive query:
`cat tests/_cap/test{1,2}.log | grep -oE "ino=[0-9]+ .*i_gen=[0-9]+" | grep -oE "ino=[0-9]+|i_gen=[0-9]+" | paste - - | sort | uniq -c | sort -rn | head` — any count>1 == residual double-conversion.
If lookup_fail=9 persists with readdir=200 even after doubles→0, the leaf-hash hole is a SEPARATE bug (sess20 lineage), investigate next. Need ≥3 clean runs for criterion. Soundness of both guards: create-only test never legitimately reverts block→shortform within an incarnation (rm-rf bumps di_gen → excluded). [[sess42-DECISIVE-double-sf-conversion-same-incarnation-proven]]
</body>
