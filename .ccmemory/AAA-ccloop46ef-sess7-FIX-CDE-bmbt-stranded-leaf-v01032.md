---
name: AAA-ccloop46ef-sess7-FIX-CDE-bmbt-stranded-leaf-v01032
description: sess7 mid: v0.10.31 killed oops/wedge (16 nodes clean, FAIL moved to bmbt stranded leaf); v0.10.32 = fence !DONE-undest arm + skip reconcile/stale +…
metadata:
  type: project
---

# sess7 part 2 — v0.10.31 verdict + the stranded-bmbt-leaf root + v0.10.32 fixes C/D/E

## v0.10.31 run (154203Z): FAIL 0/16 BUT the fix-A/B targets fully held
Zero NULL+4 oopses, zero wedges, zero panics, zero strikeouts — all 16 nodes alive+kernel-clean (vs 0/16 WITH dead nodes on v0.10.30). Failure moved to: rounds slow from ~85s to ~280s from r10 (121s barrier lag), test1 (rank1) LOOKUP_ENOENT walls.

## Root chain (fully evidenced on test1, daddr=25118808 = dir 131's bmbt leaf)
1. r9 rm tenure (tenure=10428): fence wrote 13-era fine (P66 comm=rm t=614-619). Then logged 13→12; a peer-BAST modify-evict cleared XBF_DONE mid-tenure.
2. Release fence's undestaged arm REQUIRED XBF_DONE (mxfs_dir_bmbt_scan needs) → !DONE+undest invisible → EX handed away without landing the 12-era. **Fence gap = the loss.**
3. Peers wrote 13→15→14→16 eras from the 13 base (12-delta durably lost). test1's leaf now: undest (lseq=7>wseq=5), stamp=prior-tenure → chokepoint/FUA skip arms fire FOREVER (iflush-hook resubmits ~40Hz → P61/P77 walls flood dmesg+journal), fence can't see it, sess66's promised "stale it" was never implemented.
4. Reads: P91-FUA-SKIP-LOGGED completes reads IN PLACE (BLI attached) then __xfs_buf_ioend runs verify_read over the dirty in-core image (CRC only stamped at write) → manufactured EFSBADCRC "Metadata CRC error" walls (LUN verified VALID by raw read+crc32c on clyde backend /home/steve/disk.img @ (daddr+196688)*512!) → every lookup ENOENT → 121s barrier decay → RULE-0 timeout.
   Same family as sess15 P15I inobt corpse.

## v0.10.32 fixes (build D0A20A10A38858B1AF46DE2)
- **FIX-D (root)**: mxfs_dir_bmbt_scan both predicates: undest arm no longer requires XBF_DONE (only !XBF_STALE). b_addr survives a DONE-clear, write-under-EX is safe (stamp==current at release).
- **FIX-C (heal)**: mxfs_bmbt_skip_preserve_truth now RECONCILES: same-as-LUN → certify destaged (P82); differs+undest → P81-BMBT-SUPERSEDED-DROP (loud loss accounting) + certify + xfs_buf_stale; differs+clean → stale. Ends the 40Hz walls + heals stranded buffers (next access cold-reads peers' era). Implements sess66's promised stale.
- **FIX-E**: b_mxfs_inplace_read flag (xfs_buf.h) set by P91 before emulated ioend; __xfs_buf_ioend read branch consumes it and SKIPS verify_read (in-core authoritative image must not be CRC-checked).

## Watch in next run (156xx+)
- P81 fires = fence STILL leaking somewhere (D incomplete) — each P81 is a real lost delta.
- P82 = benign certify.
- Expect: no P61/P77 walls, no CRC errors, rm phase back to ~0-1s, rounds ~85s.
- Note: journal replay of superseded skipped items at crash recovery is a pre-existing hazard (out of scope, noted).
