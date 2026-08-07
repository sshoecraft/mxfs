---
name: ccloop-c7ee71c6-sess48-CLMERGE-ROOT-PROVEN-site5
description: sess48 ROOT PROVEN: in-core fossil reverter = mxfs_iflush_cluster_merge_dirs bli_dirty save/restore of di_next_unlinked; fix = site 5 overlay (0.11.3…
metadata:
  type: project
---

# sess48: THE fossil reverter found — clmerge bli_dirty save/restore

## RULE 4 chain that pinned it
1. 390-c1 P-IUNLSTORE-WRSITE specimens: outgoing cluster write carried fossil with record LIVE — state `pin=0 delwri=0 bli=0 in_ail=0 comm=xfsaild/dm-1` (test2, daddr=37678384/37678288).
2. Grep all `di_next_unlinked` writers → `xfs_inode.c` mxfs_iflush_cluster_merge_dirs (P-CLMERGE machinery, runs from xfsaild iflush-cluster under the buffer lock): two `memcpy(dbuf, ddisk, inodesize)` sites (DEADINCARN + restore arms) installed the coherent-disk-read image wholesale, restoring the buffer's nu ONLY `if (bli_dirty)`.
3. bli_dirty is BUFFER-level `(bli->bli_flags & XFS_BLI_DIRTY)`: after checkpoint the BLI detaches ⇒ bli_dirty=0 ⇒ platter's pre-write nu installed in-core (fossil) ⇒ xfsaild destages it (matches WRSITE bli=0 exactly) ⇒ (pre-v4) completion stamped wr_epoch ⇒ lazy drop killed the record ⇒ P53. The sess47 TAIL7 "committed iunlink write vanishes after bli detach" shape, now at line level.
4. Two latent extra defects in the same lines: (a) restore WITHOUT xfs_dinode_calc_crc — nu IS inside the di_crc region (upstream xfs_iunlink_update_dinode recomputes every time; the old sess44 comment claiming "outside di_crc region" is WRONG) ⇒ CRC-invalid slots written (historical EFSBADCRC/P110 noise candidate); (b) buffer-level flag could restore OUR stale nu over a FOREIGN slot's fresher disk value (cross-node fossil writer invisible to our store).

## Fix (0.11.391, fleet-deployed, guards clean)
- Removed both save/restores (+ dead bli/bli_dirty locals; sess44 comment updated in place).
- **Install site 5**: after the merge loop, one `mxfs_iunl_store_overlay(mp, xfs_buf_daddr(bp), b_length, b_addr, BBTOB)` — store = exact per-slot truth (live same-gen record → committed value +CRC; else disk stands: foreign slots, retired values, dead incarnations).
- Discrim hardening: FUA leg skipped when `mxfs_fua_disable=1` (fleet default) — site 5 runs in xfsaild-under-buffer-lock = the sess113 forced-FUA drain-wedge vector; plain-only verdicts IN/NOT-IN-TARGET-CACHEVIEW.

## Verification state
- 391-c1 (marked sweep): bad=0, overlays=0, wrsite=0, fossilwr=0, discrim=0 — first fully-quiet cycle of the campaign.
- Promotion bar: ≥4-6 marked clean cycles (historical fatal rate ~1/2 cycles on test2) + matrix + reap guard each ~2 cycles. WRSITE>0 = another reverter exists; FOSSILWR>0 = regression alarm.
- Sweep tool: `tests/iunl_soak_sweep.sh <mark> [n]` (single awk pass/node; markers `echo 'MXFS-SOAK-MARK <mark>' > /dev/kmsg` per node — dmesg persists across preps, raw greps count prior builds).

## Context
0.11.391 fleet 32/32. 11 defects OPEN of 39 (4 critical) — this campaign targets the P53/D-RSYNC-RENAME family head. v4 (site 4 write-side overlay + payload-verified retire w/ gen-mismatch-stamps rule) stays as permanent belt-and-suspenders.
