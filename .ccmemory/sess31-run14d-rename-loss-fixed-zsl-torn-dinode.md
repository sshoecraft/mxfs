---
name: sess31-run14d-rename-loss-fixed-zsl-torn-dinode
description: sess31: cache_coherency FIXED (P31 iflush-self-skip retry, DB81AF92, 4× PASS). New blocker: zsl 16-node storm torn BTREE dinode; probe build DC5E59F4…
metadata:
  type: project
---

# sess31 (ccloop 14d31183) — cache_coherency FIXED; zero_silent_loss new blocker

## FIXED: cache_coherency rename-batch loss (build `DB81AF92F7D9A57B9415CF7`)

**Root (RULE-4 proven via journald cross-node realns timeline — dmesg ring WRAPS,
journalctl -k retains; the "0 in dmesg" trap struck AGAIN):**
victim t1's `mkdir -p rename_visibility` ran on self-created parent `.mxfs_test`
(ino 131) via FASTEX, adding `rename_vis→135` to its inline SHORTFORM fork. At
BAST-release the durability loop ran (`drain_ms=70`, in-core `disk_size=61`) but
**`xfs_iflush_cluster` rc==0 means ">=1 inode in cluster flushed", NOT "THIS
inode flushed"** — ino 131 was ILOCK-trylock-skipped (concurrent local stat),
the loop bwrote the cluster WITHOUT the new dirent, set flushed=true, unlocked.
t2's fresh FUA read 9ms later got the old 36-byte fork → t2 double-created
`rename_visibility=10485889` → t1's ino-135 subtree (its 20 create-phase files)
orphaned → 40/240 loss on every node. (sess105's "create-phase bug" reframe ✓.)

**Fix:** in xfs_mxfs_dlm.c release flush loop (~line 2634): after rc==0
bwrite, verify `!XFS_LI_IN_AIL(ip->i_itemp)`; if still in AIL → this inode was
skipped → `P31-RELFLUSH-SELF-SKIPPED` + retry. Verified: 8 diag attempts +
4 consecutive criterion PASSes (old MTBF 2-5 attempts). P31 never fired live
(race timing-dependent) — diagnosis stands on the timeline.

## Gate status (build DB81AF92): criteria 1-12 PASS
mkfs_timing, chk_clean, dkms_install, online_resize, cluster_ops_timing,
wedged_unmount, online_membership, dmesg_clean, cache_caps, posix_semantics(1),
cache_coherency, strong_consistency — all RESULT: PASS this session.

## NEW BLOCKER: zero_silent_loss (16-node dpn=100 storm) — 1590/1600 silent loss

zsl had NOT been re-run since sess17's build. Iter 1: 9 nodes shut down with
`corrupt dinode 131, (btree extents)` at xfs_iread_bmbt_block during xfs_create.

**Proven so far (journald, realns 1781251710.x):**
- Storm dir `wa_iter1` = ino 131, fmt=BTREE (>1500 entries), bmbt leaf at
  daddr 39659208.
- Victim t3: EX grant .394 → fresh FUA dinode `nextents=22` → bmbt re-read →
  hex dump shows a **VALID BMA3 block, owner=131, correct blkno, numrecs=23**.
  Failure = xfs_iread_bmbt_block's `loaded+numrecs > if_nextents` (23 > 22).
- **TORN PAIR: bmbt leaf durable at 23 records, dinode durable at 22.**
- Grower = t7 (tenure .334–.390, grew 22→23, DID flush bmbt:
  P133-BMBT-RELFLUSH ×3, + dinode RELFLUSH + blkdev flush). t3 read 22 only
  4ms later → either t7's dinode iflush wrote stale 22, or a third party's
  stale inode-cluster write (daddr 0x80, hot cluster inos 128-159) reverted
  23→22 in the window.
- **Suspicious: redundant releases** — t7 logged P106-EXREL ×3 (.390/.396/.408)
  for one tenure; the trailing two re-ran the full drain (dinode iflush+bwrite)
  AFTER the slot unlocked and t3 held EX = unlocked write-after-release.
- P133-DIRINO-REVERT (write-side stale-dinode detector in pal/linux/xfs_buf.c
  ~2410) was double-blind: instr-gated AND `di_format==EXTENTS` only.

**Instrument build ready: `DC5E59F421EBE405D06350E`** — P133-DIRINO-WR/REVERT
now fires under `mxfs.dirwr=1` and accepts BTREE dinodes.

## NEXT
1. Deploy DC5E59F4, run `INSMOD_OPTS="dirwr=1" bash zero_silent_loss.sh --iters 1
   --dpn 100 --mode 1` (foreground, ~150s), mine journald for
   P133-DIRINO-REVERT (stack names the producer: xfsaild stale push vs
   redundant-release iflush vs t7 stale in-core).
2. Also investigate the redundant P106-EXREL ×3 per tenure (re-entrant
   bast_process?) — an unlocked release-flush is a clobber weapon regardless.
3. Then remaining gate: crash_consistency, fence_during_write,
   single_node_paired, rsync_paired, scaling_curve(16), posix_semantics(16).
4. Wedged nodes (test10/test12 style "teardown FAILED") → power-cycle via
   `scripts/cluster_reset_n.sh 16` (75s budget) before zsl runs.

## Ops notes
- SSH to nodes: `/src/mxfs/tools/mxfs_sshpass.sh <node> /tmp/.mxfs_pass "<cmd>"`
  (plain ssh as steve fails).
- dmesg ring on VMs ≈2278 lines and WRAPS under probe storms — ALWAYS
  cross-check journalctl -k before concluding "0 hits" (3rd occurrence).
- P106-EXGRANT only logs slow grants; REL>GRANT count asymmetry is partly
  benign (cached re-grants), but same-tenure trailing EXRELs are real.
- mode numbering in probes: req=3 PR/SHARED, req=5 EX.
