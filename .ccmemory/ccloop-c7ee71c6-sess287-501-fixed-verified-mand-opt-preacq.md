---
name: ccloop-c7ee71c6-sess287-501-fixed-verified-mand-opt-preacq
description: sess287: D-501 FIXED AND VERIFIED 0.11.503 sv 6ED390FBE6C — mandatory/optional AG preacquire split; dlm_fairness 19s PASS 32/32; rsync_paired+scaling…
metadata:
  type: project
---

# D-501 FIXED AND VERIFIED (sess287, 0.11.503 sv 6ED390FBE6CC511CDFEDA31)

## What landed (per sess286 RULE-5 ruling)
- `mxfs_trans_preacquire_inode_ags` (xfs/xfs_mxfs_dlm.c ~41190) new signature: `(tp, inodes, num_inodes, mand_inodes, num_mand)`.
- MANDATORY AGs (miss → handoff/block/-EAGAIN, unchanged protocol): rename's existing target_ip + RENAME_WHITEOUT wip (both in-trans iunlink), xfs_remove's victim ip (`(tp,&ip,1,&ip,1)` at xfs_inode.c:5945).
- OPTIONAL AGs (src/target dir, src_ip): trylock hit → cached grant registered as before; miss → `P293-PREACQ-OPTSKIP` (pr_info, cap 256) and PROCEED. Optional misses do NOT consume the 8-handoff budget.
- Dedupe seeds mandatory inodes FIRST so a shared AG keeps the stronger class; mand[] flag rides the insertion sort.
- Tripwire `P292-DIRTY-AGWAIT` (pr_warn_ratelimited) at the deep P1-AGWAIT blocking fall-through (xfs_mxfs_dlm.c ~36680, beside P5D): DIRTY trans blocking on peer-held AG = the skipped insurance actually mattered.
- Rename caller xfs_inode.c:6501 builds `mand_ips[2]` = {target_ip, du_wip.ip}.

## Verification (2026-08-14 21:51-21:59Z, 32/caw)
- dlm_fairness PASS 32/32 in 19s/30s (was 0/32). P293 fired ~16/node on the hot dir's home AG; P292=0, P271=0, P290/P13-CLEANRETRY=0 fleet-wide in-window (all 32 swept, windowed per-node by /proc/uptime — boot epochs differ!).
- D-488 birth-suite regression, same build: rsync_paired PASS 32/32 17s/60s; scaling_curve PASS 32/32 36s/90s; probes all zero.

## Traps
- `make clean` deletes tools/ binaries → prep FAIL "mkfs tool not found". Always `make tools` after `make clean`.
- tools/mxfs_sshpass.sh takes BARE hostname (prepends root@ itself); `root@testN` double-prefixes and auth-fails.
- Old P271/P290 lines persist in dmesg across module reloads — window by per-node uptime before attributing.

## Next
dlm_membership + dlm_scaling re-run (BLOCKED node-fault cells), board chunks B–D on .503. 35 open (24 critical).
