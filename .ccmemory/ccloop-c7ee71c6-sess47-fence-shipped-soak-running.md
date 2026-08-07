---
name: ccloop-c7ee71c6-sess47-fence-shipped-soak-running
description: sess47: 0.11.377 = REAP-IFREE fix (VERIFIED) + inocl time-travel fence default-ON (param inocl_fence); soak cycles running; P53 armed as falsifier
metadata:
  type: project
---

# sess47 state @ 0.11.377 (srcversion C4B4990D457D8BEA45793F2)

## Shipped this session
1. **D-REAP-IFREE-EFSCORRUPTED-SHUTDOWN-372: FIXED AND VERIFIED (0.11.375).**
   mxfs_ifree_unlinked_preflight in xfs/xfs_inode.c (before xfs_inactive_ifree's xfs_ifree; GPT-hardened: nonblocking predecessor PIN — igrab live / iget-recycle reclaimable / -EAGAIN mid-evict = clean-cancel skip; pin released after AG DLM drop). Probes P-UNLREM-* permanent in xfs/libxfs/xfs_inode_util.c. Deterministic repro tests/reap_midlist_repro.sh (scenario A: reclaimed-chain mid-list; scenario B: igrab arm w/ local-fd-live prev). 374=REPRODUCED → 375/376/377=CLEAN every run; matrix 9/9 ×3; aged cycles clean ×2.
2. **Inode-cluster time-travel fence (0.11.377, default ON, mxfs.inocl_fence 0644).**
   pag_mxfs_inocl_wr_epoch (xfs_ag.h) stamped at cluster write completion (pal/linux/xfs_buf.c ~2295); cold cluster read inside unflushed window → P-INOCL-COLDREAD print + coalesced device flush (sibling of sess6 P143 agmeta fence; the agmeta ops list deliberately still excludes clusters). Exposure measured: 25+ cold-in-window reads/cycle across 4 nodes on 376 report-only. rsync_paired 18s post-fence (baseline 23-28s) — no perf cost.
   **P53-IUNLINK-MISMATCH is the falsifier: if it fires with fence=1, the arm is wrong/incomplete.**

## Producer case file
memory `ccloop-c7ee71c6-sess47-rsync-rename-producer-fossil-nextunlinked` + ring test2:/root/transcommit_incore_1785706689.dmesg (fatal P53 old_ptr=0x117 dip_gen==i_gen; 2 siblings absorbed by IDEMPOTENT carve-out). P-PINNED-REREAD=0 and P-BUF-FREE-WITH-ITEMS silent → eviction arms disfavored; cache-bypass FUA time-travel is the live arm.

## Soak protocol (continue until ≥4 aged cycles clean on 377)
cycle = `timeout 160 ./run.sh 32 caw rsync_paired` → `timeout 480 tests/openunlink_matrix.sh test1 test2 test3` → fleet sweep `dmesg | grep -cE 'P53-IUNLINK|Shutting down|error -117|P-UNLREM-NOPREV'`. STANDING RULE: on any shutdown, `dmesg > /root/<tag>.dmesg` BEFORE recovery.

## Queue after soak
knob=1 (icluster_dlm=1) matrix on 377; crash_consistency clean-window (tests/clean_load_run.sh, quiet stretch); GPT items 2-4 for the icluster campaign; FOREIGN-REPLAY; TCP rig arm. Ledger: 11 OPEN of 39 after -372 closure (5→4 criticals).
