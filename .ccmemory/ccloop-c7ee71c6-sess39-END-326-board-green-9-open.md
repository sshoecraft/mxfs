---
name: ccloop-c7ee71c6-sess39-END-326-board-green-9-open
description: sess39 END: 0.11.326 FULL BOARD GREEN (3rd); dir_reuse DISPROVED-as-mxfs (rig SSD proven); RELBAR + EVICT-RETENTION-EX-LEAK both FIXED AND VERIFIED;…
metadata:
  type: project
---

# sess39 END — 0.11.326 (srcversion 5FFAE4D4224A9F250649758)

## Closed this session (net 9 OPEN, from 9 at entry via +3 found, -2 fixed, -1 disproved)
1. **D-DIR-REUSE-COHERENCY-32-FLAKY: DISPROVED as mxfs defect.** Run-over-run decay (fresh 8-9r PASS → plateau 7r → 25min-idle recovery; 3 laps on schedule) = host storage path: pure-host dd-dsync probe p90 26→95ms max→1806ms during plateau; nvme w_await p50 1.19→4.29 below the whole stack; table/CPU/log-counters all flat. Rig = 990 EVO Plus 93% full + myse (user process) 1.19TB/9h ambient + game (never touch Wow/worldserver/myse — user's live processes). RIG RULE: pace measurements only from ≥25min-idle storage state.
2. **D-EVICT-RETENTION-WIRE-EX-LEAK (was D-CRASH-REJOIN-STALE-OWN-EX-SLOTS): FIXED AND VERIFIED in 326.** sess37 retention trusted in-memory mode; wire held EX while memory said PR (live: 200-file bulk repro → 190 orphan wire-EX gen=1; P6R-RETAIN fired for those inos; 13.4K historical orphans ~435/node from rsync_paired board files). Fix: retain only on wire-confirmed PR (mxfs_v5_dlm_inode_granted_mode hint-read, last condition). A/B on 326: 0 orphans (vs 190). Phantom-retention variant (P6R with no wire slot) also covered.
3. **D-RELEASE-BARRIER-OPEN: FIXED AND VERIFIED.** Its own ledgered test met: full all-green board then cluster-wide P220 census — ~130K unlocks, obligation=0/flushing=0/in_ail=0/pinned=0 on ALL 32; defer backstop fired 2× and correctly withheld. (dump via echo 1 > /sys/module/mxfs/parameters/release_barrier_dump.)

## Board: 0.11.326 ALL GREEN @32/caw (third all-green board: 322, 325, 326)
22 tests incl. crash, fence, netpartition, soak, cc 654, zsl 644, dirent_durability ×2, dir_reuse in-board (58=8r,107s), fio_perf 2829/6942 MiB/s 242K/365K iops.

## 9 OPEN
- Pace: D-32NODE-SHARED-DIR-CREATE-PACE, D-READDIR-PEER-CACHED-DIR-PACE (re-measure under the fresh-state rig rule; turn anatomy: grace idle + wire-unlock CAS p50 9.7/p90 44ms = dominant, drain only ~1.6ms — sess38's 'drain-dominated' was WRONG, P138 stage split proves sx=unlock)
- Authority: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-AGI-UNLINKED-CROSSNODE-RECOVERY-SHUTDOWN (canary armed, quiet all day)
- D-DIRVIEW-NONCONVERGE-SESS25, D-MATRIX-UNMEASURED (rig-blocked)
- NEW D-STATFS-IFREE-NEGATIVE-RANK1 (n1 m_ifree>m_icount by 10851, in-memory only)
- NEW D-DWORK-RUNTIME-PIN (bulk-created inodes survive drop_caches; armed-dwork igrab suspect; demand-release verified OK; runtime sibling of sess36-37 unmount dwork family)

## NEXT (in order)
1. 0.11.327: dir_ex_batch_grace_ms default 40→10 (A/B: turn p50 81→50ms, +1 round, 9r fresh ×2; sysfs resets on reload — that trap cost sess38's setting). After deploy: cache_coherency + dir_reuse + pace chunk protective board.
2. D-DWORK-RUNTIME-PIN RULE-4 (probe i_count + dwork state on a pinned ino).
3. D-STATFS drift: instrument xfs_trans_mod_sb vs replay double-apply on rank1.
4. Authority family batch.
## Tools this session
tests/drc_lap_probe.sh + drc_lap_analyze.py (per-node stat/log/PSI snapshots + differ), tests/host_write_sampler.sh (nvme+fsync+per-proc writes), tests/drc_lap_run.sh (instrumented lap). Table parse: python O_DIRECT read of /home/steve/disk.img @67149824, 65536×512 slots, live=0x4D584357 tomb=0x4D58444C; slot layout: ino@+16, holders_ex@+40, gm@+88, gen@+4.
dlmtr ring: echo INO > watch_ino, dump via stat .mxfs_dirdump in a dir; lktdump = different (dlm.c) ring.
Magic: P6R-RETAIN(retention), P220(relbar census), P138-BAST sx=wire unlock, P6H-ADOPT reads=poll count.
Criteria NO — 9 OPEN.
