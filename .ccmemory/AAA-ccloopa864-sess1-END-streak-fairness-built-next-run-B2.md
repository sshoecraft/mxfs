---
name: AAA-ccloopa864-sess1-END-streak-fairness-built-next-run-B2
description: sess1 END: build B7A8BCAB = v0.10.39+ex_grant_streak PR-anti-starvation. Next: run B2 modargs fair_handoff=1 fastpoll=1 close_release=0; watch use_fr…
metadata:
  type: project
---

# sess1 END — state at relay

## Where things stand
dir_reuse_coherency@32/caw = the ONLY criteria gap (all other 6 boards 17/17 per showstat/criteria.json).

## Current build: srcversion B7A8BCAB1ADE70A412417DE (v0.10.39 + streak fix, BUILT, NOT YET RUN)
Contains (all in-tree):
1. binval-retire (xfs_trans_buf.c) — PROVEN fix for the P97 fence wedge.
2. soft random jitter (caw_inode_backoff).
3. close_release (PARAM, run with =0 — no-op for this test).
4. caw_inode_fastpoll (PARAM, default 1) — 2ms poll first 64ms of inode waits.
5. dir-EX-BAST sweep (dir_ex_bast_sweep=1 default): on losing a held dir (PR or EX, v0.10.39-wide) to a peer, s_inodes-walk demote all idle REG PR grants. PROVEN: rm 39s (r1) vs 105-190s; wide trigger fires per-round on peers (test5: 9 sweeps).
6. pr_idle_release_ms (PARAM default 0=off — REFUTED as default, keep off).
7. **NEW UNTESTED: ex_grant_streak fairness** — slot pad2 renamed ex_grant_streak; caw_grant_streak_note() at both grant CAS sites; fair-handoff release chooser yields ONE turn to the WHOLE PR class after MXFS_CAW_EX_STREAK_YIELD=3 consecutive EX grants. Fixes: run B (235542Z) test1 verify-readdir PR starved 240s behind 31 creators' EX round-robin → rc=-110 shutdown (ino=131 mode=3 comm=bash).

## Run ledger (all on 32/caw dir_reuse, timeout 5200, MXFS_DEV=/dev/mapper/mpatha)
- A (232826Z, fastpoll=0 fair=0): rounds 106/140/133 ✓ pace BUT rank1's dd starved 360s on dir EX (free-for-all, fastpoll had been the equalizer) → shutdowns r5-7.
- B (235542Z, fastpoll=1 fair_handoff=1): rounds 100/131/147 ✓ BUT PR starvation (fair rotation excludes shared class) → test1 dead t=859.
- B2 = NEXT: same modargs as B (`dirwr=1 dirland=1 close_release=0 caw_inode_fastpoll=1 caw_fair_handoff=1`) on B7A8BCAB with the streak fix. Expect: no starvation of either class, rounds ~100-150s, full 24 rounds ≈ 3000-3700s.
- WATCH in B2: (a) any "Shutting down"/unrecoverable/use_free per node (fresh dmesg.stream per power-cycled node — grep is contaminated on non-rebooted nodes; check line timestamps vs run window); (b) round walls via DRCph; (c) the r2-create use_free corruption (xfs_dir2_data.c:2436, bestfree stale-leaf family) — reproduced once on v0.10.38 (test5, run 225612Z, forensics in my session's t5b.stream copy + node streams); if it reproduces, root-cause via armed watch_ino probes (P49-STALEBASE/P10-RDBLK/P13-LADD around the failing create).

## Cluster state at relay
All runs killed, /tmp/mxfs_run.lock FREE, node-side scripts pkilled. Nodes were last seen up but several have SHUTDOWN mxfs mounts from run B (test1 t=859 + others) → next session MUST sweep SSH-dead + power-cycle + mpath_up 32 before launching (prep also self-heals). Build on NFS is current (insmod from /src/mxfs/mxfs.ko).

## Fallback thinking if B2 still starves/corrupts
- Starvation: raise/lower MXFS_CAW_EX_STREAK_YIELD; or grant PR class alongside... (no — incompatible while EX held); aging via yield classes is the design lane.
- use_free: it's the leaf-vs-data bestfree divergence family (P6L leaf scan was the 8-node fix; 32 reopens it). Full forensics recipe in AAA-ccloopa864-sess1-PACE memory.
- If pace regresses again: the phase data method — DRCph create-start/create-done/verify-done/rm-done per node; peers' create window = rank1 [create-done→verify-done].
