---
name: AAA-ccloope8e9-sess1-PASS1-32caw-dirreuse-0.10.66-run67-live
description: HISTORIC: dir_reuse_coherency@32/caw FIRST FULL PASS (run66, 0.10.66=C5EF60D5, 32/32 nodes 24/24 rounds, all probes 0 on all 32 nodes). run67=pass-2…
metadata:
  type: project
tags: [dir_reuse_coherency, caw, 32node, PASS, milestone]
---

# run66 = FIRST FULL PASS of dir_reuse_coherency@32/caw (the last criteria cell)

## Verdict (2026-07-12 ~04:45Z)
`PASS dir_reuse_coherency (nodes_pass=32/32)`, run_id=20260712T033621Z, build 0.10.66 srcversion C5EF60D535AF290C91B4112, 24/24 rounds, pace ~145s/round (~58 min total).
Cluster-wide sweep of ALL 32 nodes: P-SEMA-OVERUP=0, P-SEMA-DUALLOCK=0, P-WRCNT-RESUBMIT=0, P-BLI-DOUBLEDONE=0, shutdowns=0, kernel BUG=0. criteria.json 32/caw dir_reuse_coherency now records PASS.

## Why it passed (see AAA-ccloope8e9-sess1-ROOT-sema-poisoning-4patches-0.10.65 for full chain)
0.10.66 removed the bmbt-evict double-unlock (`xfs_buf_unlock; xfs_buf_relse` → relse only) at the 2 sess4-era sites in xfs_mxfs_dlm.c (mxfs_dir_evict_bmbt_blocks + mxfs_dir_evict_bmbt_by_root). Probes had proven +1 sema/loop (count 2→19 in 1s, single bmbt daddr, stack=evict_bmbt_blocks←reload_inode←ilock_begin←lookup). Historical failure ladder cleared: r9 meltdown (0.10.63 ilock walk), r10 dir-data CRC (0.10.64 canonical block0), r17 crash + r18 undercount (0.10.66 sema fix — undercount indeed did NOT recur once double-submits were impossible; run66 r17 AND r18 verified clean).

## Validation ladder remaining before YES marker
1. run67 (pid 2000572, log $SP/run67.log, SP=/tmp/claude-1000/-src-mxfs/e215743d-7b2e-4198-91e2-451903616da5/scratchpad) = consecutive pass #2 — launched 04:47Z.
2. run68 = pass #3 (project convention 2-3 consecutive).
3. Re-verify N=1/2/4/8/16 caw dir_reuse_coherency (+ ideally spot other suite tests) since xfs_buf core changed (probes+worker-router+item_done xchg + the dlm evict fix). Full suite: `./run.sh <N> caw` (no test arg = all applicable). MXFS_DEV=/dev/mapper/mpatha ALWAYS.
4. Also prudent: one full-suite 32/caw (`./run.sh 32 caw`) to re-confirm the other 16 cells on 0.10.66 (they last passed on older builds; core changed).
5. Only when all green: `echo YES > /src/mxfs/.ccloop/runs/e8e920f7-dcb3-4781-989f-cca95cb2f962/criteria-met`.

## Watch items for the remaining runs
- Any P-SEMA hit anywhere = residual poisoner (stack names it, cap 400/dump 8).
- SYSCALL_HANG family (scsi_execute_cmd / blk_execute_rq — block-layer, documented in wedge-root-has-moved-to-scsi-layer-2026-07-11) is NOT fixed by this work and could still bite; harness fast-aborts.
- test1 stream gotcha: prep power-cycles kill `dmesg -Tw` ssh streams (exit silently, file freezes). Start streams AFTER "=== run @" appears, or re-start post-prep. Ring survives (dmesg -Tw dumps full ring on start) unless node rebooted.
- pkill '[d]mesg -Tw' also matches the mxfs_sshpass wrapper holding the stream — use `fuser -k <logfile>` instead to kill a specific stream.
