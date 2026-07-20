---
name: sess1-a9a03929-gen-aware-unlock-fix-wedge-fixed
description: sess1(a9a03929) build D03537C9: gen-aware unlock closes run42 concurrent-EX dirent loss; dwork re-arm closes the 120s strand it exposed. 21 rounds 0…
metadata:
  type: project
---

# sess1 (ccloop a9a03929) — gen-aware DLM release, wedge chain fixed

Build `D03537C94865133FF366972` (in tree, deployed run47). Prior context: continuing a16ec5f2 sess5/6; clyde HOST rebooted 08:17 (infra restore: `scripts/lio_tcm_setup.sh setup`, `echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass`, boot VMs — see runbook below).

## FIX CHAIN (all RULE-4 proven, in-tree)

1. **Gen-aware release** — `mxfs_dlm_unlock_gen(ctx,res,expected_gen)` (dlm.c; wrapper mxfs_dlm_unlock=gen 0; v5_mount.c `mxfs_v5_dlm_inode_unlock_gen`; decls dlm.h/v5_mount.h). bast_process captures `p_rel_gen` via `mxfs_v5_dlm_inode_grant_gen` BEFORE the NL-set; unlock releases ONLY that tenure. Newer-gen entry → -ESTALE, nothing touched. Kills run42-t4 loss root: stale queued release ate the fresh EX mirror, echoed CURRENT gen (dlm.c rel_gen=found->grant_gen) → master accepted → peer granted → CONCURRENT EX (invisible to P-DOUBLEGRANT) → stale-base RMW → durable dirent loss (P5H insert ep=647 → 4ms → P2-EPOCHPLACE master_ep=0).
2. **Local-immediate grant gen stamping** (dlm.c ~1497): was the ONE grant path leaving grant_gen=0 → masters' own tenures had gen 0 → capture read 0 → releases skipped → run44 total wedge (readdir=0 everywhere) + owner-scan evict (cur_gg!=cached) was INERT on masters. Stamp `dlm_next_gen(ctx)` like sites 793/1368/3304/3356/3529.
3. **P6Z skip**: TCP + capture==0 → skip unlock entirely (stale/duplicate release; releasing "whatever's there" can only eat a fresh grant).
4. **Strand re-arm via dwork** (run46 lesson): first ESTALE version set state=BAST with holders==0 → NOTHING consumes BAST (only holder ilock_end/unpin) and BAST blocks fast-path admits (P47-FILEBLOCK state=2) → md5sum getattr blocked 117s in mxfs_dlm_ilock_begin (ddwatch stack) → rank never finished creates → barrier held cluster → idle dir holder never BAST'd (master: ZERO P7S 114s — no requests arrived) = the 120s wedge, broken only by xfs blockgc at mount+300s. FIX: on ESTALE (or P6Z-with-tenure-now-present) set `i_dlm_bast_pending=true`, state=NONE, arm `i_dlm_bast_dwork` (+4ms), wake, return. The dwork (MHT machinery, survives state clobbers, "sole releaser") samples till quiescent then runs a FRESH bast_process (fresh gen capture, full drain).

## Verified (run47, 8/tcp drc):
- 21 rounds, ZERO drc-FAIL/RDMISS/shutdown/-110. P6G=68-92/node (race is HOT — every fire was a would-be lost-update), P6Z=253-310/node, P36-RETRY≈8-15 (was 177+).
- Probes added: P7S-BAST-FIRE (dlm.c fire_bast_records, ino<=256), P7B-BASTNOTIFY (xfs bast_notify entry), P6G/P6Z/P6E. ddwatch.sh generalized to ALL D-state tasks.

## REMAINING = PACE ONLY
21-22s/rd rounds 1-7, degrades to 25-28s by r15+ (run43 same shape → degradation PRE-EXISTS my changes). Need ≤20s×24=480s. Phases (r15-20): create 3-11s (stagger), verify 8-13s (grows over rounds), rm ~10.6s flat (800 unlinks × ~13ms cross-node ino-EX pull: BAST→holder drain(log_force?)→unlock→promote→grant). Ideas: coalesce unlink-side releases (mxfs_release_coalesced_flush exists), verify-phase getattr PR-pull cost, round-degradation source (icache growth? log volume?).

## Environment runbook (post clyde-reboot)
- Storage: `bash scripts/lio_tcm_setup.sh setup` (fileio backstore over /home/steve/disk.img → tcm_loop → /dev/mxfs-shared symlink; VM XML device=lun).
- `echo '<REDACTED-ROTATED>' > /tmp/.mxfs_pass; chmod 600` (root pw for testN).
- /src = QNAP NFS (192.168.1.4:/src) — same tree visible on all nodes; insmod /mnt/mxfs-src via run.sh prep.
- Run loop: reboot 8 VMs (virsh -c qemu:///system destroy/start, 45s), deploy+start `/root/ddwatch.sh` via SCP, `timeout -k 10 585 ./run.sh 8 tcp dir_reuse_coherency > out 2>&1` (NO pipe — orphaned children hang the pipe), collect /root/dmesg.stream + /root/ddwatch.log per node.
- MQTT broker 192.168.1.149 must be up (run.sh coord).
- Node-id map run46: t1=2932801977? (check P44 local=), t3=master-131 run46, t8=1416257729. Masters rotate per run (membership hash).

## Ladder: pace ≤20s/rd → 8/tcp drc ×5 clean → 4/2/1 → full `./run.sh N tcp` N∈{1,2,4,8} → YES.
