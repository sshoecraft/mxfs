---
name: cawp-gate-pr-fence-full-verification
description: cawp rig: CAW settle gate + ghost rescan + racy join + D4 preempt + full EBADE fence resolution ALL VERIFIED on v0.11.81. Matrix sweep is next (ladde…
metadata:
  type: project
tags: [cawp, caw-gate, ghosts, pr-preempt, ebade-fence, ccloop-c7ee71c6]
---

# CAW-branch verification complete (v0.11.81 build 9674E330, ccloop c7ee71c6 sess1)

## All task-#2 legs verified on the cawp rig (scripts/rig.sh pass 2)
- **cawp rig = REAL per-node I_T nexuses** (per-VM SCST targets node1/node2 via clyde loopback sessions; PR state shared across both targets of the one vdisk). test2's mount probe: "own key visible, 2 key(s) — per-node PR active"; sg_persist confirms both keys.
- **CAW settle gate (D5 edit, first-ever execution)**: joiner "membership settled at mount ... after 0ms". Formation 21-25s prep, subset 4/4 PASS (cache_coherency 534, posix_multi, dlm_fairness, dlm_membership).
- **Racy join**: simultaneous mounts both rc=0 ~1.15s, both gates 0ms, active_count=2 both.
- **Ghost injection**: forged 2 ACTIVE frozen-ts HB records (disklock_offset=67117056 + slot*512; struct: magic 0x4D584C4B, flags@4=1, node_id@8, fs_gen@12 = folded volume_id — MUST match live fs_gen or sess131 filter ignores them; ts@16 fixed). Mount: P-EVICT-AUTOMON both → CAW auto-monitor 10s frozen-confirm (serial, inside DLM init) → gate 2s+5s rescan → **P-MEMB-GATE-GHOSTS 2 discounted** → mount OK, wall 18.3s (= automon 10.6s + gate 7s + 0.7s; conservative-by-design crash-recovery verification; potential future optimization: gate could reuse automon verdict — NOT a defect).
- **D4 positive preempt**: virsh destroy test2 → HB expiry ~73s → "P-PR-FENCE preempted dead node (key ...)" → victim key removed, survivor's intact, dead slice replayed ("foreign replay of slot 0 complete").
- **Full fence resolution (D1+D4+D8 keystone)**: test2 sg_persist-preempted test1's key → test1's next disklock HB FUA bounced **EBADE (-52) within ~2s** → P-WITHDRAW-QUEUE FS shutdown → P-SHUTDOWN-FENCE refuses acquires → dd EIO → NO auto-re-register. Fencing latency ≈ HB interval, independent of user I/O.

## Matrix sweep plan (task #9, NEXT)
Final build v0.11.81 (9674E330). Use ladder_rung.sh's chunk lists as FOREGROUND run.sh calls (never outer-timeout run.sh — kills poison the rig): prep; [precond posix_single fsx fio_verify integrity_filetypes fault_enospc]; [cache strong posix_multi mmap]; [zsl fairness membership scaling_curve dlm_scaling rsync]; [crash fence netpartition dlm_lock_correctness tcp_dlm_scaling]; [fio_perf fio_perf_vs_xfs]; [dir_reuse]; [soak]; N=1 adds tooling last [mkfs_timing chk_clean online_resize dkms_install single_node_paired fio_vs_xfs_baseline cluster_ops_timing fault_io_error]. Recorded cell walls are small (32/cawp total 431s, 32/tcp 567s; dir_reuse@32 ~104s actual) → 600s foreground chunks fit. Leave RULE0_CALIBRATE unset (enforce). Refresh .xfs_fio_baseline.<cond>.json at each condition start (ladder health-gate pattern: swapoff/on + drop_caches, then run.sh 1 xfs prep+fio_perf with MXFS_DEV per condition — caw:/dev/mapper/mpatha cawd:by-path shared tcp/cawp:/dev/sda). Rig order from current cawp: rig.sh pass 32 → cawp rungs 32..1 → rig.sh direct 32 → cawd → rig.sh mpath 32 → caw → rig.sh tcp 32 → tcp. Then #10 QNAP, #7 quiet-window fio.

## Cluster state at handoff
cawp rig up (2-node targets only — pass 32 needed for scale rungs). test1 unmounted/rmmod'd (was deliberately fenced in the EBADE test), test2 mounted+module loaded, LUN has suite-era FS. Both need fresh prep anyway. VERSION=0.11.81; all changes UNCOMMITTED (no-git rule). tcp cells in criteria.json carry mixed v77-81 stamps — sweep overwrites.
