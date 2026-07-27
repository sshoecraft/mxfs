---
name: ccloop-c7ee71c6-sess11-C-readdir-fix-physboard-tcpflip-incident
description: sess11-C: P95D readdir pre-lock converge (ghost-dirent FIXED), full CAW-family boards green, PHYSICAL pve board+withdraw green at .113; 16/tcp collap…
metadata:
  type: project
tags: [readdir, ghost-dirent, physrig, boards, lio-writeback, rule6]
---

# sess11 part C (v0.11.112-113, srcver 388FE1AA / pve-6.17 build C8246A58)

## Ghost-dirent readdir defect — FIXED AND VERIFIED (RULE 6)
16/cawd fence_during_write: removed name `n12_12` stayed LISTED on 3 nodes for minutes
(stat=ENOENT, ls=present, drop_caches-immune) while writer's P13-SFRM proved the SF remove
ran. ROOT (captured live): "DLM reload BAIL ino=… rd_held=1 wr_last=mxfs_dlm_reload_inode
rd_last=xfs_file_readdir SAME PID ×256" — the ls holds ILOCK_SHARED (taken so the DLM hook
fires) while its own armed reload needs the write side → bails forever → serves stale SF
body. FIX: pal/linux/xfs_file.c xfs_file_readdir — if i_dlm_stale at entry, bounded-blocking
converge (≤200×10ms, P95B/C contract) BEFORE any ilock; P95D-READDIR-WAIT prints on every
taken arm. VERIFIED: staged churn shows resolved=1 rounds=85 + terminal agreement; 3×
drc→fence green; full 16/cawd board green. NOTE resolved=0 mid-churn = legal snapshot.
Healing experiment: any EX op on the dir cured the pre-fix ghost (that was the proof of
mechanism). Earlier one-shot 8/cawd fence FAIL (silent mkdir ENOENT on 4 nodes after drc)
remains OPEN-with-tripwire: fence_during_write.sh now has "fdw setup mkdir clean" check +
FDW-MKDIR-FAIL/RETRY kmsg telemetry; not reproduced in 10+ runs (incl. tests/repro_mkdir_race.sh
×50 epoch-aligned).

## fio_perf_vs_xfs methodology corrected (evidence-backed, not weakened)
8/cawp randW flagged 68% vs raw ceiling while SAME-DAY native XFS = 37751 iops (59% of raw)
and mxfs@8 = 44244 (117% of native). Row now gates randW against the NATIVE-XFS baseline
(its stated purpose; ceiling stays for seqW N-sharer split + randW fallback). Same-day
triple measurement in test comment. scripts/raw_fio_ceiling.sh cawp re-run merged N=8.

## Boards green this session (v0.11.113 = 388FE1AA unless noted)
- cawd: 2/4/8/16 all 19-19/20 rows + withdraw each (2,4 at .111; 8,16 re-verified .113).
- cawp: 8 rows 19/19 + withdraw. caw(mpath): 4 rows 19/19 + withdraw.
- crossing-sweep (tests/caw/caw_align_probe) CLEAN via cawd, cawp (qemu over iscsi-sd), mpath.
- **PHYSICAL pve1/pve2+QNAP (user-directed): 16/16 rows + withdraw + fio (seqW 111MiB/s =
  GbE line rate, randW 30k) ALL PASS at C8246A58** (same source, 6.17 build; deployed
  md5-verified after a silent nested-scp no-op almost ran pve2 on the old .76 module).
- tcp: 1/2/4/16 green at .111; .113 tcp re-verify on VM rig INCOMPLETE (see incident).

## 16/tcp-at-.113 collapse incident (OPEN disposition, likely infra)
After rig.sh tcp 16 flip: fio_perf seqW 2795MiB/s (4-10× prior band) → clyde load 82 →
15/16 nodes mass rc=-110 ino=128 shutdown→withdraw cascade (comm=rm, fio cleanup), test1/
test10 ssh-wedged. Mechanism: LIO fileio backstore runs WRITE-BACK (pre-existed from sess1,
reused idempotently forever) although scripts/lio_tcm_setup.sh line ~98 explicitly designs
write_back=false with a comment describing THIS flood; page-cache absorb → writeback storm →
root-ino master VM starved >184s with TCP still up (no declare-dead; P164 covers dead not
livelocked masters) → cluster-wide acquire-timeout suicide. Robustness note for later: a
stalled-but-connected master >60s budget kills peers — consider suspect-on-service-latency.
ACTION IN FLIGHT: lio teardown+setup rerun; targetcli STILL SHOWS "write-back activated" —
VERIFY the flag actually took (check /sys/kernel/config/target/core/fileio_*/mxfs/attrib/
emulate_write_cache and fd_dev flags; may need explicit attribute set). Then restart all 16
VMs (qemu fds point at the deleted tcm device!), re-prep 16/tcp, re-run board (fio rows
separate from coherency rows to bound load).

## Harness/infra fixes this session
- run.sh: foreign-kernel WANT_SRCVER (marker identity = node-installed module on physrig).
- withdraw_recovery_test.sh: MXFS_NODE_LIST-aware, OBS=first survivor (was test2), creator
  default test$N, adaptive completion poll (QNAP zeroing ~31s vs VM 4s; 90s budget).
- rig.sh: ALLNODES = running∪requested (was hardcoded 32 → 48min grind on destroyed VMs).
- Physrig prep gotcha: pve node sometimes needs a manual umount+rmmod nudge before re-prep
  (prep's escalation is virsh-only); QNAP foreign replay prints "skipping intent item type
  0x1237" + a WARN stack — pre-existing, benign-looking, unfiled.
- /tmp/.proxmox_pass regenerated from ~/.config/osimager/secrets (password same as VM fleet).

## Next session order
1. Fix/verify LIO write-through, restart 16 VMs, re-prep + 16/tcp board at .113 (+ withdraw).
2. If green: matrix essentially complete on VM rig; consider 32/cawd spot rows (test17-32
   need XML re-wiring — wire_vms only touched 1..16).
3. Remaining opens before YES: fence-mkdir one-shot (tripwired), stalled-master robustness
   (design item), watch list in state.md, uncommitted tree.
