---
name: sess38-run14d-recovery-and-probe-gating
description: sess38 run14d: host reset recovered (16 iSCSI logins needed for VM start!), zsl PASS ×2; ship probe-gating sweep (40+ routine markers → dirwr/instr)
metadata:
  type: project
---

# sess38 (run 14d31183) — post-wedge recovery + probe-gating sweep

## Recovery after the 2026-06-12 manual host reset
- The @reboot clyde_boot_recover.sh did NOT run (it self-disarms; only the
  session that reboots installs it — a USER manual reset boots without it).
- **VM start dependency discovered**: test1..test16 passthrough
  `/dev/disk/by-path/ip-127.0.0.1:3260-iscsi-iqn.2026-05.local.mxfs:disk1{,n2..n16}-lun-0`.
  `virsh start` fails "Cannot access storage file" until the HOST is iscsiadm-logged-in
  to ALL 16 targets (not just disk1b). Fixed clyde_boot_recover.sh to log in all 17.
- Recovery sequence that worked: login 16 targets (parallel) → `cp ~/.mxfs/pass
  /tmp/.mxfs_pass` → `cluster_reset_n.sh 16` → zero_silent_loss PASS 3/3 (355s-ish,
  480s budget) on build `DE7F1BDA`. Confirms sess37 iter-3 join failure was the SCST
  wedge, NOT an mxfs regression.

## SCST fix handed to Opus (separate session)
User runs an Opus session fixing the SCST block_count leak in /src/scst, reproducing
on scratch device **disk2** (leak is per-device, disk1 insulated). scst.service
restart / module reload needs a coordinated window between my criterion runs.

## Probe-gating sweep (ship cleanliness)
sess37 plan item "strip/gate P35x/P36 probes" expanded: a PASSING zero_silent_loss
run still emitted ~9000 `mxfs: P*` lines across 4 nodes (~36k cluster-wide), incl.
dump_stack() Call Traces from P124-ALLOC-REVERT in xfs_buf_submit (would trip
dmesg_clean's `Call Trace` grep). Approach: gate EVERY routine-fired marker behind
`unlikely(mxfs_dirwr_enabled || mxfs_instr_enabled)` (dlm/ uses caw_instr_on() for
dual-build), print-statement-only (side effects like nskip++/all_evicted stay
ungated). Hand-gated first batch (P35E, P35C sweep incl. per-release FUA-compare,
P36-*, P105-*, P-SFDIR-RELOAD, P-DIR-SEQ, P23-SLOWPATH, P135-SLOTWR, P20-CLUSTER-INVAL);
4 parallel agents did the remaining ~46 sites (xfs_mxfs_dlm.c, pal/linux/*,
dlm/*, xfs_inode.c+libxfs). Backups at *.c.backup for diff review (no git!).
First gated build `9683085C` passed zero_silent_loss 3/3 before the agent sweep.

## Verification protocol for the sweep
diff vs .backup per file, build, cluster_reset_n.sh 16, zero_silent_loss, then
check `dmesg | grep -c "mxfs: P"` ≈ 0 on nodes. Then the remaining gate:
verify_ship.sh end-to-end (budgets in tests/criteria/TIMEOUT_BUDGETS.md, total
~52 min — needs per-criterion foreground strategy).

Related: [[sess14-scst-wedge-host-reboot]], [[sess15-run14d-wedge-recurrence-and-silent1]].
