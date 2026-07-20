---
name: caw-sess4-dirreuse16-root-and-clean-build-params
description: sess4 (12e0d157): substrate HEALTHY, clean build 6C6D5274 (P-AGLOW removed, P-DBLALLOC gated), dir_reuse@16 root=per-modify flush hang+16-way content…
metadata:
  type: project
---

## ccloop 12e0d157 sess4 progress (2026-07-07)

### Substrate is HEALTHY (NOT PR-wedged)
Multipath mpatha = 2 active paths (sdb+sda, no queue_if_no_path, no path fail), no
reservation conflicts, no I/O errors. 4/caw cache_coherency+zero_silent_loss PASS 4/4
in 57s at DEFAULT (fb=0, build 9731510A). So session3's fb=0 flip works at 4; the
"empty content" it saw at fb=1 does not reproduce as a substrate issue now. test1-16 up;
test17-32 shut off.

### showstat state (criteria.json, per N/caw = 17 tests)
1/2/4/8 caw = 17/17 PASS. 16/caw = 16/17 (ONLY dir_reuse_coherency PENDING).
32/caw = 6 PASS / 1 FAIL (dlm_scaling 7/32) / 10 PENDING.

### Clean build lineage
9731510A (sess3 fb=0 default) -> **E1466434** (removed the un-gated P-AGLOW alloc/free
pr_warn probes in xfs_alloc.c; GATED P-DBLALLOC behind new `dblalloc_probe` param=0 —
it did 1 synchronous LUN read PER data alloc while holding AGF, a RULE-0 confound) ->
**6C6D5274** (+ `dir_persig_flush` + `dir_shared_pr_skip` params). ALL new params
default to ship-safe. Build cmd: `make modules` (~16-24s).

### New params (all default-safe; A/B levers)
- `dir_shared_pr_skip` (default 0): extends the owned_ex FUA-skip in xfs_da_read_buf to
  a dir held >=MXFS_LOCK_PR with !i_dlm_dir_want_ex. FIX for dlm_scaling@32 shared-parent
  read storm. UNTESTED at 32. Safety net = coherency suite. See
  [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]].
- `dir_persig_flush` (1=always/default sess48, 0=never, 2=only-when-peer-wants-EX): gates
  the per-modify xfs_log_force(SYNC)+dir-flush in mxfs_dlm_dir_durable_signal.
- `dblalloc_probe` (default 0): re-enables the P-DBLALLOC detector (heavy, off by default).
- `P-DSCAN` probe in xfs_da_read_buf (gated on dirwr): logs shared-dir DLM mode/flags.

### dir_reuse@16 ROOT (RULE-4, build 6C6D5274)
NOT corruption (0 shutdowns). TWO costs: (1) mxfs_dlm_dir_durable_signal runs
xfs_log_force(SYNC)+mxfs_dir_flush_data_blocks on EVERY unlink of a contended dir
(gen>0), while holding dir ILOCK_EXCL -> rank1's rm-rf of 1600 entries HANGS
(xfs_buf_iowait in mxfs_dir_bmbt_scan xfs_bwrite, hung-task 90s+). persig_flush=0
REMOVES the hang (no hung-task) — PROVES the flush is that hang. (2) BUT still slow:
even persig_flush=0 didn't finish 4 rounds in 600s. Real residual = fundamental 16-way
shared-dir EX-handoff contention: 1600 creates/round each ping-pong the dir EX lock +
BAST-demote 15 peers (P47-FILEBLOCK rc=-35 EAGAIN demote-wait on file inodes during rm).
create phase ~25s, verify ~53s -> round ~80s+. run.sh internal budget=140*16=2240s.
MEASURING true 24-round wall with persig_flush=0 (background) to see if it fits 2240s +
stays coherent (persig_flush=0 may reintroduce the sess48 durable-loss gap; if so use
persig_flush=2). Test: NFILES=50 ROUNDS=24 EXP=2*T*50=1600/round; DRC_ROUNDS/DRC_NFILES
via MXFS_TEST_ENV. dir_reuse is the SAME blocker at 16 AND 32.

### Infra notes
- SSH: `tools/mxfs_sshpass.sh testN /tmp/.mxfs_pass 'CMD'` (passfile is the 2nd ARG!).
- run.sh forwards `${MXFS_TEST_ENV:-}` (e.g. DRC_ROUNDS=4) + MXFS_EXTRA_MODARGS to insmod.
- Bash TOOL default timeout 120s; set timeout param for run.sh (prep alone ~130s).
- Kill a run: pkill run.sh + `pkill -f dir_reuse_coherency` on each node (pattern
  self-matches the ssh shell -> exit1 but works). run.sh SIGTERM teardown unloads mxfs.
- NEVER boot test17-32 or add iSCSI logins DURING a 16-node timing run (contaminates).
</body>
