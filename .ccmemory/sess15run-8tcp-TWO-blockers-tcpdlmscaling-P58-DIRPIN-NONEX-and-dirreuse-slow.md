---
name: sess15run-8tcp-TWO-blockers-tcpdlmscaling-P58-DIRPIN-NONEX-and-dirreuse-slow
description: sess15(ccloop): full 8/tcp@900s = 16/17. TWO blockers: (1) tcp_dlm_scaling 1/8 CORRECTNESS = P58-DIRPIN-NONEX dir committed at dlm_mode=0/NL; (2) dir…
metadata:
  type: project
---

## sess15(ccloop) — full 8/tcp baseline @ TEST_TIMEOUT=900 (build 167ADFFF, clean reboot)

### RESULT: 16/17 PASS. The picture is now CLEAR — TWO independent blockers:

**Blocker 1 — tcp_dlm_scaling: CORRECTNESS, 1/8 PASS (real fail, NOT a cascade victim).**
Precise root (dmesg test2, RULE 4): `mxfs: P58-DIRPIN-NONEX ino=537968 dlm_mode=0 state=3 ex_h=1 pr_h=0 dlm_pin=0 comm=bash — dir committed WITHOUT EX authority`, stack = `xfs_inode_item_pin → xfs_cil_prepare_item → xlog_cil_commit → __xfs_trans_commit` (and `xfs_inode_item_precommit`). I.e. a DIRECTORY inode is being modified + committed into the CIL while THIS node's cached DLM mode is **NL (dlm_mode=0)**, not EX → no DLM authority → the sess58 durable-dirent **RESURRECTION** root (P58-DIRPIN-NONEX is the sess58 KEPT detector in xfs_inode_item.c). sess58 FIXED this for 2/tcp by acquiring the dir's DLM grant in the `xfs_lock_two_inodes` / `xfs_lock_inodes` nowait paths (ILOCK acquired via AIL-nowait skipped the DLM grant). At **8 nodes** there is ANOTHER modify+commit path that reaches commit with the dir at NL — find it (comm=bash = a shell op in the tcp_dlm_scaling workload: concurrent create/rename/remove). FIX FAMILY: ensure EX DLM authority on the dir inode before it is logged/committed on that path (mirror sess58). This is the #1 priority — it's correctness, deterministic-ish, and detectable via P58-DIRPIN-NONEX (always-on).

**Blocker 2 — dir_reuse_coherency: SLOWNESS only (PASSED 8/8 @900s, no shutdown this run).** ~630s vs ~12s native = RULE 0 fail at the default 300s budget. Root = TCP-DLM acquire churn / missed-BAST queue-vs-grant race on the hot shared dir + cross-node inode coherency reads (all 8 nodes read all 800 files → EX→PR downgrade BASTs). See [[sess15run-FIXPLAN-8tcp-dlm-queue-vs-grant-race-and-acquire-churn]] and [[sess15run-PRECISE-ROOT-8tcp-dlm-acquire-starvation-ino131-P36-retry-60s]].

### Order of attack (next session)
1. FIX tcp_dlm_scaling P58-DIRPIN-NONEX (correctness, 8-node dir-modify-at-NL). Find the uncovered modify→commit path; acquire dir EX first. Validate 2/tcp + tcp_dlm_scaling still pass.
2. THEN dir_reuse slowness (so it fits a sane budget) — the harder perf work.
Both must be solved for 8/tcp 100%. 1/2/4 tcp still PASS.

### Repro
Clean virsh-reset ALL 8 (local pkill leaves orphan remote test procs — contaminates). `TEST_TIMEOUT=900 ./run.sh 8 tcp` (full) OR `./run.sh 8 tcp tcp_dlm_scaling` (isolated). `dmesg|grep P58-DIRPIN-NONEX`. Build 167ADFFF probes (P14/P15/dir_perf_probe) all default-OFF.
