---
name: sess53-BREAKTHROUGH-plain-defaults-plus-P52-guards-17of17
description: sess53: PLAIN ./run.sh 2 tcp (pure defaults, dir_pr_release_fast=1) + P52 guards = 17/17 reliable (3/3 so far). Option B (=2) was CAUSING tcp_dlm_sca…
metadata:
  type: project
---

## sess53 — the criterion config is PLAIN defaults + P52 guards (NOT option B)

### KEY FINDING (overturns sess52's option-B direction)
The criterion (`./run.sh 2 tcp` reliably 17/17) is met by the **PLAIN command, pure
defaults** on build **D67776EC** (= option-B code present but `dir_pr_release_fast`
DEFAULT=1, i.e. the sess51 NARROW self-demote-only release-skip) **+ the P52 freed-reuse
dir reload guards**. Tally so far: **d1,d2,d3 = 17/17** (~540s each, clean reboot between).

### WHY option B (dir_pr_release_fast=2) was WRONG
sess52 added option B (`MXFS_EXTRA_MODARGS='dir_pr_release_fast=2 dir_acq_lockwait=60'`).
`=2` BROADENS the release durability-skip to EVERY clean non-EX release (xfs_mxfs_dlm.c
~5129). Measured this session with `=2`:
- r1: node1 SHUTDOWN at `xfs_iunlink_item_precommit→xfs_iunlink_log_dinode` (di_next_unlinked
  old_ptr!=in-core i_next_unlinked) on a reused FILE inode (P53 diag added; ino 8939320).
- r2: PASS 17/17.
- r3: tcp_dlm_scaling soft-fail `tds shared dir drained got=1` (durable dirent LEAK n2_r124).
- fast warm-FS repeat (tests/tcp/fg_tds_repeat.sh): node2 SHUTDOWN at `xfs_trans_cancel:1061`.
So `=2` is UNRELIABLE on tcp_dlm_scaling (leak + 2 distinct shutdown faces). `dir_acq_lockwait=60`
and `dir_pr_release_fast=1` are ALREADY the code defaults (xfs_mxfs_dlm.c:3910,3942) — option B's
only delta is the `=2`, which HURTS.

### WHY plain defaults work NOW (didn't in sess52)
sess52's bind: `=1` failed dir_reuse_coherency (stale-block race), `=2` failed tcp_dlm_scaling.
Since sess52 I rebuilt with the **P52 freed-reuse guards** (D67776EC: P52-RELOAD-FREEDREUSE-DIR-SKIP
~6869 + P52-FRESHSRC-FREEDREUSE-DIR-SKIP ~7323). Those fix dir_reuse's gen-mismatch freed-reuse face,
so `=1` now passes BOTH dir_reuse AND tcp_dlm_scaling. Confirmed: plain run dir_reuse PASS + tcp_dlm_scaling PASS.

### BUILD STATE
- HEAD `D67776EC` = the criterion build (option-B code + P52 guards; default release_fast=1).
- Current local `mxfs.ko` = `B9258412` = D67776EC + a HARMLESS P53-IUNLINK-MISMATCH diagnostic
  pr_warn in xfs/xfs_iunlink_item.c (logging only, no behavior change). Plain runs on B9258412 ARE
  valid criterion evidence (=1 default). Consider removing P53 diag for a clean final build, or keep
  (harmless, aids future debug).

### NEXT (in progress)
1. Keep running PLAIN `./run.sh 2 tcp` with clean reboots to ≥6-8 consecutive 17/17 (intermittent
   ~1/3 under =2, so need a solid streak under =1). Helper: `PLAIN=1 bash tests/tcp/fg_one_run.sh dN`
   (foreground, reboots, ~565s budget; dmesg on fail). Do NOT use MXFS_EXTRA_MODARGS.
2. If streak holds → criterion MET. Optionally rebuild clean (drop P53 diag), 2-3 final PLAIN runs,
   then `echo YES > .ccloop/runs/8ddb16a2-.../criteria-met`.
3. If a PLAIN run fails: it'll be tcp_dlm_scaling (iunlink/trans_cancel shutdown or dirent leak).
   Fast warm-FS repro = tests/tcp/fg_tds_repeat.sh (after a full-suite warmup; reboot+remount-without-
   mkfs preserves on-disk warmup). P53 diag captures the iunlink old_ptr vs i_next_unlinked + uncp.
Related: [[sess52-FIX-broad-skip-plus-acquire-lockwait-optB]] [[sess51-FIX-narrowed-self-demote-durability-skip-17of17]]
