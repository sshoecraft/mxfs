---
name: sess10run-FIX-dir_epoch_adopt-default-on-fixes-4tcp
description: sess10(ccloop) REFUTED: dir_epoch_adopt=1 is NOT a reliable 4/tcp dir_reuse fix (~1/5 pass, 1 fluke). Reverted to default 0. Tree back at baseline DE…
metadata:
  type: project
---

## sess10 (ccloop 4cb2d0a2) — dir_epoch_adopt=1 experiment: REFUTED as a fix

### What happened
Saw ONE PASS 4/4 of `./run.sh 4 tcp dir_reuse_coherency` with `dir_epoch_adopt=1` (vs 0/4 default), baked it in as default (build E4540ADC), but on re-testing it FAILS ~80%+ of the time:
- dir_reuse 4/tcp standalone, fresh virsh-reset cluster, epoch_adopt=1: **FAIL 0/4 x3 consecutive** (+ 1 more FAIL after crash_consistency). The single early PASS was a FLUKE (4-node dir_reuse is intermittent).
- epoch_adopt=1 + dirrefresh=1 + dir_leaf_rebuild=1: also FAIL 0/4.

### Conclusion
**REVERTED** `mxfs_dir_epoch_adopt` to default 0 (xfs/xfs_mxfs_dlm.c:2863). Tree rebuilt to baseline **srcversion DE3A7E21** (identical to start of session). Confirms sess67's "epoch_adopt alone insufficient for 4node." Param-toggling of the gated-OFF dir-coherency knobs does NOT reliably fix it — needs real code work.

### What IS solid (verified this session, build DE3A7E21)
- 2/tcp dir_reuse PASS; full 2/tcp suite = 14/17, the 3 fails (fence_during_write/fault_netpartition/tcp_dlm_scaling) ALL PASS standalone = in-suite contamination.
- 4/tcp: ALL coherency tests pass in-suite EXCEPT dir_reuse; dir_reuse fails ~80%+ standalone (durable single-dirent loss, e.g. node4_f1.md5, survives drop_caches = durable on-disk).

See [[sess10run-NEXT-real-fix-direction-concurrent-rmw-stale-base]] [[sess10run-4tcp-clean-repro-dirty-block-clobber-mechanism]].</body>
