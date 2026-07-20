---
name: sess46-barrier-timeout-and-lostupdate-same-root
description: sess46: posix_multi16's 120s barrier timeouts (dominant ~385s slowness) AND concurrent_touch dirent loss are ONE bug — concurrent shared-dir create d…
metadata:
  type: project
---

## sess46 (ccloop run 14d31183, session 46) — posix_semantics_multi16

Build D9D22CF3 on test1-16. Criterion still FAIL (18/19 PASS otherwise).

### KEY FINDING: barrier-timeout slowness AND concurrent_touch loss = SAME ROOT
Full `--phase cluster` (per-test wall, build D9D22CF3):
- concurrent_mkdir PASS but **137s** (124s = ONE 120s barrier timeout at `cm_ready`)
- concurrent_touch **FAIL** node9 lost 27 of its OWN 100 files (1573/1600), 27s
- concurrent_write PASS 12.8s, cross_visibility PASS 11s
- cross_write_read PASS but **247s** (TWO 120s barrier timeouts: `cwr_write` 0/16, `cwr_verify` 15/16)
- run hit 560s after only 5/14 cluster tests.

**The 120s barrier timeouts are the dominant RULE-0 budget-eater, NOT raw op slowness** (real work <1s/test). SAME bug as concurrent_touch loss:
- barrier signal = each node creates `.mxfs_barriers/<name>/<nodeid>` in a SHORTFORM dir.
- `present=[...]` diag GLOBALLY CONSISTENT across all 16 observers (cm_ready present=[2-10,12-16]; nodes 1+11 missing everywhere) AND victims' OWN `own_lookup=0 own_readdir=0` → dirent DURABLY LOST on disk, not per-node cache staleness.
- = concurrent create into a shared dir durably clobbers a peer's just-added dirent. Block dir (concurrent_touch) loses file dirents; shortform barrier dir loses signals → 120s hang.

**Fixing the concurrent-create durable lost-update fixes BOTH correctness AND slowness.**

### ESCALATION: loss → DURABLE DIR-BLOCK CORRUPTION → node shutdown
test1 force-shut-down TWICE on remount onto the (corrupt) cluster FS:
1. `xfs_trans_cancel at xfs_remove ... Corruption of in-memory data (0x8)`
2. `Metadata corruption detected at __xfs_dir3_data_check, xfs_dir3_block block 0x1fd9f0` → shutdown at xfs_buf_submit (pal/linux/xfs_buf.c:1972).
So the concurrent-create lost-update durably CORRUPTS a dir3_block (fails dir3_data_check), not just loses entries → any node re-reading blk 0x1fd9f0 shuts down. The on-disk FS is corrupt; MUST re-mkfs to get a clean test cluster.

### MECHANISM (hypothesis, to PROVE before patching — RULE 4)
Slow-path EX-acquire of a populated dir inode DOES call mxfs_dlm_reload_inode (xfs_mxfs_dlm.c:5780). Candidate stale-read sites: (a) reload reads stale on-disk (peer release didn't drain durably), (b) reload reads stale SCST cache (non-FUA), (c) **P91-RELOAD-PROTECT (xfs_mxfs_dlm.c:3821) keeps the cached inode-cluster buffer in-core when ANY co-resident inode has uncheckpointed mods → stale shortform dir fork survives → RMW clobber**, (d) concurrent EX (CAW double-grant). DISCRIMINATE with dirwr=1 probes (runtime toggle /sys/module/mxfs/parameters/dirwr, lighter than instr): P105-ACQ-DIRINODE vs P105-REL-DIRINODE (acquirer disk_size < prior releaser's = stale read PROVEN); P106-EXGRANT/EXREL (overlap = concurrent EX). DIR-STALE-SKIP is now ~0 so block-dir drain (sess83/88/133) mostly closed; residual is shortform/inode-cluster path.

### STATE at this point
- dirwr=1 set on all 16 (module-global, survives remount). dmesg cleared.
- Cluster FS is CORRUPT (blk 0x1fd9f0). test1 keeps shutting down on remount. NEXT: clean umount all 16 → fresh mkfs (test1) → mount all → isolated concurrent_touch with dirwr=1 → harvest P105/P106 → prove stale-read site → fix → verify 1600/1600 AND no 120s barrier TO.
- run_tests `--test X` path calls verify_environment (fails if any node unmounted); `--phase` path skips it. Isolated cmd: `MXFS_NODE_OFFSET=16 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 16 --test test_concurrent_touch --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared --no-color`.

### INFRA: SCST disk1 re-wedged by my interrupted run, RECOVERED (reusable)
Power-cycling VMs mid-mkfs/mount re-triggered sess43 SCST atomic-blocked-cmd wedge (/dev/sda reads hang, iscsi_conn_cleanup D-state×10, PR was CLEAN — it's CAW↔READ deadlock not PR). Recovery (~2min): read /sys/module/scst/sections/* with SUDO into vars first (`$(cat .text)` as non-root = Permission denied), run scripts/scst_atomic_edges.py via gdb on /proc/kcore → find cycle READ(op0x88)↔CAW(op0x89,blockers=1); `cd scripts/scst_unwedge && make && sudo insmod scst_unwedge.ko blocker=<READ addr> blocked=<CAW addr>` → CAW requeued, cascade drains. LESSON: never power-cycle VMs mid-mount; ensure clean umount before any teardown_all.

Related: [[sess43-dirdata-pin-rootcause]] [[sess41-shortform-dir-evict-gap-root]] [[sess43-scst-unwedge-and-p136]] [[sess90_lessons]]
