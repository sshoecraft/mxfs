---
name: sess31-HEAD-handoff
description: sess31 HEAD: MAJOR WIN duplicate-IQN infra fix → 1/2/4 tcp=100%, 8/tcp=2/3. Sole residual=rare dir_reuse async-destage TOCTOU loss. Reliable round-1…
metadata:
  type: project
---

## sess31 HEAD — read this first

### THE BIG WIN (persistent, verified, survives reboots)
The ~30-session "8-node coherency flakiness" was largely an **infrastructure bug: 6 of 8 test VMs shared one iSCSI InitiatorName** (QNAP target dropped colliding sessions → node wedge cascades misread as mxfs coherency bugs). Fixed (unique IQNs on test4-8) + cleaned 20GB /var/log fill (ENOSPC broke dkms_install). Result, build 37A37B10 (UNCHANGED — no kernel edits this session):
- **1/tcp = 16/16, 2/tcp = 17/17, 4/tcp = 17/17** — all PASS clean.
- **8/tcp = 17/17 on 3 of 4 full runs (~75%)** — only run C failed, on the dir loss below (was NEVER passing before the IQN fix). [[sess31-BREAKTHROUGH-duplicate-iscsi-iqn-was-the-8node-flakiness]]

### SOLE remaining blocker (criteria NOT yet met)
The rare **dir_reuse_coherency single-dirent loss** at 8 nodes (readdir 799/800). Mechanism = async-xfsaild-destage TOCTOU: an EX-holder destages a stale in-AIL dir-DATA block (bgen=0) missing a peer's durable add → reverts it. Confirmed by fresh P-WMERGE (disk_extra=1 incore_extra=1). [[sess31-DECISIVE-round1-standalone-repro-confirms-sess28-mechanism]]

### Tested & ruled out this session
- create-time merge `dir_merge=1` — INEFFECTIVE (loss persists; TOCTOU). 
- read-time `dir_addname_coherent` — ineffective (CLEAN-only, skips in-AIL).
- destage graft `dir_write_merge=1` — HARMFUL (bnobt double-free shutdown).
- `inode_mht_ms=800` — passes short runs but WEDGES bast_work_fn under sustained 8-node load.
[[sess31-KEY-loss-is-async-destage-TOCTOU-create-and-read-merges-ineffective]] [[sess31-mht800-mitigation-passes-but-wedges-under-load]]

### RELIABLE REPRO (use this — loss at ROUND 1, ~1 in 2 runs, NOT reuse-dependent)
Reboot all 8 (clears mounts so insmod modargs apply — run.sh REUSES the mount otherwise), then:
`MXFS_EXTRA_MODARGS="dir_writeprobe=1" MXFS_TEST_ENV="DRC_ROUNDS=8" timeout 520 ./run.sh 8 tcp dir_reuse_coherency`
Loss = node1_f4.md5, 799/800. Clobber = P-WMERGE in `/root/drc_create_r1_rank<N>.dmesg` (CREATE-phase snapshot, NOT the verify drc_fail dmesg). Harness: `tests/tcp/drc_repro_loop.sh ITERS MODARGS ROUNDS` (reboots+loops). Modargs are insmod-style (NO `mxfs.` prefix). Launch background loops with `setsid ... </dev/null &` (plain nohup gets reaped); poll the LOG for "HIT" (steve can't write /root).

### NEXT SESSION
RULE-4 instrument WHY create-time `dir_merge` is ineffective: does mxfs_dir_merge_peer_into_tp (xfs_inode.c:1725) fire on the .md5 create, re-add node1_f4.md5, yet the destage still revert it? Likely a cross-block free-slot relocation issue OR the merge snapshot stales before the async destage. The correct fix is to make every in-core dir block COHERENT-with-disk before any destage — candidate: at EX acquire-evict (we hold EX, disk frozen → no TOCTOU), transactionally merge peer entries into in-AIL stale blocks (the acquire-evict currently CAN'T invalidate in-AIL blocks — that's the gap). Gate any new lever default-off to keep the keeper safe.

### State: cluster rebooted clean, default config, all nodes up, build 37A37B10. CRITERIA (8/tcp 100%) NOT MET — do not write YES.
</body>
