---
name: sess43-scst-unwedge-and-p136
description: sess43: SCST unwedge tooling; P136 rescue (7BD3933D) stops cluster shutdown; REAL blocker = COLD 16-node concurrent shared-dir create loses entries (…
metadata:
  type: project
---

## Working criterion #19 `posix_semantics_multi16` (last gate FAIL)

`tests/criteria/posix_semantics.sh`: runs `run_tests.sh --phase all` (single +
cluster) on test1-16, asserts 0 FAIL, 600s timeout. Build identity = srcversion
(no MODULE_VERSION macro). **Current build 7BD3933D (P136 rescue, KEEP).**

## SHARP FINDING (sess43): lost-update is COLD-cache only

- `test_concurrent_mkdir` run STANDALONE on a WARM cluster (after reset4 mount
  churn) → **PASS**.
- Same test run FIRST in a cold `--phase cluster` right after mount →
  **FAIL: dir count 781/800** (19 lost); concurrent_touch 1599/1600; concurrent_
  write fails. All in the FIRST ~3 cold tests, then cross_visibility onward PASS.
- => The bug is **16-node concurrent create into a SHARED parent dir with COLD
  caches**: block-format parent (800 entries), each node EX-adds its dirents; a
  node's EX-acquire reads a STALE parent dir block (missing a peer's just-
  committed entries from the SCST write-cache vs FUA/platter gap), adds its
  entry, writes → DURABLY clobbers peer entries. This is the sess83/88/90 dir-
  block durable lost-update, still incomplete at 16-node cold first-touch.
- NEXT SESSION: instrument the dir-block EX-acquire read path (xfs_da_read_buf /
  the dir add in xfs_dir2) to log when the freshly-EX-acquired parent dir block
  has FEWER entries than a peer's last-committed count (stale read). Likely fix =
  same P34D cache-coherent (plain, not FUA) re-read when fua_disable=1, applied
  to the dir-DATA block read on EX-acquire (sess42 P34D fixed it only for the
  dinode reload path). Reproduce with the COLD full `--phase cluster`, NOT
  standalone (standalone warms the cache and hides it).

## METHODOLOGY: contaminated state gives false hangs

Killed runs leave orphaned find/rm/mkdir holding ilocks → next run HANGS in
SESS50-STARVE (rm/find D-state in mxfs_dlm_ilock_begin) — NOT a real bug, just
contamination. ALWAYS before trusting a result: kill remote orphans on all 16
(`pkill -f "run_tests|mxfs_test|find /mnt|rm -rf /mnt"`) AND prefer a full
`scripts/cluster_reset_n.sh 16` + `reset4.sh 16`. A clean concurrent_mkdir
standalone PASSES — don't chase the contaminated hang.

## SCST host wedge recovery (REUSABLE — saved hours, RULE 2: never reboot clyde)

`scst stop` hangs in D-state, suspend=1, threads in scst_susp_wait. Root:
destroying all 16 VMs mid-I/O aborted a COMPARE AND WRITE (op 0x89) while
overlapping READ(10)s were scsi-atomic-blocked on it → A↔B deadlock cycle;
scst_unblock_aborted_cmds only walks blocked/deferred lists, leaks atomic-
blocked cmds. Recovery (built this session, KEEP):
- `scripts/scst_atomic_wedge_diag.py` (gdb -P): walks **vdev_list** (NOT
  scst_dev_list — mid-unregister devs unlinked from it) via /proc/kcore with
  scst.ko+scst_vdisk.ko DWARF; section addrs from `/sys/module/scst/sections/*`
  (must run as root cd'd into that dir); kallsyms() for list heads. Prints each
  cmd's scsi_atomic_blockers/blocked_cnt → identify the CAW (op 0x89,
  blocked_cnt=N) and one blocking READ.
- `scripts/scst_unwedge/` module: `insmod scst_unwedge.ko blocker=0x<READ>
  blocked=0x<CAW>` — under dev_lock verifies A↔B topology then frees blocker's
  array, zeros CAW blockers, requeues CAW on cmd_threads active list. Suspend
  completes instantly. Offsets verified identical vs running scst.ko first. Then
  `rmmod scst_unwedge; systemctl restart scst`.

## NFS export evaporates after host churn
Re-add: `sudo exportfs -o rw,sync,no_subtree_check,no_root_squash,fsid=4321
192.168.120.0/24:/src/mxfs` (needs fsid=). Remount each node:
`mount -t nfs 192.168.120.1:/src/mxfs /mnt/mxfs-src`.

## P136 drain-rescue (build 7BD3933D, KEEP — verified)
With 863173A4 every run ended cluster-wide-shutdown: test4 P113-DRAIN-WEDGE
ino=136 → IFLUSHING set, li_buf XBF_DONE not on delwri, write NEVER submitted →
iodone never runs → AIL item orphaned → EX never released → 15 peers STARVE 120s
→ SHUTDOWN_CORRUPT_INCORE. FIX in `mxfs_ail_drain_inode_sync`: at iter≥512, if
IFLUSHING && pin==0 && buf not on delwri && trylock && b_list empty →
delwri-queue+submit the orphaned cluster buffer (P136-DRAIN-RESCUE). Verified
fired test10 ino=23076639, no shutdown. P113 print extended (last_fields/
iflushing/rescued/lb_err).

Cluster left clean, orphans killed, 7BD3933D on all 16. Marker NOT written.
