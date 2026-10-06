---
name: trap-chk-mxfs-on-a-filesystem-with-unreplayed-journals-reports-stale-lazy-counters-as-errors
description: TRAP (0.90.71): chk_mxfs -n after withdrawn (never cleanly unmounted) mounts erred "inobt free 102 != sb ifree 115"; mount once, unmount cleanly, rec…
metadata:
  type: feedback
---

**What happened (2026-10-06, physical PVE pair):** both DRBD mounts had withdrawn
(authority lease expired at 10:46 on 0.90.68), and the units were then stopped,
which unmounts a shut-down filesystem without writing anything. `chk_mxfs -n
/dev/drbd0` returned rc=4: `ERROR: inobt total free inodes 102 != superblock
ifree 115`, and the superblock's fdblocks read 8286699 against an AGF/BNO sum of
6903535. It advised `-a` / `-y` repair.

**Why it is not corruption:** XFS v5 keeps icount/ifree/fdblocks lazily. They
are written to the superblock only at a clean unmount or freeze, and a mount
after an unclean stop recalculates them from the AG headers. Both journals still
held committed transactions: the replay at the next mount allocated 358622 blocks
(1.37 GiB). Checked again after one mount on 0.90.71 and a clean stop: rc=0,
ifree 102 = 102, fdblocks = BNO sum + 76, which is 4 AGFL blocks x 19 AGs.

**How to apply:**
- Never act on a `chk_mxfs` counter finding from a filesystem whose last
  unmount was not clean (withdrawn, crashed, fenced). Mount it once so the
  journals replay, unmount cleanly, and check again. Only a mismatch after a
  clean unmount is a finding.
- Never run `chk_mxfs -y` / `-a` on such a filesystem. Its journal check
  rewrites DIRTY slots as CLEAN (tools/chk_mxfs.c ~1788), and dlm/journal.c:1600
  skips the replay of a CLEAN slot. Defect queue:
  D-CHK-MXFS-FLAGS-LAZY-COUNTERS-OF-A-DIRTY-JOURNAL-AND-ADVISES-REPAIR.
- `scripts/pve_pair_update.sh CHECK=1` stops at such a finding, by design. The
  path that settled it: `SKIP_INSTALL=1` (mount), then `SKIP_INSTALL=1 CHECK=1`
  (clean stop and check). Evidence:
  tests/evidence/pve_phys_drbd_20261006/update-0.90.71*.log.
