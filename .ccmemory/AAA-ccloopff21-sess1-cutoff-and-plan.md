---
name: AAA-ccloopff21-sess1-cutoff-and-plan
description: ccloop ff214062 sess1: host crash recovered (SCST stale /etc/scst.conf, /tmp/.mxfs_pass wiped), 32 nodes back up on 0.10.74. Cutoff 2026-07-12T20:17:…
metadata:
  type: project
---

## Context
Prior run (daf50d34) got 0.10.74 (srcversion 84FCBF6FF9F30138E2B5836) to close the
mkdir_storm dirent-loss family (iget-vs-inodegc gcwait fix). Was mid-way through the
final single-build ladder sweep (32/caw g1 group running) when **clyde (host) crashed**
around 2026-07-12 14:36 local (19:36Z) — hard reset, uptime reset to 0.

## Recovery performed this session (ff214062 sess1)
1. `systemctl status scst` was failed: `/etc/init.d/scst start` restores a STALE
   `/etc/scst.conf` (auto-generated long ago) that references a nonexistent backing
   file `/home/steve/disk-1.img` (device names disk1/disk1b/disk2, target
   iqn...:disk1 — none of this matches the project's actual naming). This systemd
   unit is NOT this project's SCST mechanism and should be ignored/not relied on.
   FIX: `sudo scripts/scst_setup.sh setup` (uses sysfs mgmt directly, real backing
   file `/home/steve/disk.img` 50GB, device "mxfs", target
   `iqn.2026-05.local.mxfs:shared`) — this is the actual, correct, idempotent path.
2. `/tmp/.mxfs_pass` (SSH password file used by every test/ssh helper) was wiped by
   the host reboot (/tmp is tmpfs-like/ephemeral here). FIX:
   `cp /home/steve/.mxfs/pass /tmp/.mxfs_pass && chmod 600 /tmp/.mxfs_pass`
   (memory `env-cluster-bringup-after-host-reboot` already documented this — reused
   it directly). Symptom if missed: mpath_up.sh / ssh_node calls silently return
   empty output, look like "all nodes FAIL" with no error text.
3. All 32 VMs were shut off (host crash took the guests down too). FIX:
   `scripts/mpath_up.sh up 32` self-heals via virsh destroy/start per node — brought
   all 32 to 2-path /dev/mapper/mpatha in one shot (after fixing #2, since node_ensure's
   ssh calls need the pass file to do anything).
4. Verified all 32 nodes: kernel 6.8.0-101-generic (matches vermagic), /src NFS
   reachable, mxfs.ko NOTLOADED (clean state, expected — run.sh's prep_cluster loads
   + srcversion-verifies fresh every run via the NFS-shared /src/mxfs/mxfs.ko, no
   separate deploy step needed/exists).

## Corrected understanding: category "suite" vs "criteria" dirs
`tests/criteria/*.sh` (e.g. `tests/criteria/soak.sh`, 1hr SOAK_HOURS default) is a
STALE/UNUSED parallel implementation. The ACTIVE harness resolves
`$REPO/tests/$cat/$name.sh` where `$cat` = criteria.json's `"category"` field, which
for the standard 17-test matrix is `"suite"` -> `tests/suite/<name>.sh`. E.g. actual
`soak` test = `tests/suite/soak.sh`, SOAK_SECONDS default 30 (fast smoke, NOT 1h).
Don't waste time re-reading tests/criteria/*.sh for behavior — read tests/suite/ or
tests/caw/ instead (whichever the criteria.json category says).

## Plan / cutoff
matrix_check.py showed (before this session's fresh runs): 1/2/4/8/16 caw = 17/17
PASS each, but 32/caw = 12/17 (5 PENDING from the crashed run: scaling_curve,
dlm_scaling, rsync_paired, soak, dlm_lock_correctness — auto-FAIL once fail_stale_pending
runs on next run.sh invocation).

**Concern carried from daf50d34 sess1**: passes for 1/2/4/8/16 span builds 07-06→07-12,
"no single build has swept the matrix" — provenance murky, some may predate the 0.10.71/
0.10.73/0.10.74 storm-family fixes. Decision: re-run the ENTIRE ladder (1,2,4,8,16,32)
fresh on 0.10.74 this session for honest single-build provenance, all with
MXFS_DEV=/dev/mapper/mpatha (multipath, per criteria), via `scripts/revalidate_cell.sh
<N> <g1|g2|dr|nodr|full>`.

**Cutoff timestamp for final YES gate: 2026-07-12T20:17:47Z**
Final check: `python3 scripts/matrix_check.py --since 2026-07-12T20:17:47Z` must show
1/2/4/8/16/32 @ caw all 17/17 before writing YES.

Order: 32/caw g2 (canary, small) -> 32/caw g1 -> 32/caw dr (dir_reuse, ~75min) ->
16 (nodr+dr) -> 8 -> 4 -> 2 -> 1 full each.

Long-run pattern (CLAUDE.md dev note): nohup setsid + background, foreground poll
loop `timeout <=290 bash -c "until grep -qE 'CELL-GROUP (OK|NOT-CLEAN)' log; do sleep
N; done"` repeated across turns — Bash tool foreground cap is 10min/600000ms, tests
run much longer (dir_reuse@32 budget ~140*32+900=5480s).
