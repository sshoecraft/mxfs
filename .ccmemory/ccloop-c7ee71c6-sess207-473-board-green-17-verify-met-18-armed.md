---
name: ccloop-c7ee71c6-sess207-473-board-green-17-verify-met-18-armed
description: sess207: 0.11.473 (sv 3157B6269F6FBDBDBDEC384) NL-setter instr deployed; FULL board green; #17 VERIFY criterion MET on aged fs (PENDGRAFT graft, 0 LI…
metadata:
  type: project
---

# sess207 — 0.11.473 instrumentation build, board green, #17 verify met

## Build 0.11.473 (sv 3157B6269F6FBDBDBDEC384), deployed 32/caw
#18 NL-setter forensics landed:
- xfs_inode.h: i_dlm_nl_line/pid/ns/om/comm[16] near i_dlm_mode.
- mxfs_dlmtr_rec: stamps last granted->NL lowering for EVERY inode (before
  the watch_ino gate), condition mode==NL && om!=NL.
- mxfs_dlm_inode_init: zeroes the 5 fields AFTER the two init dlmtr_rec
  transitions (recycled-slab om would garbage-stamp them).
- mxfs_dlm_open_protect: sn_* snapshot under i_dlm_lock at the post-ride
  re-read; P95-OPEN-PROTECT-FAIL now prints mode/state/exh/prh/acq/iclus/
  unpub/stale/ssrc/imode/gen/open_n/selfc/reusedc/nl_line/nl_om/nl_pid/
  nl_comm/nl_age_us.
TRAP: make clean wipes tools/ binaries — `make tools` needed before prep
(prep FAILs on missing mkfs_mxfs).

## Board on 0.11.473 — ALL functional cells PASS
Chunks (run_ids 20260810T145131Z..T150608Z): 1a precond/fio/fio_vs_xfs/cc,
1b strong/posix/mmap/zsl, 2a dlm_fairness/membership/scaling_curve/
dlm_scaling, 2b rsync_paired/crash_consistency, 3 dir_reuse/fence/
netpartition/soak, 4 dirent_durability/node_responsive/kernel_health,
5 ag_strand/sustained/publish_int/type_int/open_defects.
- crash_consistency 32/32 204 checks 83s/90s — the board's
  NO_TERMINAL_RECORD=32 red CLEARED (was a capture failure under
  first-run-after-marathon slowness, not reproduced).
- zero_silent_loss 29s/60s (sess204's chunk-1 timeout not reproduced).
- open_defects FAIL = RULE 6 policy cell only.

## #17 D-IUNL-LIVESKEW — ledger VERIFY criterion MET (close next session)
Ledger VERIFY: 4+ overwrite laps 32/caw; zero P53 fatals/shutdowns;
PENDGRAFT/POSTSTATE observed or zero LIVESKEW. Evidence on .473 (same fix
as .472 + forensics only):
- 38 overwrite laps on SAME fs (30 fresh + 8 board-aged), all PASS 32/32.
- Preconditions REAL: P-IUNLSTORE-GENSKEW ~314/node, P-IUNLSTORE-OVERLAY
  ~16/node fleet-wide (sess204 fresh-fs soak was vacuous, OVERLAY=0).
- P-IUNLSTORE-PENDGRAFT ×1 test24 15:09:45: "cert={0xf5->0xffffffff} —
  skew explained by pending transition; grafting committed value".
- ZERO P-IUNLSTORE-LIVESKEW / force_shutdown / withdraw fleet-wide.
- test27 P53-IUNLINK-MISMATCH 15:10:41 BENIGN: old_ptr==next_agino=0x9c8,
  resolved P53-IUNLINK-IDEMPOTENT no-op (free/reuse race), no shutdown.

## #18 P95 — instrumentation armed, no refire yet
Zero P95 on .473 across 38 laps + full board (only sess206's old test19
13:52:49 line persists in dmesg). Keep lapping on the AGED fs (do NOT
re-prep — mkfs de-ages). On refire the enriched print names the NL setter
via nl_line; then RULE-5 consult (retry-acquire vs -ESTALE vs -EIO).
