---
name: sess15run-FIXH-orphan-release-eats-fresh-grant-ROOT
description: sess15 ROOT+FIX-H (CBD34F20): P135 orphan-release ate own just-granted tenure (grant-completion window) → double-EX → dirent swallow. sess14 interp i…
metadata:
  type: project
---

# sess15 FIX-H — the one-dirent swallow ROOT: orphan release eats fresh grant

## sess14's interpretation was INVERTED
r10 capture re-read with per-node mono↔realns decode (N6 realns is ~1.03s
offset from its mono vs N4 — the prior session compared FRACTIONAL realns
across nodes and mis-assigned tenure order). Truth from
/tmp/run_dir_reuse_coherency_20260704T201007Z/test6_drc_fail_r4_rank6.dmesg:

- 334.1924 N6 P135-ORPHAN-RELEASE ino=540021 (in-core NONE/NL, mirror held)
- 334.1928 N6 P63-HANDOFF grant_gen=9252 — its own slow-path acquire GRANTED
  (receive kworker links mirror BEFORE the blocked acquirer thread resumes;
  mxfs_v5_dlm_inode_held on TCP reads that same LOCAL MIRROR → the P135 gate
  misread the grant-completion window as an orphan)
- The queued bast_process ran in the [mirror-link → holders++] gap:
  entry_gen==rel_gen==9252 (gen_moved=false), holders==pin==0 (dd still in
  post-grant reload; P71-HOLD holders++ only at .19335) → every abort check
  passed → wire-released the LIVE tenure with a valid gen echo
- Master freed 9252 → granted N4 gen 9253 0.7ms later (N4 P63-HANDOFF
  335.8606) → TRUE DOUBLE-EX
- N6 P106-STALE-EX on_disk_held=0 at .6541 (mirror unlinked by the self-eat),
  kept operating (pin=1 create): FUA-read 73-base, added node6_f9@off=1800;
  N4 added node4_f9@off=1800 under its (valid) 9253; N6's writeback crc=45fb2864
  won → node4_f9 durably swallowed (799/800)
- N4 ran the IDENTICAL shape same second (P135 .8606 → grant 9253 .8606) and
  survived only because dd's pin landed before the recheck (P15 abort pin=1).
  Coin flip = the ~1-in-2 iter failure rate.

## FIX-H (build CBD34F20, xfs_mxfs_dlm.c)
1. bast_process P15-recheck backstop: abort when
   `p_held_mode==MXFS_LOCK_NL && p_rel_gen != 0` (cleanup-flavor instance vs
   live-gen tenure). Abort state = CACHED + bast_pending (same as
   pin_only/gen_moved). P15-REL-ABORT print gained `orph=` flag.
2. bast_notify P135 queue-time gate: query grant_gen next to inode_held;
   `held==1 && gg!=0` → P135-GRANTWIN-PARK: set bast_pending, arm MHT dwork
   (bastq_src=13), DO NOT queue the orphan release. `held==1 && gg==0` keeps
   the old orphan-release path (CAW disk-slot semantics unchanged — grant_gen
   is always 0 on CAW).

## Known residual candidates (NOT yet addressed, on purpose — one fix at a time)
- P6Z reconcile flavor: mxfs_v5_dlm_inode_release_unconditional (gen=0
  mirror-bypassing) still has a [stranded-sample → master-processing] window
  (xfs_mxfs_dlm.c ~12064-12083). Candidate hardening: refuse under
  table_rwlock in dlm.c mxfs_dlm_send_unconditional_release if a local-owner
  GRANTED/CONVERTING entry exists; caller treats -EEXIST as stranded.
  Needs evidence before landing (watch P-PHANTOM-RECONCILE-SENT adjacent to
  fresh grants).
- Stranded-grant livelock: if a granted mirror entry is NEVER consumed
  (no known producer), GRANTWIN-PARK + backstop abort ping-pong on the peer's
  6s retries. Watch for repeating P135-GRANTWIN-PARK same-ino streaks.

## Validation state at write time
Not yet run. Plan: 8/tcp suite_iter (drc is the proving face; ~1-in-2 iter
repro pre-fix), then 2/4/1 columns, then accumulate repeats. Column status
pre-fix on 4D677327: 8/tcp 17/17,17/17,15/17; 4/tcp 17/17; 2/tcp 17/17×2of4;
1/tcp 16/16.
