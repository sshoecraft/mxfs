---
name: ccloop-c7ee71c6-sess20-three-roots-and-four-killed-hypotheses
description: sess20: 3 roots proven byte-exact (torn fork; P184 unbounded veto = 29-link revert; stranded CAW AG = 21-node shutdown). 4 hypotheses killed.
metadata:
  type: project
tags: [ccloop, c7ee71c6, sess20, 32caw, sfstorm, torn-fork, p184, stranded-ag, rule5-gpt]
---

# sess20 — three roots proven, two fixed and validated

Build trail: 0.11.150 → 0.11.160 (`CA93F44CC6444662546E4A3`). Reproducer
unchanged: `tests/sf_mkdir_storm.sh 30 32 2 1`.

## ROOT 1 — torn LOCAL fork (FIXED + VALIDATED)

`mxfs_dlm_reload_inode` ran `xfs_idestroy_fork` ~150 lines before
`xfs_inode_from_disk`. `xfs_idestroy_fork` NULLs a LOCAL fork's `if_data` and
LEAVES `if_format=LOCAL` + `if_bytes` (it is written for teardown). The P34J
TOCTOU bail — the ONLY `return` in that window — returns with the fork torn.

Byte-exact, test13 ino=52953231, 514 microseconds:

    151.405249 P34J-RELOAD-RACE-BAIL demoter=1 epoch=5
    151.405763 P181-FORK-TORN if_bytes=100 if_data==NULL mode=040755
    151.412737 P171-SFNULL x11506 -> xfs_dir2_sf_verify -> FS SHUTDOWN

FIX: destroy moved adjacent to `xfs_inode_from_disk`. VALIDATED: 48 P34J bails
→ 0 tears, 0 SFNULL, 0 shutdowns (was 2 bails → 4 tears → 11506 → 4 shutdowns).

## ROOT 2 — P184's unbounded veto (FIXED + VALIDATED)

sess19 added P184-RELOAD-KEEP-OBLIGATION: refuse to adopt the platter whenever
`pending != durable`. **It has no test that we are actually ahead.**

test23 ino=44040339, 11 ms: it protected ONE unlanded mkdir and destroyed 29
links + 29 names. Platter = block-format, 32 entries, nlink 34, chg 35. Our
fork = 3-entry SHORTFORM, nlink 5, chg 7. The drain published ours with full
authority (`relflush=1 held=1`), and printed the proof itself first:
`P146V-UNLANDED incore[nlink=5 LOCAL] disk[nlink=34 EXTENTS]`,
`P32-IFLUSH-NXSHRINK`, `P-CCREGRESS cc_disk=35 cc_writing=7`.

FIX: keep the fork only when provably ahead (nlink ≥ disk AND changecount ≥
disk AND no LOCAL-vs-non-LOCAL regression), plus **P189-RELOG-BEHIND-DISK** so
the P146V re-log arm refuses a behind-disk core.
VALIDATED: P186-NLINK-REVERT 15 → 0; P184 25 → 0 (100% harmful); P146V 141 → 4.

## ROOT 3 — stranded CAW AG grant (FIX IN, UNVALIDATED)

`P5N-AG-ORPHAN-NAK ag=23 disk_held=1` ×120: the AG holder bit is set in the
on-disk slot table while the node has `holders=0 !cached !demoting
!release_pending`. The BAST schedule gate requires `pag_dlm_cached`, so no peer
BAST can EVER schedule that release. sess6's orphan-NAK is a no-op on CAW
(`mxfs_v5_dlm_ag_orphan_nak` returns 0 when `!ctx->dlm`).

Consequence captured 15:01: AG 8 stranded on test1 → test26 waited 240 s on it
while holding dir ino=138 EX + pin=1 → 31 peers starved → 480 s cap →
**21 of 32 filesystems shut down**. Evidence `tests/logs/wedge_ino138_20260728_1501/`.

FIX `mxfs.ag_strand_repair=1`: re-adopt into `pag_dlm_cached` and hand to
`bast_work_fn` (full Invariant-1 drain then unlock). No strand since — watch
for `disk_held=1 repair=1`.

## KILLED WITH EVIDENCE — do not re-chase

- **sf→block conversion**: P185 audits in-core vs a fresh platter read INSIDE
  `xfs_dir2_sf_to_block`. 0 drops, 29/29 clean, every run. The project's
  multi-session "the shortform window is the vulnerable one" framing is wrong.
- **P3-REFUSE-OLDER-DISK**: P3-SFSETS dumps both name sets at each refusal —
  in-core a strict SUPERSET every time.
- **stale RMW base at modify time**: P190 compares platter nlink/changecount in
  `mxfs_dir_modify_adopt_disk_format`. 878 checks, 0 hits; geometry identical
  on both sides (`fmt=2 nx=1 sz=4096`).
- **`pub_skip_rearm=1` LIVELOCKS.** Keeping a skipped inode dirty + in the AIL
  cannot work: the skip happens BECAUSE we lack publication authority, so the
  retry never succeeds. P187 hit its 4000 cap, skip rate 21 → 490, test12
  wedged. Default now 0.

## METHODOLOGY

- Storm run-to-run variance on IDENTICAL builds is 393-563 failing checks.
  **Single-run deltas are not evidence.** Marker counts (P186/P184/P181) are
  causal and moved decisively; the round count did not.
- The P186 nlink watermark MUST be disarmed in `xfs_droplink` — the storm's own
  `rm -rf` teardown produced 812 of 984 false hits before that.
- A storm run leaves the cluster degraded; re-prep before every measurement.
  This session's first two runs were measuring the PREVIOUS session's wedge.

## RULE-5 GPT consult (worth re-reading; first attempt was rejected by a
cyber-policy false positive — reword away from SCSI/LUN/initiator vocabulary)

Its two load-bearing points:
1. **In-flight write ordering across the handoff** is the class not being
   considered: a stale write submitted while ownership was VALID can reach the
   platter after a later tenure's write. A submission-time ownership guard
   cannot catch it — which explains why `dir_nl_require_grant` measured no
   effect. Needs per-inode in-flight accounting + wait-for-zero before unlock.
2. The completion path declaring unsubmitted bytes durable is an unconditional
   defect, but must be repaired UPSTREAM (closed publication barrier), not by
   re-arming at the skip — confirmed empirically by the livelock above.
