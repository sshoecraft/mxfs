---
name: ccloop-c7ee71c6-sess23-P32E-is-the-discriminator
description: sess23: P32E-DIREPOCH-FENCE is the ONLY marker that is 0 on every passing run — the sharp target for catching the silent-loss chain; storm no longer…
metadata:
  type: project
tags: [ccloop-c7ee71c6, sess23, D-SILENT-MKDIR-LOSS, P32E, discriminator]
---

# sess23 — P32E-DIREPOCH-FENCE is the discriminator

## The measurement

Three independent PASSING runs on 0.11.194 (`BDD132E1285CDEB945565F1`), all
window-scoped: 16-node `dirent_durability`, 16-node 60-round storm, 32-node
60-round storm.

| marker | passing runs | in sess22's captured LOSS chains |
|---|---|---|
| **P32E-DIREPOCH-FENCE** | **0, always** | **present in every one** |
| P34J-RELOAD-RACE-BAIL | 105-108 | present |
| P189-RELOG-BEHIND-DISK | 21-62 | present |
| P198-RELOAD-DEMOTE-WAITED | 187-475 | n/a (sess22's fix, working) |
| P195-STALE-BASE-ALREADY-DIRTY | 0-2 | present |
| P188-REL-OBLIGATION-AT-UNLOCK | 0 | present |
| P177-OBLIGATION-DROPPED-AT-ADOPT | 0 | present |
| P146V-UNLANDED | 0-2 | present |

**P32E is the ONLY marker that is zero on every passing run.** P195, the race
bail and P189 all fire freely on clean runs, so none of them is the predicate
for the loss — which independently confirms the separate finding that P195 is
neither necessary nor sufficient.

P32E is the mechanism that "silently drops every flush of whatever the
operation goes on to commit" (sess22's chain). It is the sharpest available
signal and the right thing to hunt.

## The one measurement that settles H2

0.11.194 adds `i_mxfs_racebail_ns`, stamped when `P34J-RELOAD-RACE-BAIL`
abandons a reload, and P32E now prints `racebail_age_ms=`.

Catch ONE run with `P32E > 0` and read that field:
- small `racebail_age_ms` (the inode race-bailed milliseconds earlier)
  -> **H2 PROVEN**: the race bail is the second producer, and the fix is the
  sess22-shaped bounded RETRY of the reload instead of abandoning
  (lever `mxfs.reload_race_retry_ms`, paired A/B, cost measured — sess22's
  analogous wait cost 2.3s cluster-wide over a 120s storm).
- `racebail_age_ms=-1` (that inode never race-bailed)
  -> **H2 REFUTED**; the producer is elsewhere, look at what else can leave
  `i_dlm_dir_valid_epoch` behind the master `dir_epoch`.

`tests/dd_loss_capture.sh N 16` loops `dirent_durability` until it FAILS and
harvests exactly this census plus full dmesg. ~85s per iteration.

## Reproducer status — the storm is no longer the tool

`tests/sf_mkdir_storm.sh 60 32 2 1` on a FRESH prep — state.md's designated
reproducer, reliable pre-sess22 — now **PASSES 60/60 on all 32 nodes**, and also
passes at 16. The only reproduction this session was `dirent_durability`
@16/caw: 1 failure in ~12 runs (`durable_loss=3 mkdir_err=0`).

**RULE 6: this is NOT evidence of a fix.** The rate dropped; the defect has no
disposition. But stop spending runs on the storm — use `dd_loss_capture.sh`.

## Build state
0.11.194 = 0.11.193 (the NULL-contract panic fix) + the racebail stamp + the
P32E `racebail_age_ms` field. 32/caw prepped clean in 58s; 16/caw in 39-53s.
