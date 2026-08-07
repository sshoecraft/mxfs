---
name: ccloop-c7ee71c6-sess110-blocker5-LANDED-and-P241-VERIFIED-on-rig
description: sess110: blocker 5 LANDED + 0.11.440 DEPLOYED and MEASURED — the sess106 st_unset population is GONE fleet-wide, mint+adopt VERIFIED on 32 nodes.
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, dlm-caw, direct-handoff, verified, rig]
---

# sess110 — blocker 5 landed, and the sess108+109 producer half is RIG-VERIFIED

**0.11.440, srcversion `DF0E1ABC1CEA16331E2DF6C`, DEPLOYED to 32/caw (72s) and
MEASURED.** Prior: `…sess109-adopt-validation-LANDED-blocker3` (adopt half),
`…sess108-handoff-mint-LANDED-and-defects-table` (producer half),
`…sess106-P241-MEASURED-direct-handoff-mints-no-epoch` (the root).

## Blocker 5 — the AG epoch now comes out of the granting CAS

`mxfs_v5_dlm_ag_lock()` / `_ag_lock_nb()` (`dlm/v5_mount.c`) gained a
`struct mxfs_grant_result *gres` out-param, `mxfs_grant_result_init()`-ed
BEFORE the `!ctx` / `withdrawn` early returns and passed into
`mxfs_dlm_caw_lock`. All three call sites are in `__mxfs_ag_dlm_lock`
(`xfs/xfs_mxfs_dlm.c` ~34957 nb arm, ~34976 P1-AGWAIT probe, ~35058 blocking
fall-through); one `ag_gres` local serves all three because each call re-inits
it and only the last one to return 0 reaches the epoch block. Verified no
`goto`/label in 34605-35120, so the epoch block is unreachable without a lock
call.

The consumer at the old `mxfs_v5_dlm_ag_grant_epoch()` site now requires all
three of: `mxfs_grant_result_proving()`, `kind == MXFS_LTYPE_AG`, and
`resource == pag_agno(pag)`. Anything else publishes epoch 0 and, on CAW only,
logs **`P243-AGAUTH-UNBOUND`** (capped 200).

**DELETED with their only callers**: `mxfs_v5_dlm_ag_grant_epoch()`
(v5_mount.c/.h) and `mxfs_dlm_caw_read_ex_grant_epoch()` (dlm_caw.c/.h). Each
site keeps a comment saying why an out-of-band epoch read can never be bound to
the caller's grant, so it does not get reintroduced.

## Board lap — 4/4 PASS, no RULE-0 regression

| criterion | sess110 | sess106 | budget |
|---|---|---|---|
| rsync_paired | 15s | 14s | 60s |
| cache_coherency | 23s | 23s | 60s |
| dir_reuse_coherency | **105s** | 113s | 120s |
| dirent_durability | 64s | 63s | 240s |

32/32 nodes each. hostload 12.8-21.2. dir_reuse improved 8s — the direct
handoff is the pace-setting path and the mint added no measurable cost.

## THE MEASUREMENT — the sess106 defect population is GONE

`P241-AUTHTRY nonewr_samegen=0 nonewr_stalegen=0 by_try: none` on **all 32
nodes**. sess106 had `nonewr_samegen=7117 by_try: st_unset=7117` on test1 and
8 on every other node. Zero failed install tries fleet-wide.

Cluster probe tallies (`tests/step53_handoff_probes.sh 32`):

- **P6H-HANDOFF 7372, `gep=0` count 0** — every direct handoff mints.
- **P6H-ADOPT** 11334 post-reload: `st=1` (WRITE_EPOCH, proving) 2156,
  `st=2` (NONWRITE_MODE, benign) 8111, `st=0` 1067.
- **gep vs reg_gep: advanced 9950, equal 1384, regressed 0.** No adopt ever
  saw the epoch go backwards.
- **P6H-ADOPT-REFUSE 0, P242-GRANT-UNSET 0, P243-AGAUTH-UNBOUND 0.**

Zero refusals on a uniformly-0.11.440 fleet is the expected shape (the
`unminted` arm exists for the mixed-version case), and zero
`P243-AGAUTH-UNBOUND` says every fresh AG EX acquire published a bound epoch.

## Two follow-ups this measurement opened

1. **`st=0` is `gres == NULL`, NOT `UNSET`.** The emit prints
   `gres ? gres->status : 0` and `caw_grant_result_fill` always sets a status
   for a non-NULL gres, so all 1067 are callers that passed NULL and therefore
   *cannot* install authority. Fail-closed, but it is an unmeasured 9.4% of
   adopts. NEXT: give the probe a distinguishing field (e.g. `hasg=0/1`) instead
   of overloading `st=0`, then census which inode-lock callers pass NULL.
2. **`equal=1384`** should be entirely non-write adopts — the `unminted`
   refusal only fires under `mxfs_mode_can_write(ad_held)`, and REFUSE is 0, so
   by construction none of the 1384 can be write-capable. Cross-tabulate `st`
   against the advance classes to confirm rather than infer.

## Harness traps hit this session (both cost a wrong first answer)

- **`grep -o 'PROBE[^\n]*'` is broken.** Inside a bracket expression `\n` is
  literally backslash-or-n, so the match truncates at the first letter `n` —
  `P6H-HANDOFF ino=…` became `P6H-HANDOFF i` and every field histogram came
  back empty, which reads exactly like "the field is missing". grep is
  line-oriented already: select the line, then `sed -n 's/.*\bfield=\([^ ]*\).*/\1/p'`.
  `tests/step53_handoff_probes.sh` carries this warning in a comment.
- **dmesg survives the module reload.** 30657 raw P6H-ADOPT lines were only
  11334 from 0.11.440; the other ~19.3k were pre-reload and have no `gep=`/`st=`
  field at all. Always scope to post-reload before tallying.
- `tools/mxfs_sshpass.sh` takes a BARE host (`test1`) — it prepends `root@`
  itself. Passing `root@test1` yields `root@root@test1` → "Permission denied",
  which looks exactly like a credential failure.

## NEXT

Blocker 6 (adopt-vs-reconcile linearization — audit `caw_drop_own_waiter`),
then 8/9/10. The `st=0`/NULL-gres census above is cheap and should ride along
with the next probe build.
