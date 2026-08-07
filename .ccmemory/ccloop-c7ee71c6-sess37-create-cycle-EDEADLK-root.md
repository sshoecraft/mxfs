---
name: ccloop-c7ee71c6-sess37-create-cycle-EDEADLK-root
description: sess37 last capture: create = lookup-PR → EX upgrade DENIED (DLM inode lock failed mode=5 rc=-35 EDEADLK) → drop+drain → fresh EX, per create; + P-DI…
metadata:
  type: project
---

# Create-cycle root capture (test5, instr=1, r=6 create window, dir ino=537845, 0.11.317)

Timeline inside ONE create wave (dmesg, test5 ~19679.4-19679.6):
1. P-DIRBAST ×4 at state=0 mode=0 — peers' BAST resend loop hammers NON-holders too (wasted notify traffic; resend targets should be the holder set only — check caw_send_bast_mcast targeting).
2. P138-WAIT mode=3 caw_try=7 caw_miss=6 — the lookup-half PR acquire pays a 7-attempt CAS storm (PR claims outside the streak batch still storm; possible lever: extend direct-grant to PR singles when slot is PR-compatible and no EX waiter).
3. Full reload machinery runs on the dir (P65-EPOCH-ADOPT/P63-HANDOFF/P62/P56 — cross-node EX handoff forcing reload) — per PR re-entry, the dir reloads from platter (disk_size=39 shortform adopt).
4. **`mxfs: DLM inode lock failed: ino=537845 mode=5 rc=-35`** — the create-half EX acquire fails EDEADLK. The sess51 comment (dlm_caw.c ~11960) describes this exact shape on TCP: both nodes cache PR from bash open(O_CREAT)'s lookup half, both want EX, upgrade denied → loser drops PR→NL through the FULL drain pipeline then re-requests fresh. Now proven live on CAW at 32 nodes.
5. P70-BP ENTRY mode=3 selfdem=1 qsrc=6 — self-demote dwork arms on the dir (src=6 site, dlm_caw ~27698 region) adding release traffic.

## Per-create cost structure (explains 214 dir transitions/round and the zero-margin 8 rounds)
lookup-PR (CAS storm) → reload → EX upgrade → EDEADLK → PR drop + FULL DRAIN → fresh EX acquire (rotation wait) → insert → EX stripped → repeat. ≥3 wire transitions + 1 drain + 1 reload PER CREATE.

## Fix directions (next session, in leverage order)
A. **Create-intent EX-first**: VFS passes LOOKUP_CREATE intent — when the lookup is for a create in a dir we'll insert into, request the dir at EX for the LOOKUP half (skip the PR half entirely). Kills the whole cycle: 1 EX tenure per create (or per wave if tenure batching then holds). Check mxfs_dlm_ilock_begin's mode selection for the lookup path (where PR is chosen) and whether dentry lookup under dir EX is already coherent (it must be — EX ⊃ PR).
B. **Upgrade-in-place on CAW**: convert path (dlm_caw.c ~4790 compatible-upgrade CAS) — measure why the upgrade DENIES instead (other PR holders present = genuinely incompatible; but with upgrader priority (sess130) + direct-handoff, the releaser could hand EX to an UPGRADER (relax the last-holder condition: holders subset of {W} → grant + clear old mode in same CAS — noted in sess37 transcript as the upgrade-handoff extension).
C. P-DIRBAST non-holder spam: bound the resend targeting.
D. PR-single direct grant (see 2 above).

## Status: dir_reuse first PASS (58/58, exactly 8 rounds) on 317; margin zero; defect OPEN. 8 OPEN total. Criteria NO.
