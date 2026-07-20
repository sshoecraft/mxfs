---
name: AAA-ccloopa864-sess2-FIXES-and-B8-status
description: sess2: dir_reuse@32 root = stuck/orphaned on-disk EX holder at reuse. TWO fixes built (v0.10.45 4E1FA7B6): acq-side self-EDEADLK + holder-side stale-…
metadata:
  type: project
---

# dir_reuse@32 — root fixes + B8 status

## ROOT (proven, B6/B7 P-ACQ-STUCK probe): stuck/orphaned on-disk dir-EX holder at reuse boundary
A peer ends up holding the shared-dir (ino=131) on-disk EX bit but its release never lands, wedging all 32 nodes 360s -> rc=-110 cascade. Two variants seen:
- **B6 variant (acquire-side self-deadlock)**: holder's incore state reset to NL by the inode reuse; it then tries to ACQUIRE (PR) and its OWN stale EX bit blocks it (is_compatible fails). Stuck in caw_wait_for_grant forever.
- **B7 r4 variant (holder-side stale DEMOTING)**: test28 held EX (bit27, slot 46987), entered state=DEMOTING to release for a peer BAST, but the demote work went stale (work_busy=0, lost-work race) -> P72-SWALLOW-DEAD ×3000 (swallows every peer BAST at the DEMOTING gate) -> never releases.

Both = the on-disk holder bit persists because incore state doesn't drive the release. resource_id lacks inode-gen so reused ino131 = same CAW slot inherits prior tenure's bit (AAB-dlm_scaling32 family).

## FIXES (v0.10.45 srcver 4E1FA7B6, B8 RUNNING)
1. **v0.10.44 acquire-side** (dlm_caw.c caw_wait_for_grant, after read_slot+magic check): if node_held_mode(slot, self)!=NL && !is_compatible(slot, mode) -> return -EDEADLK (self-hold blocks own acquire). Routes to the PROVEN main-loop bast_process recovery (drain+clear disk bit+NL, retry). Probe P-SELF-STALE-EDEADLK. NOTE: was INERT in B7 (0 fires) — the main-loop P109-EDEADLK (test1=18x) handled acquire-side; B7 still reached r4 (vs B2-B6 r2/r3) then hit variant-2.
2. **v0.10.45 holder-side** (xfs_mxfs_dlm.c ~14198, P72 DEMOTING-swallow branch): when state==DEMOTING && work_busy==0 (stale), RE-QUEUE bast_work instead of swallowing. Probe P72-STALE-REQUEUE. queue_work succeeds (work idle); if races false, xfs_irele. Targets the B7 r4 wedge.

## Run ledger (all 32/caw dir_reuse, modargs dirwr=1 dirland=1 close_release=0 caw_inode_fastpoll=1 caw_fair_handoff=1, timeout 5200)
- B2 v0.10.39: r3 EX-starve. B3 v0.10.40: r2 PR-starve. B4 v0.10.41: r3 EX. B5 v0.10.42: r2 PR. (all FAIRNESS tuning — WRONG TREE, the real root is the orphan holder.)
- B6 v0.10.43: r2, diagnostic — found orphan (test32).
- B7 v0.10.44 (acq fix): reached **r4** (pace 100/122/133s healthy) then variant-2 (test28 stale DEMOTING) wedge.
- B8 v0.10.45 (both fixes): RUNNING. Watch: get past r4; P72-STALE-REQUEUE fires+clears; full 24 rounds. Also carries B2-B5 fairness changes (yield_set_ms don't-re-arm; NO streak-reset; upgrader-defer INERT) — orthogonal.

## Watch/next in B8
- If it completes 24 rounds -> criteria MET (dir_reuse@32/caw was the ONLY gap; all other node counts + tests PASS). MUST confirm reproducibility (wedge round varied r2-r4, so needs a clean pass + ideally a 2nd).
- If a NEW wedge variant: harvest P-ACQ-STUCK (slot state: hex=holder bit, gen), P72-STALE-REQUEUE (did re-queue fire but not clear? -> bast_process itself fails for the reused inode), which node holds.
- If P72-STALE-REQUEUE storms without clearing -> bast_process can't release the reused-inode hold -> escalate to inode-free-time bit clear (AAB caw_epoch_free_reset extended to holder bit) or RULE-5 Fable consult (criteria met: complete diagnosis, delicate heavily-patched area).

## Ops: after kill, leftover mxfs_sshpass cleanup subshells hold /tmp/mxfs_run.lock (fuser -k). Prep power-cycles shut-down nodes (convergence can FLAKE — 3-consecutive-stable check; just relaunch). Recover SSH-slow: virsh destroy+start (~12s).
