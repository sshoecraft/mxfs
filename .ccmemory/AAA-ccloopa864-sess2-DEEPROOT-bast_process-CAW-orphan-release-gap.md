---
name: AAA-ccloopa864-sess2-DEEPROOT-bast_process-CAW-orphan-release-gap
description: sess2 DEEP ROOT: bast_process orphan-release (orphan_live+280-strike) is TCP-ONLY (p_rel_gen!=0, always 0 on CAW). So a CAW incore-NL + on-disk-EX or…
metadata:
  type: project
---

# dir_reuse@32 DEEP ROOT — bast_process never releases a CAW orphan holder bit

## The chain (fully instrumented across B6/B7/B8)
1. dir_reuse@32: rank1 rm-rf+recreates shared dir ino=131 each round. At the reuse boundary a peer ends up holding the on-disk dir-EX bit while its incore i_dlm_mode=NL (inode reclaim reset incore without clearing the disk bit; resource_id has no inode-gen so reused ino=same CAW slot inherits the bit).
2. That stuck holder wedges all 32 nodes 360s → rc=-110 cascade. Consistent nodes: B6 test32(slot51115), B7 test28(slot46987), B8 test27(slot36627) — hex=holder bit, gen advancing (not frozen).
3. Peers BAST the holder; holder is in state=DEMOTING and swallows them (P72-SWALLOW-DEAD), OR state=NONE/NL.

## Why NOTHING releases the orphan bit (THE deep root)
`mxfs_dlm_bast_process` (xfs_mxfs_dlm.c:10663) release condition (~11827): `if (ex_holders>0 || pr_holders>0 || pin>0 || gen_moved || orphan_live)`. For a CAW incore-NL orphan ALL are false:
- ex/pr_holders, pin = 0 (incore forgot the tenure).
- gen_moved: p_rel_gen==0 on CAW → false.
- **orphan_live = (p_held_mode==NL && p_rel_gen!=0 && !self_demote)** → p_rel_gen is ALWAYS 0 on CAW (comment 11766 "CAW unaffected grant_gen is 0") → orphan_live=FALSE on CAW.
So bast_process SKIPS the release block entirely → the on-disk EX bit is never cleared. The orphan_live + 280-sample strike-escalation (P15H-STRANDED-RELEASE, ~7s, avoids releasing a live mid-completion grant → double-EX) is **TCP-only**. CAW has NO equivalent orphan detection.

## Fixes tried (this session, all evidence-backed)
- B2-B5 fairness tuning (streak/yield/upgrader): WRONG TREE. r2/r3 death.
- B7 v0.10.44 acquire-side self-EDEADLK (caw_wait_for_grant: node_held!=NL && !is_compatible → -EDEADLK): pushed wedge r2/r3 → **r4**. But the probe P-SELF-STALE-EDEADLK stayed 0 (main-loop P109-EDEADLK handled acquire-side; the stuck HOLDER never acquires so acquire-side fix can't reach it).
- B8 v0.10.45 holder-side stale-DEMOTING re-queue (P72 branch: work_busy==0 → re-queue bast_work): FIRES heavily (P72-STALE-REQUEUE 100s-1000s/node) but does NOT clear — because the re-queued bast_process no-ops on the CAW orphan (above). Died r4 again (test27).

## THE FIX NEEDED (design question → Fable consult in progress)
Add CAW orphan detection to bast_process mirroring the TCP orphan_live strike-escalation, but keyed on the LIVE DISK SLOT (mxfs_dlm_caw_held / node_held_mode) instead of p_rel_gen: if incore mode==NL but we hold the on-disk bit, and it stays stranded across ~N samples (no ACQUIRING slow-path consuming it), RELEASE it (drain+caw_unlock+clear bit). MUST NOT release a grant a concurrent same-node acquirer just CAS'd but hasn't adopted incore yet (the CAW analog of the r10 double-EX; caw_wait_for_grant promotes then caller adopts incore — narrow window). Alternative: clear the bit at inode-reclaim/free time on the holder (AAB-dlm_scaling32 dealloc-clear extended to the holder bit, not just epoch).

## Build state
v0.10.45 srcver 4E1FA7B6 (both acquire + holder-re-queue fixes + P-ACQ-STUCK/P-SELF-STALE-EDEADLK/P72-STALE-REQUEUE probes) + B2-B5 fairness changes. Cluster killed, lock free. dir_reuse@32 is the ONLY criteria gap.
