---
name: sess3-END-run18-evict-cil-window-hypothesis
description: sess3(a16ec5f2) END: run18 (dirwr=1): only fail=r8 4 lost tail-entries; P29 shows NO submit-time count-drop → HYPOTHESIS: dir-block evict during comm…
metadata:
  type: project
---

# sess3 END checkpoint — run18 analysis + next session's precise target

## run18 (build 780517DA, dirwr=1, fresh boots; run.sh killed by tool cap but nodes continued to r=17)
- ONE fail round: r=8 readdir=796/800; lost = node2_f47.md5 node2_f48.md5 node2_f49.md5 node8_f50.md5 (tail-of-round creates, the classic "last entries" pattern).
- P29-DATAWRITE fired ~810/node: **ZERO writes had buf_cnt < disk_cnt** → no node ever SUBMITTED a data block with fewer dirents than coherent disk. (NB: P29's tag=CLOBBER is broken — `bsum!=dsum` triggers on every legitimate ADD; ignore the tag, use the counts.)
- Zero shutdowns again (SFTORN fix solid across runs 16,17,18).

## HYPOTHESIS for the residual dirent-loss (r=8-class, also r=1 whole-creator-loss in run17, r=6/7 singles in run14/15)
Since no stale-count submit exists, the adds were never in any submitted image → they were discarded IN-CORE after commit: **a dir data buffer evicted (XBF_DONE cleared / cache dropped) in the window between trans-commit (changes only in CIL; buffer looks clean — no XFS_LI_IN_AIL yet, b_addr holds the only current content) and AIL-push writeback.** After evict, cold re-read restores the STALE disk image into b_addr; the later AIL push writes THAT → committed adds durably lost. Same "discard committed-unwritten state" class as the fixed SFTORN root but for dir DATA buffers.
- Suspect paths (all in xfs_mxfs_dlm.c): mxfs_dir_evict_owned_dir_blocks (P68-PREEVICT full evict on gen_change/shrink/handoff at reload!), mxfs_dir_stale_clean_data_blocks_relsafe (release-path GFS2-style demote-invalidate), tenure-evict (P23/epoch), drain_evict paths. Their guards likely check XBF_DELWRI_Q/XFS_LI_IN_AIL/pin — the CIL phase (committed, pre-checkpoint) may pass those checks (li attached but !IN_AIL, bli_flags DIRTY?) — check whether they skip buffers with b_log_item present + test_bit(XFS_LI_DIRTY) or li_in_cil.
- NEXT PROBE: in each evict path, when about to evict a dir buffer with bp->b_log_item, log (daddr, bli_flags, li_flags IN_AIL/DIRTY/IN_CIL?, pin, comm, stack once) — run with watch+dirwr → correlate an evict of the victim block (holding f47-f50 adds) right before the loss. Note victims are TAIL adds: at round end the last adds sit in CIL (no checkpoint yet) exactly when the creator RELEASES dir-EX (BAST) → release-path evict/stale_clean is the top suspect (it runs after data_durable — but data_durable checks the BUFFER not the CIL: a just-committed add's buffer may show clean+!in_ail while its BLI sits in CIL → passes fence → stale_clean evicts → loss ✓ fits "last entries" precisely!).
- The release fence's data_durable = per-buffer !dirty && !in_ail; a CIL-resident change makes the buffer LOOK clean. THE FENCE MUST xfs_log_force (checkpoint) FIRST then re-check — it does log_force only in the RETRY loop (when first check fails); if first check passes spuriously (CIL window) it NEVER forces ✓✓ THE GAP: fence's fast-path exit misses CIL-only dirt. FIX candidate: unconditional xfs_log_force(SYNC) before the first data_durable sample in the dir release fence (or include ili/bli CIL state in data_durable).

## Also learned run17/18
- run17: r=1 lost 200 files (test2's whole set + another's) same class, cold-start; r=9 one dangling dirent (node7_f23 in readdir, stat ENOENT). 17/19 rounds clean.
- P-LKTIMEOUT-HOLDER/-REMOTE dumps live (dlm.c) — fire per 1s pending_wait expiry; run16's test6 -110 ABBA still to fix (dir-EX holder waits AG; AG holder stuck on dir-EX; yield only runs 3×/acquire because mxfs_v5_dlm_inode_lock blocks 60s internally — consider small retry budget wiring like sess58 intended, or master-side aging).
- Pace: ~25s/round with probes; needs ≤20 (RULE 0) — strip probes after the correctness endgame.

## State
- Build 780517DA everywhere (SFTORN -EAGAIN fix + holder dumps + PW probes). VMs get fresh-boot via virsh destroy/start (55s wait) — do this before every diagnostic run for clean dmesg.
- Criteria marker NOT written. Sequence to criteria: fix CIL-window evict → 8/tcp ≥5 consecutive clean → 4/2/1 → full ./run.sh N tcp suites.

Links: [[sess3-ROOT-FIX-sftorn-skip-consumed-ili-fields]] [[sess3-MID2-run17-no-shutdowns-starvation-next]]
