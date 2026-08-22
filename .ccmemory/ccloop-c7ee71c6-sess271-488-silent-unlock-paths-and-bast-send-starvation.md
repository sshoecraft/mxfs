---
name: ccloop-c7ee71c6-sess271-488-silent-unlock-paths-and-bast-send-starvation
description: sess271: -488 5th face — logged unlock-failure paths ELIMINATED on test28; 3 silent strand paths in caw_unlock_gen_body + waiter never re-BASTs (last…
metadata:
  type: project
---

# sess271 — -488 fifth face: elimination pass + BAST-send starvation

## Eliminated (test28 journalctl -b -1, full-boot greps, zero hits)
- "dlm_caw: unlock exhausted" (retry-cap path, dlm_caw.c ~9024)
- P-UNLOCK-REGRANT-ABORT (regrant path ~9033; cap 50/boot NOT consumed — zero for any resource)
- P251-LREQ-DRY, P55-STUCKMETA, P67-AG-BAST-STALL

## Remaining silent strand paths in caw_unlock_gen_body (dlm/dlm_caw.c 8423-9061)
All swallowed: bast_work_fn → mxfs_v5_dlm_ag_unlock (void, v5_mount.c:6130) → mxfs_dlm_caw_unlock.
1. find_slot -ENOENT → rc=0 silent (8573). Platter slot for ag=3 EXISTS (50128 gen=128), so this firing would itself be a find_slot defect.
2. find_slot other rc → silent goto out (8577)
3. caw_slot CAS non-EAGAIN rc (transport -EIO) → silent goto out (8953), no print, tenure already dropped at COMMIT.
Plus: AG resources get NO wall-clock unlock deadline — 8499-8502 covers only INODE/ICLUSTER; AG = 100-retry cap (MXFS_CAW_MAX_RETRIES dlm_caw.h:52). Same shape sess6 fixed for ICLUSTER; AG omitted.

## Key misread corrected
"P12-WORK COMMIT demoting with nothing after" is what SUCCESS looks like — there is no completion print (P10-INSTR only if instr enabled). Do not infer a wedged worker from it. test2 ag=6 COMMIT 17:24:57 + silence = fine; /proc/*/stack sweep on test2 shows NO bast worker running.

## BAST-send starvation (new, load-bearing)
test2 rsync 13975 retries ag=3 every 120s (rc=-110, P1-AGWAIT) but the fleet's LAST ag=3 BAST multicast was 17:16:46 — zero re-BASTs in 20+ min of retrying (2405 lifetime RX on test2, all ≤17:16:46). Waiter bit already set on platter → re-poll skips send. Consequence: the readopt strand-repair (xfs_mxfs_dlm.c 41629-41666) is bast-rx-driven and can NEVER fire, so any strand becomes permanent even on a live holder. Send sites to read next: caw_send_bast_mcast at dlm_caw.c 5887, 8062, 8176, 10117.

## readopt storm context
Before the strand: test28 readopt=356..452 AND test2 readopt=464 on ag=3 (17:15:4x) — strand-repair loop cycling on multiple nodes ~100x/s, each cycle acquire→demote→unlock. The final unlock left bit28. Also test28 16:47-16:48: disklock_hb_fn blocked on mutex 60s+ (defect #22 shape), self-resolved.

## Fix shape queued for RULE 5
(i) AG unlock: add wall-clock deadline; on ANY failure re-arm in-core tenure (or defer tenure drop until confirmed clear) + loud probe on every silent path; (ii) waiter re-BASTs on every 120s retry (min); (iii) tame readopt churn. Then full re-prep + 3× rsync_paired + 3× scaling_curve + board.
