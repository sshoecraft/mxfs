---
name: sess44-NEXT-fix-dir-epoch-on-local-promotion-grant-dlm-704
description: sess44 SHARPEST next-action: the master COMPUTES dir_epoch correctly (P64-MASTER-HANDOFF 128x for ino=131, epoch advances to 515) but the GRANTEE nod…
metadata:
  type: project
---

## sess44 — SHARPEST root: dir_epoch is COMPUTED but NOT PROPAGATED to grantee locks

### Decisive evidence (last 8-node FAIL run streams):
- **P64-MASTER-HANDOFF fires 128× for ino=131, epoch advances to 515** → the MASTER's dg_grant_ex (dlm.c:2666) IS correctly detecting cross-node handoffs and bumping the per-resource epoch. Computation works.
- **P68-EVDECIDE shows cur_mep=0 dominant** at the MODIFYING nodes → `mxfs_v5_dlm_inode_dir_epoch` (→ mxfs_dlm_grant_dir_epoch → the LOCAL node's granted `lk->dir_epoch`) returns 0. So the epoch the master computed (515) is NOT stored on the grantee node's local lock entry.
- P-STALEMASTER-GRANT=0 (no mastership flap), but **P-DOUBLEGRANT fired 1×** for ino=131 (a genuine concurrent-EX instant — rare, ~1 vs 38394 clean modifies, but real; could be the actual loss moment).

### THE PROPAGATION GAP (two sites to fix/verify):
1. **Grantee-side storage on grant RECEIPT**: when a remote node receives a LOCK_GRANT carrying `resp.dir_epoch` (send_grant stamps it, dlm.c:849/2873/2918), the grantee must store it into its local `lk->dir_epoch`. Check process_grant / the LOCK_GRANT handler (dlm.c ~3150-3210, where lk->grant_gen = grant_gen at 3187/3204) — verify `lk->dir_epoch = resp.dir_epoch` is ALSO done there. If missing, that's the gap → grantee's lk->dir_epoch stays 0 → cur_mep=0.
2. **Master self-grant**: when the master grants EX to ITSELF via local promote_waiters (dlm.c:704-709, stamps grant_gen at 707 but NOT dir_epoch — dg_grant_ex is only called on the REMOTE paths 2867/2912/3050), the master's own lk->dir_epoch stays stale/0. Call dg_grant_ex(ctx,&res,local_node,gen,&de) + lk->dir_epoch=de there so the master detects a handoff FROM a peer on its self-reacquire.

### After fixing propagation: verify cur_mep becomes non-zero (515-ish) at modify via P68-EVDECIDE, then the EXISTING newtenure/prior-tenure evict (default-on mxfs_dir_newtenure_evict) should finally fire (P26-NEWTENURE-EVICT/P16-PRIORTENURE-EVICT) and cold-read the stale base. Validate ./run.sh {1,2,4,8} tcp. CAVEAT (sess35 trap): epoch going 0→nonzero mid-tenure can make new_tenure over-fire and retire this tenure's own un-landed creates → readdir=0; the epoch must be set at GRANT time (tenure start, before any modify), not mid-tenure. CAVEAT 2: the 1× P-DOUBLEGRANT suggests a residual rare concurrent-EX that no coherency fix addresses — investigate separately (the dir's shadow-slot eviction at DG_SHADOW_N=512 under 800-inode/round load could reset/race it).

### RESIDUAL WALL still applies: even with epochs propagated, sess43+sess44 showed the stale base is often the node's OWN dirty/in-AIL buffer (un-evictable) and the loss may be insert-time during leaf/node conversion. So epoch-propagation is necessary but may need the conversion/leaf-coherency fix too.

### STATE: keeper 3062493A (== baseline for 1/2/4; 2/tcp dir_reuse PASS; all sess44 levers default-off; P44 probe gated). Criterion NOT met. [[sess44-ROOT-epoch-and-grantgen-both-zero-for-reused-dir-inode-coherency-signal-dead]] [[sess44-FINAL-bug-is-acquire-side-stale-read-dlm-serializes-correctly]] [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]]
