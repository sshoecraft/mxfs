---
name: sess44-ROOT-epoch-and-grantgen-both-zero-for-reused-dir-inode-coherency-signal-dead
description: sess44 ROOT-LOCALIZATION: for the rm-rf-reused storm dir (ino=131), BOTH cross-node coherency signals are 0 — mxfs_v5_dlm_inode_dir_epoch (cur_mep) A…
metadata:
  type: project
---

## sess44 (ccloop) ROOT-LOCALIZATION: the acquire-side coherency SIGNAL is dead for the reused dir inode

### Decisive evidence (P68-EVDECIDE always-on probe in mxfs_dir_evict_data_blocks, last 8-node FAIL run):
- The acquire-side evict DOES run and examines cached blocks (12000-24000 P68-EVDECIDE per rank — NOT 0 as an older comment claimed).
- BUT the dominant decision (~96000 events) has **cur_mep=0 valid_epoch=0 b_epoch=0**. `cur_mep = mxfs_v5_dlm_inode_dir_epoch(dlm, ino=131)` returns 0. The newtenure/prior-tenure epoch eviction ALL require `cur_mep != 0` → INERT.
- `mxfs_dir_grant_evict=1` test: **P36-GRANTEVICT fired 0×** → grant_stale_base never true because `i_dlm_cached_grant_gen` is ALSO 0 (grant_stale_base requires cached_grant_gen!=0 && b_grant_gen!=0).
- So BOTH cross-node coherency signals — the DLM dir_epoch (`lk->dir_epoch` via mxfs_dlm_grant_dir_epoch, dlm.c:2448) AND the inode grant-gen (`i_dlm_cached_grant_gen`, set at xfs_mxfs_dlm.c:14304/15006 on slow-path acquire) — are **0 for ino=131**. With both 0, the evict falls back to dirty/pin/delwri/!DONE/undestaged flags, which CANNOT distinguish a stale prior-tenure base from current-tenure work → the stale base is kept (undurable=1) or a fresh cold-read isn't forced.

### WHY both are 0 (hypothesis for next session): ino=131 is the storm dir, rm-rf'd + recreated EVERY round (freed+realloc'd inode-number reuse). On inode free/realloc the DLM lock resource's dir_epoch resets and the inode's cached_grant_gen resets to 0 — and/or the rapid ~2-6ms MHT-batch EX handoffs during the create wave are FAST-PATH (cached EX re-grant without a master round-trip) so they never assign a new dir_epoch/grant_gen. P44-MODGRANT confirmed held=1 (real grant) on every modify but the grant carries epoch/grant_gen=0.

### THIS EXPLAINS 40 SESSIONS OF FAILURE: every acquire-side fix (newtenure_evict, prior_tenure_evict, grant_evict, tenure_evict, dir_coherent_modify) is gated on a NON-ZERO epoch or grant_gen. For the reused storm dir both are 0, so ALL of them are structurally INERT — they look correct in code review but never fire on the actual failing inode. And every release-side fix is moot because the acquire side never refreshes (sess44 whole-AIL push proved release durability is already sufficient).

### COMBINED with sess44's other proofs (NOT stale-base via grant_evict+push still fails, NOT stale-write via whole-AIL push): the surviving mechanism is most likely sess41's INSERT-TIME loss during dir GROWTH (block->leaf->node conversion / leaf-node split drops a peer's prior-tenure entry because the converting node's LEAF/freeindex structure is stale) — and the leaf/freeindex coherency is ALSO unprotected because the same dead epoch/grant_gen signal gates any leaf refresh.

### NEXT (RULE 4) — fix the SIGNAL, not the consumers:
1. **Make the DLM assign a non-zero, monotonically-advancing dir_epoch (and inode grant_gen) on EVERY cross-node EX handoff of a reused inode**, including fast-path/MHT re-grants and post-realloc first grants. Instrument `mxfs_dlm_grant_dir_epoch` / the grant path (dlm.c ~2448, 2868, 3065, 3193): log when ino=131 gets a grant and whether dir_epoch is assigned non-zero. Find where the reuse/fast-path drops it to 0.
2. OR adopt a coherency signal that survives inode reuse and fast-path: a per-(physical-daddr) or per-(inode-number+generation) handoff counter the master stamps on EVERY grant transfer.
3. THEN the existing newtenure/prior-tenure evict will finally fire and cold-read the stale base (and extend it to LEAF/freeindex blocks for the conversion/split case).
Build 3062493A = keeper (P44 probe gated behind instr; all sess44 levers default-off). Tools: P68-EVDECIDE (always-on, the evict decision), P44-MODGRANT (instr), P36-GRANTEVICT, P13-NADD offset trace. [[sess44-FINAL-bug-is-acquire-side-stale-read-dlm-serializes-correctly]] [[sess44-DECISIVE-release-completeness-not-the-gap-bug-is-acquire-or-concurrency]] [[sess41-DEFINITIVE-loss-is-insert-time-not-writeback-ring-proven]]
