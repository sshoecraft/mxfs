---
name: sess37-DECISIVE-clobber-on-nonmaster-stale-local-dlm-EX
description: sess37 CORRECTED: master_self=0 dominance is a POPULATION confound (7/8 nodes non-master). The 11 master_self=1 clobbers PROVE genuine-EX intra-node…
metadata:
  type: project
---

## sess37 — root of dir_reuse readdir=799 clobber (build C949F3C3, dataclobber=1 dirwr=1). CORRECTED for a population confound.

### MEASUREMENT (new master_self field in P-DATACLOBBER-SKIP): genuine-EX (real_mode=5) clobbers: master_self=0 → 166; master_self=1 → 11. All: bufgen=0 stale=1 in_ail=1 bdirty=0 in_txn=0 comm=dd/bash; kinds data+leaf (leaf daddr=6279744 buf_cnt=117 vs disk_cnt=379).

### ⚠️ CONFOUND: the dir inode (131) is mastered by ONE node, so 7/8 nodes are non-master by population. 166/177 = 94% master_self=0 ≈ the 87.5% non-master population → master_self=0 dominance does NOT prove stale-local-DLM. The earlier "stale local DLM" claim is NOT supported by this alone.

### ✅ WHAT IS PROVEN (the 11 master_self=1 clobbers): on the MASTER node the local dlm table IS authoritative (mxfs_dlm_audit_double_grant scans it and fires 0× = no double-grant). Yet a genuine-EX clobber STILL occurs on the master. Therefore the clobber is NOT a DLM grant error (no double-grant, no stale-grant on the authoritative node) — it is an **INTRA-NODE STALE-CACHED-BUFFER REFLUSH**: a node holding genuine EX has a dir buffer with bgen=0 (stale content from a PRIOR tenure when disk was smaller) that xfsaild reflushes BEFORE the buffer is re-read, overwriting the larger durable disk image (grown by a peer while this node had released EX in the interim).

### THE MECHANISM (consistent with ALL evidence incl. sess32 TOCTOU, sess26):
1. Node holds EX tenure T1, dir leaf has 117 entries; releases (drain → 117 durable on disk; but xfs_bwrite does NOT retire the buffer's BLI → a ZOMBIE BLI lingers in the AIL).
2. Peers grow the leaf to 379 on disk over tenures T2..Tn.
3. Node re-acquires EX (tenure Tk). grant_evict clears XBF_DONE + sets bgen=0 (marks for re-read) BUT the stale b_addr (117 entries) AND the zombie BLI remain.
4. Before any READ re-populates b_addr from disk (379), xfsaild PUSHES the zombie BLI → writes the stale 117-entry b_addr over disk's 379 → durably drops 262 entries (or 1 for data blocks). Clearing XBF_DONE does NOT stop a writeback of stale b_addr.

### THE FIX (sess26 NET conclusion, acquire/release-side BLI RETIREMENT — NOT write-time drop, which is categorically refuted):
At EX RELEASE, after the drain xfs_bwrite makes the dir buffers durable, **RETIRE their BLIs from the AIL** (xfs_buf_stale or equivalent) so no zombie BLI survives the handoff for xfsaild to reflush in a later tenure. The content is durable (just drained) so retiring the BLI loses nothing. Existing levers to check/fix:
- `mxfs_dir_release_invalidate` (P-RELINVAL, xfs_mxfs_dlm.c:4374): clears XBF_DONE at release BUT its SAFETY gate SKIPS in-AIL buffers (`!dirty && !in_ail && !pinned`) → it does NOT touch the zombie BLI (the in-AIL one) → the bug survives. NEEDS to handle the in-AIL destaged zombie: after drain it IS durable, so stale+retire it.
- `mxfs_dir_release_stale` (default 0, "fired 0×"): check why its gate never matched — likely the same in-AIL skip.
- Alternatively at ACQUIRE-EVICT (grant_evict): when invalidating a prior-tenure dir buffer (clear XBF_DONE/bgen=0), if it has a lingering already-destaged AIL BLI, xfs_buf_stale it so xfsaild can't reflush stale b_addr before the re-read. Must gate on DESTAGED (logged_seq==written_seq, !pinned) so no un-landed work is dropped — this is acquire-side controlled retirement, NOT the racy bio-chokepoint drop (refuted).

### NEXT: implement release-side (or acquire-evict-side) zombie-BLI retirement for already-destaged dir buffers. Test ON TOP of the best read-side stack (dir_grant_evict=1 dir_addname_coherent=1 dir_addname_epoch_refresh=1 dir_addname_platter_guard=2). Build keeper-equiv at default. Diagnostic: mxfs_v5_dlm_inode_master_self (dlm/v5_mount.c), master_self field in P-DATACLOBBER-SKIP. See [[sess37-residual-is-equal-count-content-divergence-xfsaild-leaf]] [[sess26-PIVOTAL-readside-loses-writeside-corrupts-fix-is-release-fence]] [[sess37-HEAD-handoff]].
