---
name: sess13-doublegrant-REFUTED-serialized-stale
description: sess13 DECISIVE (RULE-4): TCP dir-EX DOUBLE-GRANT REFUTED (P-DOUBLEGRANT=0, P-STALEMASTER=0 at failure). MODE-B = serialized-but-stale reload. Shortf…
metadata:
  type: project
---

## DECISIVE REFUTATION (build B65625E2, RULE-4): the 2/tcp shared-dir resurrection is NOT a TCP DLM double-grant.

## Method: tcp_dlm_scaling with `MXFS_EXTRA_MODARGS='lockwr=1'` (tests/tcp_lkt_doublegrant.sh), clean reboot, foreground. Got a leftover failure, then checked the ALWAYS-ON master-side detectors emitted by dg_grant_ex (dlm/dlm.c:2142): P-DOUBLEGRANT (different owner already EX in dg_shadow at an EX grant) + P-STALEMASTER-GRANT (mastership flap).
## RESULT both nodes at failure: **P-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0** (not instr-gated, so a real double-grant would show). P-CONVBLK-DENY=1, REAFFIRM=1 (normal). ⇒ TCP DLM serializes dir-inode EX correctly; only one node holds dir-EX at a time. REFUTES the sess12 "find the 2nd double-grant path" lead — there is none.

## So MODE-B = SERIALIZED-but-STALE modify: a node legitimately holds dir-EX and RMWs the shortform dir from a base missing the peer's (or its own earlier) durable change.

## RELEASE DURABILITY IS NOT THE GAP (checked this session):
- bast_process release barrier (xfs_mxfs_dlm.c ~3638-3748) loops until `!in_ail && !pinned && data_durable` before mxfs_v5_dlm_inode_unlock.
- `mxfs_dir_data_durable` (987) returns TRUE VACUOUSLY for FMT_LOCAL (shortform has no data blocks) — BUT the `in_ail` wait on ip->i_itemp (the inode log item) DOES cover the shortform DINODE: the item leaves the AIL only when the inode cluster buffer is iflushed AND written (AIL removal on buffer IO completion). So the shortform dinode IS durable on the shared target before unlock. Release durability is sound. DO NOT re-investigate release-barrier durability.

## REMAINING CANDIDATES (next session, RULE-4 — pick one, instrument):
1. **Read-side / SCST cache-vs-platter coherency**: at the acquirer's reload, P34D-RELOAD-FRESHSRC logged fresh==cached==our-base (size32) i.e. the coherent plain read did NOT show the peer's durable change even though release made it durable. fua_disable=1 so reads = plain bio (SCST cache); peer destage = xfs_buf write (SCST cache) — should be coherent, but verify the inode-cluster-buffer write path lands at the SAME coherence point the acquirer's plain read uses. (older lead: [[sess85]] "SCST write-cache vs FUA-reread".)
2. **Within-node release-timing self-revert**: the leftover is the node's OWN file (n1_rN). Sequence create→rename→rm under intermittent BASTs: if a BAST forces release after create-commit (n1_rN durable) but the later rename's REMOVE of n1_rN is reverted on a subsequent reload that adopts an on-disk image still carrying n1_rN. Trace per-node: P-DIR-SEQ REL realns + the on-disk SF contents (P-SFREL, instr-gated; make a lockwr-gated always-on variant) vs the reload (P34D) — prove whether the node's own removal was durable-on-device at its next reload.

## TOOLING: P-LKT ring (mxfs.lockwr=1, lktdump param) works but is FLOODED by child-inode GRANT-LOCAL noise (n1_rN, owner=local) → evicts dir events. To trace the dir: filter recording to non-GRANT-LOCAL or a target ino (small change in mxfs_lkt_record dlm/dlm.c:117) or enlarge MXFS_LKT_RING_SZ. Repro: tests/tcp_lkt_doublegrant.sh (foreground, lockwr=1). Always clean-reboot first.
[[sess13-modeB-writeside-laggy-heartbeat-not-stale-read]] [[sess13-HEAD-status]] [[sess85_lessons]] [[feedback-never-background-wait-poll]]
