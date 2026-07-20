---
name: sess8-shortform-reload-fix-partial-plus-separate-content-bug
description: sess8: shortform reload-adoption fix (1AB8C27A) gives dlm_fairness 30/30 standalone + 1 clean full 16/16, but full suite still flakes — residual resu…
metadata:
  type: project
---

## FIX 1AB8C27A1A...B44 (gate shortform reload-adoption) — PARTIAL, KEEP-with-caveat.
Changed mxfs_dir_disk_superset (xfs_mxfs_dlm.c ~4901) to drop the UNCONDITIONAL
`if_format==LOCAL` clause → shortform dirs now use `(post_release || peer_modified_since_load)`,
same as block/leaf. Rationale: the unconditional clause rolled back a node's OWN
committed-not-checkpointed DELETE on a SAME-TENURE reload (adopting a stale disk image that still
held the entry) = the durable dirent RESURRECTION.

### Validation:
- dlm_fairness standalone: **30/30 PASS** (was ~1/6–1/16 fail) — strong for the resurrection class.
- Full 2/tcp suite ×3 (reboot each): run1 **16/16** (FIRST clean full pass of the run!), run2 15/16
  (cache_coherency 0/2), run3 14/16 (crash_consistency 1/2 + tcp_dlm_scaling 1/2). NO shutdowns.
- CRITERION NOT met (needs reliable 16/16).

## KEY REFRAME: the "rotating single failure" is MULTIPLE DISTINCT coherency bugs, not one:
1. **Shortform dir-entry resurrection** (dlm_fairness, crash_consistency, tcp_dlm_scaling): my fix
   helps but is INCOMPLETE — run3 still failed crash_consistency + tcp_dlm_scaling. The residual is
   the POST_RELEASE / peer_modified path: there, mxfs_dir_disk_superset is STILL true, so adopting
   disk can resurrect an in-flight delete OR lose an in-flight add. The real fix is a true SHORTFORM
   MERGE on reload: adopt the UNION = peer's durable entries, but HONOR this node's
   committed-not-checkpointed deltas (don't resurrect our deletes, don't drop our adds). The
   codebase has never done this merge (it only ever picks adopt-disk OR keep-in-core wholesale).
2. **cache_coherency file-content-empty** (SEPARATE bug, NOT shortform-dir): `cv nodeN sees
   node1.txt` / `content of node1 exp="hello from node 1" got=` (EMPTY) on BOTH nodes. This is
   REGULAR-FILE DATA coherency (di_size=0 / data-not-visible family, cf. sess25/sess45), unrelated
   to my dir-reload change. node1.txt's content is invisible/empty cross-node. Needs its own fix.

## NEXT SESSION (to reach reliable 16/16):
A. Complete the shortform reload as a MERGE (xfs_mxfs_dlm.c reload path ~4847-5550): when
   adopting the disk shortform dinode, reconcile against this node's in-core shortform using the
   inode log intent — preserve our committed deletes (don't re-add a name we removed) and our
   committed adds (don't drop a name we added) while taking all of the peer's entries. Validate
   30+ dlm_fairness AND crash_consistency AND tcp_dlm_scaling iters, full suite ×3, and guard
   cross_write_read/unlink_visibility/zero_silent_loss against regression.
B. Fix cache_coherency file-content-empty: instrument node2's read of node1.txt — is the dirent
   resolved but di_size=0 (inode reload stale) or content bytes not FUA-fresh? Likely the
   reg-file inode-content reload coherency (see sess25 i_size sync, sess45 atime-EX-clobber).

## STATE: build 1AB8C27A deployed both nodes. Theoretically-sound partial fix; KEEP (helps
resurrection, neutral on the content bug) but NOT sufficient alone. Rename guard still KEEP.
Detectors (P-DOUBLEGRANT/P-STALEMASTER-GRANT=0 → double-grant family REFUTED) still in. Marker NOT
written. Fallbacks: 174E2CD5 (detectors, pre-merge-fix), E143DF7B (rename guard only), E8BF16B2.
See [[sess8-lead-sess49-shortform-adopt-disk-vs-delete-resurrection]],
[[sess8-DECISIVE-not-doublegrant-not-splitbrain-serialized-coherence-gap]].
</body>
