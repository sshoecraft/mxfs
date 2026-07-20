---
name: sess8-symmetric-clobber-confirms-doublegrant-detector-design
description: sess8: SYMMETRIC mutual-clobber leftover (both nodes' own rename-targets leak) = strong double-grant evidence. Detector design + lock-ordering caveat…
metadata:
  type: project
---

## Strongest evidence yet that the 2/tcp residual IS a true DOUBLE-GRANT (concurrent EX).
dlm_fairness fail (dirwr): leftover = `n1_r1.done` AND `n2_r7.done` — the rename TARGETs — present
and AGREED on BOTH nodes. Each node's OWN `rm <x>.done` was durably reverted by the peer. The
SYMMETRY (each node clobbers the other's latest change) is the signature of CONCURRENT EX holds, not
a serialized handoff (serialized handoff loses one side's change, not both mutually). dlm_fairness is
single-threaded per node, so the stale-cached-PR-reader vector does NOT apply — reinforcing that the
mechanism is two nodes holding dir-131 EX at the same time.

## Why printk can't catch it (re-confirmed): P106-EXGRANT/EXREL are plain pr_warn; under dirwr=1 the
dmesg ring ROLLS (heavy logging) and drops the intermediate GRANT/REL pairs, so the cross-node EX
window overlap cannot be reconstructed. A lock-free / low-volume in-kernel detector is required.

## SAFE DETECTOR DESIGN (next session — instrumentation only, no behavior change):
Global shadow of current EX holders, separate from the lock table (the table entry is what gets
removed, so it can't show the ghost). Choke points already located in dlm/dlm.c:
- EX GRANT (set shadow owner): `send_grant()` (dlm.c ~677) when msg_type==MXFS_MSG_LOCK_GRANT &&
  mode==MXFS_LOCK_EX (covers immediate/reaffirm/conversion/promote remote grants); AND
  `pending_signal_resource()` (dlm.c ~343) when mode==EX && success (LOCAL master-to-self grants).
  BOTH needed: a 2-node double-grant = master grants self (pending_signal) + peer (send_grant).
- GENUINE RELEASE (clear shadow): `process_remote_release()` (dlm.c ~2463, after confirmed removal)
  + `mxfs_dlm_unlock()` (dlm.c ~1331) + purge_node for the purged owner. Do NOT clear on the
  administrative removals (convblk ~2229, stale-WAITING ~2116, conversion-blocked) — leaving the
  shadow active there is exactly what exposes the ghost.
- CHECK (at EX grant): if shadow already has an ACTIVE EX for the same resource owned by a DIFFERENT
  node → pr_warn_ratelimited("P-DOUBLEGRANT ino=%llu owner_a=%u owner_b=%u") — decisive.
- Limit to MXFS_LTYPE_INODE to keep it small. Track gen too if useful.

## CRITICAL LOCK-ORDERING CAVEAT: the DLM uses mxfs_pal_* primitives (dual user/kernel build,
invariant #4) — use mxfs_pal_mutex for the shadow (grant paths are sleepable: send_cb can sleep).
send_grant is sometimes called AFTER `mxfs_pal_rwlock_unlock(table_rwlock)` (e.g. dlm.c ~2194) and
sometimes... AUDIT every call site: take the shadow lock in a CONSISTENT order vs table_rwlock
(simplest: only ever take shadow_lock when table_rwlock is NOT held, or always strictly inside it) —
a wrong order DEADLOCKS the DLM = worse than the stable 15/16. Validate the detector alone (no false
positives on PASS runs) before trusting a P-DOUBLEGRANT hit.

## THEN FIX (after confirmation): prevent concurrent EX. The convblk-removal (dlm.c ~2229) and/or
purge/release paths let a holder's entry vanish without a genuine release. Fix = never grant EX while
the shadow shows another node's active EX; make administrative removals either keep the holder
visible or force the removed node to drop+reload its cache (BAST-driven downgrade, handling the
PR→EX conversion deadlock). HIGH regression risk — validate with 30+ dlm_fairness iters
(reboot+reset between) since base rate ~1/16, plus a full-suite ×3.

## STABLE STATE PRESERVED: build AFD6B76A (rename guard KEEP + P-SFREL + P-CONVBLK-REMOVE markers),
deployed both nodes, reliably 15/16, no shutdown. Did NOT attempt the risky DLM surgery this session
to avoid regressing the verified win. Marker NOT written. Fallbacks: E143DF7B, E8BF16B2, 404BC55C.
</body>
