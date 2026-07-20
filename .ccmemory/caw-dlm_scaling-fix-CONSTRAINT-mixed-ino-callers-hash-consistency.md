---
name: caw-dlm_scaling-fix-CONSTRAINT-mixed-ino-callers-hash-consistency
description: CRITICAL implementation constraint for the dlm_scaling gen-fix: mxfs_v5_dlm_inode_lock has MIXED ino/ip callers (318/19918/20154 pass raw ino, no ip)…
metadata:
  type: project
---

## dlm_scaling gen-fix — CRITICAL implementation constraint (ccloop 0d6e174d sess2, code-verified)

Read WITH [[caw-FIX-DESIGN-dlm_scaling32-put-inode-gen-in-resource-id-offset]]. This is the gotcha that
makes the fix NON-trivial (why I did NOT stage it blind — it can silently break locking, untestable now).

### The constraint (code-verified in xfs/xfs_mxfs_dlm.c, real file not .backup):
`mxfs_v5_dlm_inode_lock(dlm, ino, mode)` callers have MIXED context:
- HAVE ip (can pass ip->i_generation): line 18660 (ip->i_ino, mode), 20252 (ip->i_ino, EX).
- HAVE ONLY ino (no ip): line 318 (ino, PR), 19918 (ino, EX), 20154 (ino, EX). (grep found ~17 total —
  enumerate all before implementing.)

### Why this is a TRAP for "gen in resource_id.offset":
That approach makes generation part of fnv1a_hash(resource) → the slot INDEX depends on the generation.
If ANY caller for a given inode supplies gen=G but another supplies gen=0 (ino-only site can't get it),
the two paths compute DIFFERENT slot indices for the SAME inode → this node coordinates that inode's lock
in TWO different slots → it can believe it holds the lock (slot A) while a peer negotiates via slot B →
lock INCOHERENCE / lost mutual exclusion / corruption. This would NOT show at 1-2 nodes; it'd surface as
rare corruption at scale — and I CANNOT test it (host wedged). Hence NOT staged.

### IMPLEMENTATION REQUIREMENTS (next session, with host):
1. EVERY inode-lock path (all 17 callers) must supply the SAME generation for a given inode. For ino-only
   sites, resolve i_generation via a NON-BLOCKING in-core inode lookup (xfs_iget with cache-hit-only / the
   mount's inode radix tree) — verify no locking recursion (you're IN the lock path). If a site genuinely
   can't get the gen (inode not in-core), that path must be handled (it can't just pass 0).
2. OR use the ALTERNATIVE that does NOT change the hash: store i_generation in the slot's spare pad2
   (dlm_caw.h:105) at GRANT time; in caw_claim_inherit_epoch compare the tombstone's stored gen vs the
   claiming gen; inherit ONLY on match. This keeps the slot index = hash(ino) unchanged (no consistency
   trap), but still needs the gen at grant/claim time — same mixed-caller availability issue, though a
   gen=0/"unknown" there only DISABLES the epoch-reset optimization for that path (safe fallback = behaves
   like today), it does NOT corrupt locking. **So the slot-pad2 alternative is SAFER (fail-safe) than the
   resource_id-hash approach (fail-corrupt). PREFER slot-pad2.**
3. Param-gate (default 0) + cluster-uniform; validate dlm_scaling@32 PASS + no 16 regression + no
   lock-incoherence (watch for double-EX / P108 / corruption probes at scale).
