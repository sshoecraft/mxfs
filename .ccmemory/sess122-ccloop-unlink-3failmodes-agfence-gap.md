---
name: sess122-ccloop-unlink-3failmodes-agfence-gap
description: sess122 (ccloop): cache_coherency now 2/4 (cross_visibility+rename_visibility PASS clean). unlink_visibility fails 3 ways, all = missing AG-lock fenc…
metadata:
  type: project
---

## sess122 (ccloop run 4eef1f39) — RULE-4 re-diagnosis on a CLEAN cluster

### Build context
Tree head builds **C01185FA** (= prior `1F7AF33C` = sess121 `E9963FFA` + W2/detector +
my P-CAWEXH/continue instrumentation). 1F7AF33C is a COHERENT SUPERSET: P122/P124
corruption fixes, sess109 ip-only drain, sess111 redrain, sess108 chokepoint all present.
NOTE: the ccloop relay summary (sess24 "W2/inobt double-alloc detector") was chasing the
WRONG thing — the real blocker is dir/AG-meta coherency, not inobt double-alloc.

### CLEAN-cluster ship-gate status (MXFS_NODE_OFFSET=0, test1-4, fua_disable=1, instr=0)
ALWAYS power-cycle (virsh destroy+start ALL 4) + `bash tests/reset4.sh 4` before trusting.
The FIRST run after a stale/old-build mount gives false failures.
- **cross_visibility: PASS** (2m14s)
- **rename_visibility: PASS** (61s alone) — the subtest sess121 said TIMED OUT @900s now passes
- **unlink_visibility: FAIL** (stochastic, ~2m18s)
- **cross_write_read: FAIL** (exit=1, not yet root-caused this session — likely reg-file durability)
- Fast repro (tests/repro_rename_concurrent.sh "test1 test2 test3 test4" 20 AND 100):
  **TOTAL_FAILS=0 ×4, no shutdown** (SESS50-STARVE fires but resolves). Healthy.

### unlink_visibility fails via THREE distinct mechanisms (all stochastic, same root)
1. **Divergence livelock** → `P-CAWEXH ino=135 req=5 ... ea_claim=0 ea_compat=0 ea_regwait=0`
   ALL CAS counters ZERO. PROVES the 100-retry exhaustion is NOT a CAS-storm (refutes sess39
   framing). The spin is in the caw_lock **divergence path** (dlm_caw.c ~1387-1468): node
   believes our_mode==EX on a dir inode while a PEER also holds incompatible → clears own bit,
   `continue`s on CAS rc==0 — but in-core i_dlm_mode=EX re-adds the bit each iteration →
   livelock → -ETIMEDOUT → SHUTDOWN. (Two EX holders = mutual-exclusion violation = P106 family.)
2. **xfs_defer_finish_noroll corruption** (xfs/libxfs/xfs_defer.c:721, SHUTDOWN_CORRUPT_INCORE)
   — on-disk/in-core corruption during deferred-ops finish, in the two-EX-holder window.
3. **P110-BIO-OVER-LOGGED on an AGI buffer** (daddr=4174642 ops=xfs_agi comm=rm) refused the
   write ("bnobt revert averted", kept in-core) → `xfs_inactive_ifree` Metadata I/O Error (0x1)
   at xfs/xfs_inode.c:2093 → SHUTDOWN. The write-side interlock MISFIRES on a legitimate AGI
   update during unlink.

### ROOT (matches [[cache-coherency-rearch-provenance-and-gap]] user directive, 2026-06-07)
The 3-invariant FENCE was applied to DIR/INODE locks (→ cross_visibility+rename_visibility pass)
but NEVER to AG locks (AGI/AGF/AGFL/bnobt/finobt). AG-meta coherency is substituted by
write-side interlocks (P110/P122/P124) which are band-aids — they now MISFIRE (AGI revert →
I/O error). The user's directive: STOP band-aiding; apply the fence to AG locks = fix the
**frozen `pag_dlm_meta_gen`** so Inv-2 acquire-time invalidation actually fires for AG-meta
(sess19b shared-on-disk-AGF-epoch design), + GFS2-style drain relocation for the inode
lock-inversion divergence.

### Instrumentation added (KEEP, gated only by INODE-type, fires on exhaustion)
dlm_caw.c mxfs_dlm_caw_lock: P-CAWEXH dump with per-continue-site counters
(ea_claim/ea_compat/ea_regwait/div/yield_bo/yield_stale/wait_enoent + last_hex/last_hpr).
Decisive for distinguishing CAS-storm vs divergence-livelock vs yield-livelock.

### NEXT
Implement the AG-lock fence: find why pag_dlm_meta_gen is frozen (acquire-side
mxfs_dlm_invalidate_ag_meta / mxfs_ag_meta_coldread_discard not bumping/firing), make AG EX
acquire bump a SHARED on-disk AGF epoch so peers cold-read AG-meta on next acquire. Then
REMOVE the P110/P122/P124 write-side band-aids. RULE 5: this is the architectural fix the user
directed — consult Gemini for the concrete pag_dlm_meta_gen/AGF-epoch implementation if stuck.
Related: [[cache-coherency-rearch-provenance-and-gap]] [[sess121-bnobt-clobber-writeside-fix]]
[[sess19b-shared-epoch-design]] [[sess108_lessons]].</body>
