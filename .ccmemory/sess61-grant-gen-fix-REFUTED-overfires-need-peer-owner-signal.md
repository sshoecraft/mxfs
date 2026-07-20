---
name: sess61-grant-gen-fix-REFUTED-overfires-need-peer-owner-signal
description: sess61: implemented sess10 grant_gen fast-path fix — REFUTED. grant_gen bumps on EVERY grant promotion (dlm.c:624), not just cross-node handoff, so t…
metadata:
  type: project
---

## sess61 — sess10 grant_gen fast-path fix IMPLEMENTED and REFUTED

Build 7B1FF03F (action gated off; baseline-equivalent). Implemented the full
sess10 plan:
- `mxfs_dlm_grant_gen(ctx,res)` in dlm/dlm.c (+dlm.h) — local node's highest-mode
  GRANTED grant_gen for a resource (modeled on mxfs_dlm_held_mode).
- `mxfs_v5_dlm_inode_grant_gen(ctx,ino)` in dlm/v5_mount.c (+v5_mount.h) — TCP
  (ctx->dlm) only; 0 on CAW.
- `i_dlm_cached_grant_gen` field in xfs/xfs_inode.h.
- xfs/xfs_mxfs_dlm.c: cache it on SLOW-PATH grant completion (~line 10225,
  queried before the i_dlm_lock spinlock); on the dir-EX FAST-PATH serve (after
  the spin_unlock ~9639) compare live grant_gen to the cached value and, on
  mismatch, force dir_ex_stale_refresh + i_dlm_dir_gen++ (P61-GG-FASTSTALE).

### RESULT: REGRESSION (REFUTED)
The fix FIRED (P61-GG-FASTSTALE 5-13x/node) but dir_reuse_coherency went from
~2/24 (baseline) to **16/24 failing rounds (r3-r20)**. nodes_pass=0/4.

### WHY (root of the refutation, traced in code)
`lk->grant_gen = dlm_next_gen(ctx)` is assigned on EVERY waiter->GRANTED
promotion (dlm/dlm.c:624), including BENIGN same-node re-grants (MHT churn:
release+reacquire by the SAME node with no peer in between). So grant_gen is NOT
a clean "lock changed hands to a PEER" signal — it is a monotonic per-grant-
episode counter. My fast-path check therefore OVER-FIRES on ordinary same-node
re-grants, forcing the heavy fast-path evict+fork-rebuild (the dir_ex_stale_refresh
path ~9690) far more often than the lossy eviction-ring did.  That forced refresh
has the sess100 hazard (cold-read returns a STALE image MISSING this node's OWN
just-committed-but-not-yet-published dir change) when over-triggered -> it
DROPS/clobbers own work -> mass failures. sess10's premise ("grant_gen changes
only when the lock changed hands") is FALSE.

### STATE: action gated behind mxfs.dirwr (default OFF) => baseline restored
The infra + detection probe are KEPT; only the harmful forced-refresh action is
gated off. Default runs should be ~2/24 again (NOT re-verified this session due
to context budget — VERIFY first next session: `./run.sh 4 tcp
dir_reuse_coherency` should be ~2/24, build 7B1FF03F).

### NEXT (refined signal)
The fast-path staleness signal must be "a node OTHER THAN US held EX between our
grants", not "our grant_gen changed". Options:
1. Master tracks per-resource PRIOR EX owner; expose a per-resource
   "peer_ex_epoch" that bumps ONLY when a DIFFERENT node is granted EX. Fast path
   fires when peer_ex_epoch advanced since cached. (Needs the local mirror to
   learn peer grants — on TCP a non-master only reliably learns via BAST.)
2. KEY INSIGHT: a REAL cross-node handoff REQUIRES this node to receive a BAST and
   RELEASE (so the peer can get EX). After releasing, our next acquire is a fresh
   SLOW-PATH grant where i_dlm_cached_grant_gen is already re-set by my slow-path
   code -> the fast path would then see a MATCH (no false fire) AND the slow-path
   reload already adopted disk. So the question is: in the FAILING case, is the
   clobbering RMW actually on a FAST path that skipped the slow-path reload, or
   does the slow-path reload itself fail to adopt the peer's block0 DATA (it
   adopts the inode fork but the cached block0 buffer stays — sess61 DECISIVE:
   dirty bufgen=0 block0 kept by the dirty guard)?  STRONG LEAD: the slow-path
   reload (mxfs_dlm_reload_inode) stales the INODE-CLUSTER buffer but may NOT
   evict the dir DATA-block buffers; mxfs_dir_drain_evict_data_blocks runs on the
   slow path (~10221) but KEEPS dirty/in-AIL block0. So even a correct slow-path
   reacquire keeps the dirty stale block0. => the fix likely belongs in the
   DATA-block evict: on a genuine peer-handoff reacquire (post_release, dir_gen
   advanced), a dirty/in-AIL block0 that is content-behind-disk must be DRAINED
   (write our committed work) THEN re-read, or merged — NOT kept. Re-examine
   mxfs_dir_evict_data_blocks/mxfs_dir_drain_evict_data_blocks dirty-keep with the
   P61-BLK0 evidence (dirty=1 inail=0 bufgen=0 core<disk).

### Verified-this-session refutations (don't repeat)
- inode-FORK adopt (format/nx/size compare): fork never behind disk under EX.
- grant_gen fast-path forced refresh: over-fires + regresses.
- logical-block split / read-side stale-serve / double sf-conversion / double-grant
  (double-grant already fixed in dlm.c gen-token): all refuted earlier this session.
See [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]],
[[sess61-DECISIVE-dirty-bufgen0-divergent-block0-kept-by-dirty-guard]],
[[sess61-HANDOFF-state-and-next-steps]].</body>
