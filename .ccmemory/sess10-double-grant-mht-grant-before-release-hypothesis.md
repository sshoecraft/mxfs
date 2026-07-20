---
name: sess10-double-grant-mht-grant-before-release-hypothesis
description: sess10 CORRECTED: master-table double-grant ALREADY fixed (gen-token 404BC55C). Remaining root = XFS-layer i_dlm_mode=EX cached persists past DLM gra…
metadata:
  type: project
---

## CORRECTED understanding (sess10, after reading dlm/dlm.c + [[sess-tcp-DLM-double-grant-FIXED-gen-token]]).

## The MASTER-TABLE double-grant is ALREADY FIXED (build 404BC55C, gen-token protocol, KEEP, in current tree): process_remote_request now ALWAYS RE-AFFIRMs a sender's existing grant (bump grant_gen, re-send) instead of remove+promote-a-waiter (which created a 2nd EX holder). Gen-checked release ignores stale releases. dg_grant_ex/dg_shadow (dlm/dlm.c ~2109) is the P-DOUBLEGRANT detector. That validated tcp_dlm_scaling 2/2. So the DLM master grant table does NOT hand two nodes EX concurrently anymore.

## REMAINING ROOT (this is what still fails ~1-2/16 full suite) = XFS-LAYER stale cached EX + LOSSY eviction-ring:
- The XFS layer caches i_dlm_mode=EX per inode and the dir fast path serves MODIFYs on it WITHOUT re-checking the DLM layer. When the DLM-layer EX grant legitimately moves to the peer, THIS node's i_dlm_mode stays EX cached during a DEFERRED BAST (MHT-defer keeps state==CACHED; or pin/active-holder). The fast path then RMWs on a lock it no longer holds at the DLM layer = P106-STALE-EX (cached_mode=EX, on_disk_held=0).
- Cross-node dir invalidation is done via the EVICTION-RING DIR_MODIFY heartbeat (note_dir_modified -> bumps peer i_dlm_dir_gen -> consumer_refresh/modify_refresh reload). This heartbeat is LOSSY/LAGGY on TCP (proven sess10: per-node gen diverged 4 vs 13). A missed notification -> stale base -> durable dirent resurrection. The eviction-ring is a BAND-AID for the missing synchronous DLM BAST-invalidation.

## THE FIX (Gemini+GPT converged, [[sess10-gpt-verdict-serialize-tenure-not-epoch]]): make dir cross-node coherency rely on the RELIABLE DLM BAST (acked TCP msg), NOT the lossy eviction-ring. Specifically:
1. When a peer acquires the dir EX (real DLM grant), THIS node's deferred-BAST MUST be honored within MHT and i_dlm_mode demoted to NL -> next access slow-paths + reloads fresh (reload-on-reacquire). 
2. The MHT-defer must NOT let the fast path serve EX MODIFYs once the DLM grant has actually moved (i.e. once a real BAST is in flight for a CONTENDED dir). Reads from cache OK; modifies must block until reload.
3. Then the eviction-ring becomes redundant for correctness (keep only as optimization).

## KEY QUESTION to resolve first (read dlm/dlm.c grant path + xfs ilock_begin MHT): can the peer be GRANTED the DLM EX while this node still defers its BAST (MHT)? If the master only grants AFTER this node releases, then MHT is safe at the DLM layer and the bug is purely the XFS fast-path serving modifies during the MHT window before this node's own release — fix = don't serve EX-modify while a BAST is pending (state should not stay CACHED for a contended dir under MHT). If the master CAN grant before release, that's a second double-grant path the gen-token fix missed.

## Builds: current deployed 5EC1F0BF (=427DB5AF logic). Double-grant gen-token fix is IN-TREE. Validate any change with FULL `./run.sh 2 tcp` x3 FOREGROUND (per [[feedback-never-background-wait-poll]]).
