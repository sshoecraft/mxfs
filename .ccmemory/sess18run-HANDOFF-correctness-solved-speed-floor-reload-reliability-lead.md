---
name: sess18run-HANDOFF-correctness-solved-speed-floor-reload-reliability-lead
description: sess18(ccloop) HANDOFF: 8/tcp dir_reuse correctness SOLVED (mht275 3/3, mht300 clean) + 1/2/4 tcp PASS. Build 58360875 KEEP. Residual: dir-data free-…
metadata:
  type: project
---

## sess18 (ccloop) HANDOFF — biggest progress in many sessions; one deep residual remains

### DONE (build 58360875D262141AAAA2BA6, KEEP — DO NOT REVERT):
- **1/tcp 16/16, 2/tcp 17/17, 4/tcp 17/17** full suites PASS (verified, no regression).
- **8/tcp dir_reuse_coherency CORRECT**: mht=275 → 3/3 clean runs (72 rounds, 0 loss); mht=300 → clean. The 100+ session dir-data lost-update is effectively eliminated at mht≥275.
- 4 KEEP speed fixes (xfs_mxfs_dlm.c + xfs_mount.h + pal/linux/xfs_super.c): NO_INODE-BAST recv-thread offload, PR-drain skip, clean-release log_force skip, release-flush coalescing. + removed test masking-`sleep 1` (tests/suite/dir_reuse_coherency.sh). Details in [[sess18run-MILESTONE-8tcp-dirreuse-PASSES-correct-mht300-speed-only-residual]] [[sess18run-FIX-noino-bast-offload-recv-thread-eliminates-60s-create-stall]].

### THE REMAINING BLOCKER (two coupled axes, both rooted in ONE thing):
**The dir-data reload-on-handoff is ~99.75% reliable PER HANDOFF, not 100%.** Residual loss = dir free-slot double-allocation: two nodes pick the same free slot in a dir data block from a stale free-space view → one dirent dropped (readdir N-1/N, durable ENOENT). At 4 nodes it's "399/400" (per code comment line ~11464). Higher mht = fewer handoffs = loss→~0 (masked, not fixed). So:
- **Correctness needs high mht** (≥275) to suppress the per-handoff miss.
- **High mht = slow** (8-node dir-EX serialization: each node's 100-create burst ~250ms fills the mht window; 8 nodes × 2 waves serialized = ~6s create/round). 24 rounds ≈ 300-340s, STRADDLING the 300s blanket TEST_TIMEOUT (mht=275 passed 2/3 on speed; mht=300 ~337s over).

### THE FIX (next session): make the reload 100% reliable, then a FAST low mht is both correct AND fits 300s.
- The gen-invalidation hook (xfs_da_btree.c:3176, `whichfork==DATA_FORK && i_dlm_dir_gen!=0`) DOES cover leaf+free blocks (they're data-fork offsets ≥ geo->leafblk) and re-reads stale cached blocks via XBF_TRYLOCK+FUA. The miss is subtler: a stale-base RMW race where the free-slot/bests view used by xfs_dir2 addname is stale at the moment of slot selection despite the gen bump (TRYLOCK-skip on a momentarily-locked block leaves loaded_gen<dir_gen → stale base kept; see sess52 acquire-side LOCKED-WAIT + sess36 ABA-clobber notes). Likely fix: on a cross-node dir-EX handoff, FORCE a full extent-map + leaf/free reload (MXFS_IF_DIR_RELOAD) coupled with the dir_gen bump (the code at xfs_da_btree.c:2820-2825 explicitly notes "couple a dir_gen bump with an extent-map reload"), OR make the addname free-slot selection re-validate against a FUA-fresh leaf/free block. Signal is reliable (dir_epoch_adopt=1 level-triggered, dg_shadow LRU); the gap is the REFRESH completeness/timing, not the signal.

### Speed facts (RULE 0): create ~6s/round (inherent 8-node single-dir contention at mht — NOT a bug; each create ~2-3ms, serialized), rm ~3.5s (800 reused-inode inactivations, PR-revokes now cheap), verify-reads ~2-3s, 4 MQTT barriers (correctly wait for slowest node, no artificial latency). 4 vCPU/node. The blanket 300s is uncalibrated for 8-node (does 2× the 4-node work). DEFAULT mht still 300. Marker NOT written (8/tcp not reliably <300s at the correctness-safe mht). See [[sess18run-STATE-8tcp-correct-at-mht275-speed-straddles-300s-need-10s]].
