---
name: sess-tcp-tcp-dlm-scaling-flaky-dir-lostupdate-root
description: tcp_dlm_scaling ~50% flaky (build 73B0809D): concurrent same-dir rename → ON-DISK stale dir/inode (eviction does NOT fix). Root = drain incompletenes…
metadata:
  type: project
---

## STATE: 2/tcp suite = 15/16, tcp_dlm_scaling ~50% FLAKY. CRITERION NOT met.
CLEAN BUILD = **73B0809D5381454A7F9B070** (B4 inode guard + P-RDDIAG gated behind mxfs_instr).
B4 fix KEEP ([[sess-tcp-B4-noauth-guard-fixes-fast-repro-wedge]]). Across ~6 suite runs
tcp_dlm_scaling: F,F,P,P,F,F. Other 15 PASS reliably (crash_consistency PASS 3/3 on 73B0809D).

## TEST: each node 150× `echo r>f; mv f f.done; rm f.done` of OWN files in SHARED dir; node1
checks `ls` drained==0. FAIL = 1 leftover, ALWAYS a NODE2 file, BOTH nodes agree, persistent
(survives drop_caches) = genuine ON-DISK dangling dirent. Two variants: nlink=1 (live, looks
like a fresh create — rename+rm reverted) or nlink=0 (inode freed, dirent resurrected). node2
RESULT=PASS (its mv+rm reported success). DIR-STALE-SKIP=0 (NOT the dirty-skip window).

## DECISIVE dirwr=1 EVIDENCE (at a real failure): P106-MR-SKIP=476/447, P106-MR-EVICT=1/4,
P-DIRBAST=4/6, DIR-STALE-SKIP=0, NO lock timeouts. => the dir modify-refresh
(mxfs_dlm_dir_modify_refresh, gen-keyed) almost NEVER evicts: it takes the gen short-circuit
(gen==evicted_gen) because the ACQUIRE-side gen bump (xfs_mxfs_dlm.c:6902, slow-path only) does
NOT fire on cached fast-path reacquires — releases(4-6) >> evicts(1).

## TRIED + REFUTED (build E4DFA811, REVERTED): bump i_dlm_dir_gen on the dir EX BAST RELEASE
(xfs_mxfs_dlm.c:4118, before mxfs_v5_dlm_inode_unlock) to force evict on any post-release modify.
RESULT: tcp_dlm_scaling STILL FAILED (n2_r7 nlink=0) AND crash_consistency REGRESSED to FAIL
(node1 read `exp= got=<hash>` for node2_f32-35 — over-eager eviction exposed NON-DURABLE peer
reads). => KEY LEARNING: forcing eviction (cold re-read from disk) does NOT fix the resurrection,
so the stale data is ON DISK, not a stale clean cache. ROOT = a node RELEASES the dir grant with
the FINAL dir-block (and inode-cluster nlink) state NOT yet durable on disk (drain pipeline
incompleteness at release for the concurrent create+rename+rm sequence), so the peer re-reads the
stale durable image. This is Architectural Invariant 1 territory (drain before on-disk unlock) +
sess65 (DLM EX serializes the entry, not the metadata writeback lifecycle).

## NEXT: instrument the BAST-release DRAIN for the dir DATA block + the file inode-cluster under
the rename+rm sequence — confirm node2 unlocks with n2_rN still on the durable dir block / nlink=1
on the durable inode. Look at mxfs_dir_data_durable / bast pipeline coverage of xfs_rename's
removed-source-entry block and the unlinked inode's cluster. Do NOT chase clean-cache eviction
(refuted). dirwr=1 via prep_node.sh MODARGS (revert after). Repro: full `./run.sh 2 tcp` ~2-3×.
See [[sess-tcp-15of16-tcp-dlm-scaling-stale-readdir-root]] [[sess65-zsl-dlm-handoff-metadata-coherency-root]].
