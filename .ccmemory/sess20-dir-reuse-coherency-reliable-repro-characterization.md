---
name: sess20-dir-reuse-coherency-reliable-repro-characterization
description: sess20: dir_reuse_coherency suite test (24 rounds, build F8FF8E54) RELIABLY + SAFELY reproduces the reuse leaf-hash loss: always node2's entries, cum…
metadata:
  type: project
---

## sess20 (ccloop 8ddb16a2) — RELIABLE + SAFE reproducer for the reuse leaf-hash loss, now a tracked criterion.

## TEST: tests/suite/dir_reuse_coherency.sh (registered criteria.json row 13 + manifest, coord=barrier, min_nodes=2). 24 rounds (DRC_ROUNDS), NF=50, each round: both nodes concurrently create NF data+NF md5 into ONE shared dir, barrier, EVERY node cold-reads + checks count AND per-entry lookup (the leaf-hash check crash_consistency lacks), barrier, rank1 rm-rf+recreate (reuse churn), barrier. Dropped per-file O_SYNC (one sync/wave) to fit time budget. showstat 2 tcp now = 16 PASS / 1 FAIL (row 13 ❌), honest.

## CHARACTERIZATION (build F8FF8E54, run FAIL 0/2, NO shutdown — clean leaf-hash loss):
- **Always node2's entries** missing (node2_fNN / .md5), observed on BOTH nodes. node1's (rank1, the dir creator/owner) entries never lost. Asymmetry: node2 must cross a DLM EX handoff to add into rank1's dir → its hash insertions are the ones clobbered by a stale leaf base.
- **readdir=200 always; only lookup fails** → pure LEAF-HASH index loss; data blocks complete.
- **Cumulative + growing**: round16=6 missing, r17=10, r18=16, r19=18; each round's missing set ⊇ prior, DESPITE rm-rf+recreate each round. Old-incarnation leaf staleness persists across the reused-inode/daddr recreations.
- **First ~15 rounds clean, manifests from round ~16.** THIS is why a 10-round test passed (false green); 24 rounds is the reliable threshold. Probe cc_blockdir_probe also reproduces (iter 6-15, distinct-dir-name variant).

## TWO FAILURE MODES under reuse churn (probabilistic): (1) this leaf-hash lost-update (clean, no wedge); (2) corruption shutdown (xfs_da_read_buf verifier fail during addname → xfs_trans_cancel → FS shutdown, needs reboot) [[sess20-residual-is-daddr-reuse-corruption-not-leafhash]].

## KEY: the sess20 readahead-disable fix (dir_no_reada=1) fixed the NON-reuse crash_consistency leaf-hash loss but NOT the reuse variant — there is a SECOND source of stale leaves: a prior-incarnation leaf image of the reused dir inode/daddr used as the RMW base. NEXT HYPOTHESIS: the sess15 incarnation/ABA invalidation (b_mxfs_dir_incarn vs i_generation) and/or acquire-evict does not cover the LEAF block (high dir2 offset 0x800000) on inode/daddr reuse, so node2 RMWs a stale prior-incarnation leaf and its new hashes are dropped on writeback. Instrument the leaf read/write for the reused dir ino with incarnation + bgen at the failing rounds. Build F8FF8E54 (P20 guard REMOVED, readahead-disable kept). [[sess20-dir-reuse-coherency-reliable-repro-characterization]] does not wedge → safe debug loop (no reboot needed between runs). [[sess20-FIX-2tcp-leafclobber-and-reada-disable]]
