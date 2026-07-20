---
name: sess20-reuse-leafhash-root-pinned-undestaged-leaf-handoff
description: sess20 LEAD (NOT yet proven): reuse leaf-hash loss — modify-path evict KEEPS a pinned+undestaged leaf (daddr 2093296, same-incarnation, NOT ABA). But…
metadata:
  type: project
---

## sess20 (ccloop 8ddb16a2) — reuse leaf-hash loss: partial diagnosis, NOT yet root-proven. (Build F8FF8E54, dir_reuse_coherency 24-round reliable repro; dirwr=1 → drc-FAIL ×2 so dirwr=1 does NOT fully hide it.)

## EVIDENCE (test2=node2, the node whose entries are lost):
`P-EVICT-SKIP ino=131 daddr=2093296 (dir LEAF) dirty=0 in_ail=0/1 pin=1 done=1 buf_incarn=2263907978 cur_gen=2263907978 buf_gen=18 undest=1` — the modify-path evict (mxfs_dir_evict_data_blocks) KEEPS this leaf (undurable: pin=1 + undestaged). buf_incarn==cur_gen ⇒ **NOT an ABA/incarnation problem** (refutes the prior-incarnation-leaf hypothesis).

## IMPORTANT CAVEAT — do NOT over-commit: **P-LEAFWRITECLOBBER did NOT fire** this run (no leaf write with buf_cnt<disk_cnt), yet entries were durably lost. So:
- The pinned leaf in P-EVICT-SKIP may simply be node2's LEGITIMATE current-tenure work (correctly not evicted) — NOT necessarily the clobber.
- The hash-drop mechanism under REUSE is therefore NOT the same as the sess19 xfsaild-stale-leaf-reflush (which DOES trip P-LEAFWRITECLOBBER). It is so far UNIDENTIFIED.

## ALSO NOTE: mxfs_dir_flush_data_blocks (release path, xfs_mxfs_dlm.c:~1267) ALREADY xfs_log_force(0)+wait_unpin's pinned dir buffers before handoff — so a naive "release doesn't unpin" theory is likely wrong. Confirm whether THIS leaf (high dir2 offset, daddr 2093296) is actually reached by that flush's iext walk and whether the flush runs on the yielding node before the peer reads.

## NEXT (RULE 4, instrument to PINPOINT the drop — do this BEFORE any fix):
1. Add `dir_gen` (ip->i_dlm_dir_gen) to the P-EVICT-SKIP log line (xfs_mxfs_dlm.c) so we see buf_gen(18) vs dir_gen at the kept leaf — is the kept leaf actually STALE (buf_gen<dir_gen) or current?
2. Add `incarn`/`i_generation` + `dir_gen` to P-LEAFWRITECLOBBER (pal/linux/xfs_buf.c) and also log EVERY leaf write's bgen vs dir_gen (not only buf_cnt<disk_cnt) so we catch the drop even when counts are equal-but-content-divergent.
3. Add a detector at the leaf READ on the modify path (xfs_dir2_leaf_addname → xfs_da_read_buf) that logs, for the reused dir ino, whether the leaf base it RMWs already contains node2's just-added names — to localize WHERE node2's hash vanishes (added-then-lost vs never-added).
4. Reliable safe repro: `./run.sh 2 tcp dir_reuse_coherency` (24 rounds, fails from ~round 16, node2 entries, readdir=200/lookup-fail, NO wedge). 

## CONTEXT: official ./run.sh 2 tcp core = 16/16 (criterion MET earlier but marker CLEARED by user — work continues on this reuse bug, now tracked as criteria.json row 13 = FAIL). P20 guard REMOVED. readahead-disable kept. Separate corruption-shutdown variant also exists under reuse [[sess20-residual-is-daddr-reuse-corruption-not-leafhash]]. [[sess20-dir-reuse-coherency-reliable-repro-characterization]] [[sess20-FIX-2tcp-leafclobber-and-reada-disable]]
