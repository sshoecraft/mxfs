---
name: sess25-resurrection-guard-iteration
description: sess25: P25-RESURRECT-SKIP iflush guard — GEN discriminator is a DEAD END at real (dirwr=0) timing (chunk-reinit randomizes gens). Need gen-free inob…
metadata:
  type: project
---

## sess25 (ccloop) — P25-RESURRECT-SKIP iflush guard (xfs/xfs_inode.c, after P17B block, runtime param mxfs.resurrect_gen_window). Root = inode resurrection [[sess25-drc-leaf-double-alloc-live-evidence]].

## GEN-DISCRIMINATOR IS A DEAD END (proven this session):
- v1 `disk_gen>incore` (0302171A): REGRESSED — readdir=0 EVERY round, ~50% FALSE-POSITIVE on fresh-chunk inodes (chunk-init randomizes di_gen via get_random_u32).
- v2 `==incore+1` (82050E75): no regression (rounds 1-5 pass) but P25-SKIP=0 (real dirwr=0 timing lags >1 free).
- v3 bounded `1<=delta<=64` (046691B9, param resurrect_gen_window=64): **P25-SKIP=0 at dirwr=0** → the real resurrections have gen deltas OUTSIDE [1,64] = chunk-REINIT fully re-randomized the gen (whole inode chunks freed by rm-rf → realloc → new random gens). **sess119 was RIGHT: cross-node gens are incomparable.** Any gen test either false-positives (>) or misses (bounded). ABANDON gen-based discrimination.
- NOTE the dirwr=1 P-IRESURRECT showed disk=incore+1 (single-free lag) — that was a SLOW-TIMING ARTIFACT; real dirwr=0 churn does multi-free + chunk-reinit. The resurrection→leaf-CRC corruption is largely a dirwr=1 artifact too.

## REAL dirwr=0 BLOCKER (046691B9, guard inert): dirent-VISIBILITY divergence, NOT leaf-CRC.
round 3 (rounds 1-2 PASS): test1(rank1, dir owner) readdir=**0**/200, test2 readdir=**100**/200, lookup_fail=0, leafCRC=0. test2 sees ONLY its own 100 entries; test1 (which created the dir+100 entries) reads its OWN dir EMPTY after drop_caches. = dir-inode/dirent cross-node coherency under reuse churn (the sess17-20 family). May be DIR-INODE resurrection (stale empty incarnation flushed/reloaded over the live one) with randomized gens → uncatchable by gen, catchable by gen-free alloc check.

## NEXT (gen-free, the only viable path):
1. **inobt-allocation check in xfs_iflush**: when dip is FREE (di_mode==0 && di_nlink==0) and in-core live, look up ip->i_ino in the inobt — if FREE → resurrection → skip; if ALLOCATED → legit → flush. DEFINITIVE (gen-independent). RISK: AGI lock-ordering (iflush holds cluster buffer; AGI normally locked BEFORE inode) → use xfs_buf_incore(AGI, XBF_TRYLOCK); skip the check (fall through to normal flush) if AGI not cached/contended. Bounds deadlock. Check perf (RULE 0).
2. OR **publish-on-create** root fix: register new inodes in the DLM at create so a peer's free BASTs the creator → creator invalidates its stale copy → no resurrection AND dirent coherency. Bigger change.
3. Re-characterize the dirwr=0 dirent-visibility WITHOUT perturbing the race (dirwr/instr=100x slow hides it) — maybe a lock-free always-on counter.

## BUILD STATE: 046691B9 deployed, window=64 = INERT+SAFE (catches 0, no regression, FP negligible). KEEP the guard structure (correct shape) + param; only the discriminator needs replacing with the inobt check. P-DBLALLOC detector (xfs_alloc.c, gated) + drc_probe.sh KEEP. Marker NOT written.</body>
