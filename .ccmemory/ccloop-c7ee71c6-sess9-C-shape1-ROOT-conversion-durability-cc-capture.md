---
name: ccloop-c7ee71c6-sess9-C-shape1-ROOT-conversion-durability-cc-capture
description: sess9-C: Shape-1 ROOT captured in cache_coherency@16 FAIL (588/590): dir block→leaf conversion not durable-before-visible (disk_nx 1→3 lands AFTER ch…
metadata:
  type: project
tags: [shape1, cache-coherency, dir-conversion, durable-before-visible, typeflip, sess9]
---

# sess9-C — Shape-1 family ROOT captured live (cache_coherency@16/tcp FAIL, run 20260725T231542Z)

## Status at this point (v0.11.103 = 2A3955E92692849839D139C, all 16/tcp)
- D1b+D2 landed and VERIFIED (see sess9-B): withdraw_recovery_test PASS; drc@16 15×PASS consecutively;
  chunk-A board: strong_consistency/posix_multi/mmap_coherency/dlm_fairness/dlm_membership PASS.
- **cache_coherency FAIL 588/590**: node3+node4 got ENOENT on node13.txt (test -f + cat both failed)
  in the cross_visibility phase — post-sync, post-barrier, single-shot checks. 13 other readers fine.
  Self-healed within ~1s (later phases all passed).

## Proven chain (t3 kernlog, 23:15:5x)
1. cv dir = ino 18874498 — a REUSED ino whose prior incarnation was a posix rename_visibility FILE.
   t3 cached the stale file shell: RELOAD-TYPEFLIP-STALE-SKIP ×5 ("type-flip w/o newer gen"), random
   gens unorderable (incore_gen=2802965944 vs disk_gen=665119007) → adoption lag until
   RELOAD-TYPEFLIP-DIRENT-OK / P-RELOAD-IOPS-REWIRE (23:15:56).
2. **THE KEY EVIDENCE**: P62-REL-DIREXT ino=18874498 disk_nx=1 (23:15:56, twice) →
   P62-RELOAD-FORK-SHRINK disk_nx=3 disk_size=8192 (23:15:57) + P65-EPOCH-ADOPT + P63-HANDOFF.
   The dir's BLOCK→LEAF conversion (16th entry overflow) became DURABLE only between :56 and :57 —
   AFTER the cv checks ran (:55-:56). t3's reload honestly adopted the platter's PRE-conversion
   1-extent image; node13.txt's dirent lived in the conversion's NEW block → clean silent ENOENT
   (block-format lookup path, no P26 prints). node1-12,14-16 were in stale block0 → passed.
   Only the conversion-displaced name missed ✓ exactly matches the symptom.
3. drc Shape-1 (round-1 112/128 undercount, self-heals) = same family: 128-file populate converts
   the dir repeatedly; laggard readdir on a stale pre-conversion fork shows only pre-conversion
   entries. drc reuses the dir ino every round (rm+mkdir) → also the type-flip/reuse adopt lag.

## Root-cause statement (RULE 6 OPEN — Shape-1 family)
Dir-growth CONVERSION transactions (sf→block, block→leaf, leaf→node) are not
durable-before-visible at the writer's release: the conversion's NEW blocks (+ grown fork map)
can lag the platter while peers' acquires adopt honestly-stale disk state. Compounded by
reused-ino adoption guards that cannot order RANDOM generations (TYPEFLIP-STALE-SKIP lag).
The durable fix is the GPT phase-2 design (monotonic LVB modification cookie per resource +
per-buffer cookie validation + EX-refresh-on-gap) — replaces unorderable gen heuristics.
A targeted interim fix candidate: writer-side — make dir CONVERSION blocks part of the
release-drain/registry set (verify whether xfs_dir2_block_to_leaf's new buffers are covered by
Phase-2 drain lists; if the conversion happened under a tenure that released before destage,
that's the producer). Reader-side: P65-EPOCH-ADOPT/P63-HANDOFF worked but arrived 1s late.

## Next instrumentation (RULE 4 step 2)
P164-CONV: log every dir format conversion (ino, from→to, new daddrs, tenure/epoch, comm) +
at release-drain: whether those daddrs were drained/registered. Rerun cc@16 in a loop (~14s/run,
FAIL was 1st occurrence in ~4 runs today at .103-era; historical cc was reliably green at .99-.101
so suspect the D-fix builds changed timing, NOT causation — the family predates sess9:
same class as drc Shape-1 which predates everything).

## Board state (single-srcver rerun in progress at 2A3955E)
Done at .103: drc ×15, strong_consistency, posix_multi, mmap_coherency, dlm_fairness,
dlm_membership PASS; cache_coherency FAIL (this defect).
Remaining: fio_perf, fio_perf_vs_xfs, zero_silent_loss, scaling_curve, dlm_scaling, rsync_paired,
crash_consistency, dir_reuse(done), fence_during_write, fault_netpartition, soak, tcp_dlm_scaling;
then 8/tcp board; then 32/tcp, 4/2/1, caw/cawp/cawd, physrig.
P-REG-DURABLE-FAIL rerr=-11 warnings fire during drc (released NOT durable, ~1/run) — same
durable-before-visible family, watch it.
Withdraw test leaves victim FS shutdown — run.sh prep re-preps; prep after any withdraw test.
