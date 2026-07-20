---
name: compiled-dirreuse-8tcp-dgshadow-lru-forkadopt
description: sess17 ccloop: dg_shadow LRU + fork-adopt eliminated 8/tcp dir_reuse data-loss; residual = EX-contention slowness + leaf holes.
metadata:
  type: project
tags: [compiled, dir_reuse_coherency, 8tcp, dg_shadow, lru, fork-adopt, dlm, ex-contention, leaf-hash, sess17]
---

# sess17 (ccloop) — dir_reuse_coherency 8/tcp: dg_shadow LRU + fork-adopt

Central topic: closing the multi-session `dir_reuse_coherency` durable data-loss on
the MXFS TCP transport at 8 nodes. This session made the biggest progress in 100+
sessions: two KEEP fixes (**fork-adopt** + **dg_shadow LRU eviction**) ELIMINATED the
durable data-block lost-update. The remaining 8/tcp failure is no longer data loss —
it is EX-contention slowness (RULE-0) plus unhealed leaf-hash holes.

## Criterion status (full `./run.sh <N> tcp`, KEEP build 544A912E9356E96A39F24E2)
- **1/tcp = 16/16 PASS**
- **2/tcp = 17/17 PASS** (verified on LRU build, no regression)
- **4/tcp = 17/17 PASS** (was failing in-suite on the inherited build; the LRU fix RESOLVED it)
- **8/tcp = FAIL** — `dir_reuse_coherency` only; every other 8/tcp failure
  (fence_during_write, fault_netpartition, soak, tcp_dlm_scaling) cascades from
  dir_reuse wedging the cluster / breaking barriers.

3 of 4 node-counts pass; criterion NOT met, marker NOT written.
[[sess17run-STATE-3of4-criterion-pass-8tcp-residual-leafhash-plus-contention]]
[[sess17run-FINAL-mht-tradeoff-improved-by-LRU-next-close-lowmht-residual]]

## The two KEEP fixes (do NOT revert — they eliminated the data loss)

### 1. fork-adopt (xfs_mxfs_dlm.c ~11027–11460)
In the `mxfs_dlm_ilock_begin` cached-EX FAST-PATH, added `bool dir_ex_handoff`, set
TRUE only at the two RELIABLE cross-node handoff setters (grant_gen change ~11295,
dir_epoch advance ~11331) — NOT the lossy gen/RELOAD-flag setter (~11229). Changed
the fast-path reload `mxfs_dlm_reload_inode(ip, ..., false)` → `..., dir_ex_handoff`:
on a genuine handoff a DIFFERENT node held EX since our last grant, so our prior work
was already drained at our release → force disk-SUPERSET adopt (`post_release=true`)
overriding keep-stale guards → the converter never freezes a stale shortform/fork base.
**Result: moved the 8/tcp failure ROUND 1 → ROUND 5.** Round-1 fresh-dir sf→block
conversion loss (node2_f1) FIXED, no timeouts, no corruption.
Builds: **9AF854E62C318B799F513FB** (fork-adopt only, KEEP baseline).
[[sess17run-FIX-forkadopt-handoff-round1-fixed-round5-residual]]
[[sess17run-HANDOFF-forkadopt-kept-round5-residual-next-granularity]]

### 2. dg_shadow LRU eviction (dlm/dlm.c) — the multi-session ROOT
`dg_shadow` is the master-side table that computes the cross-node EX-handoff bit +
per-resource epoch: a fixed array (`DG_SHADOW_N=512`) walked by LINEAR SCAN per grant.
Its old eviction recycled the FIRST INACTIVE slot. dir_reuse creates ~800 file inodes/
round; between two consecutive grants of the HOT shared dir inode (briefly inactive),
those ~800 file-inode grants RECYCLED its slot → `last_owner` LOST (handoff under-fires)
AND epoch reset to 0 (level-triggered epoch goes backwards → grantee never adopts).
Both reliable-handoff signals corrupted → dir reload under-fired → stale-base RMW →
durable lost-update.

FIX: added monotonic `last_grant_seq` (++ per grant) to `dg_shadow_ent`; evict the
inactive slot with the OLDEST `last_grant_seq` (LRU) instead of the first. The dir
inode is granted ~800×/round (every file create takes parent-dir EX) → its seq stays
near the top → never the LRU victim → handoff/epoch stay reliable. Keep `DG_SHADOW_N`
SMALL (512): `dg_grant_ex`/`dg_release` LINEAR-SCAN it per grant, and N=16384 caused
O(N) acquire timeouts.
**Result: dir_reuse 8/tcp RDMISS=0 on ALL nodes (was 799/800 lost EVERY round for 100+
sessions). The durable DATA-BLOCK lost-update is ELIMINATED.**
Builds: **CA23BB74** (N=1024 LRU, reached round 9), **544A912E9356E96A39F24E2**
(N=512 LRU, current KEEP, default mht=300).
[[sess17run-MILESTONE-dgshadow-LRU-fixes-dataloss-newresidual-timeout-leaf]]
[[sess17run-HANDOFF2-dgshadowLRU-keep-8tcp-residual-is-EXcontention-slowness]]

## Build progression
E3CDB9F1A26D6B027F27B7B (baseline, round-1 failure diagnosed) → 9AF854E6 (fork-adopt,
round 1→5, KEEP) → LRU builds CA23BB74 (N=1024) / 544A912E (N=512, current KEEP).
Refuted-and-reverted along the way: A95DE7B9 (blanket force-evict), CC554745 /
A95DE7B9-class epoch-gated evict (see Refuted).

## Diagnosis: how the failure was found

### Round-1 (fixed by fork-adopt): sf↔block FORMAT FLIP-FLOP
All 8 ranks round 1: `readdir=799/800, missing_from_readdir=[node2_f1]` — rank2's FIRST
file durably lost. NOT a crash, NOT leaf-hash (P21H-LEAFHOLE fires 400×/rank but is
HEALED by P22-DATASCAN). ino=131 oscillates on disk between fmt=1 (LOCAL/shortform) and
fmt=2 (EXTENTS/block) under the concurrent create storm (8 nodes × 50 files) —
`P26-LKFMT ino=131 fmt=1 err=-2 name=node2_f1`: a converter freezes a STALE shortform
base (missing node2_f1) and writes it, durably dropping the dirent.
Key finding — WHY the existing convert-serializer was INERT: `P65-EPOCH-CONVGATE`
(`mxfs_dir_epoch_convert_gate`, xfs_mxfs_dlm.c:3493) fired 0×. It lives in
`mxfs_dlm_dir_modify_reload_prelock` (called at xfs_inode.c:1420, BEFORE
`xfs_ilock(dp,EXCL)` at 1487), so it always sees a STALE epoch (`ge > valid_epoch`
never true). The reliable epoch only becomes current AFTER `mxfs_dlm_ilock_begin`
(xfs_inode.c:200) acquires DLM EX — which runs before the local ILOCK rwsem (225), the
one place a reload can legally run post-EX / pre-ILOCK.
[[sess17run-ROOT-round1-firstdirent-loss-convert-gate-inert]]

### Round-5 residual (data-block revert, later folded into "eliminated by LRU")
After rm-rf+recreate (reused ino 131), round 5 lost ONE first-dirent (e.g. node3_f1):
`P13-STALEREAD ino=131 use_block=2 daddr=2093296 ... node3_f1` — a REUSED daddr block
read near-EMPTY. `incore_gen==disk_gen` (sameincarn=1) → NOT incarnation mismatch; a
TENURE-scoped durable lost-update: a node keeps a stale near-empty REUSED-daddr block
across a handoff (payload-LSN "undestaged" keep-guard FALSE-POSITIVE in
`mxfs_dir_drain_evict_data_blocks` ~line 5242), then RMWs it, reverting the peer's
committed dirent. The dg_shadow LRU fix subsequently drove this to RDMISS=0 at mht≥150.
[[sess17run-FIX-forkadopt-handoff-round1-fixed-round5-residual]]

## The CORE WALL (proven): signal GRANULARITY mismatch
- Any PER-MODIFY staleness signal (master `dir_epoch`, `i_dlm_dir_gen` — both bumped by
  `mxfs_dlm_note_dir_modified` on EVERY create) over-fires under the 8-node storm →
  invalidate→cold-read storm → ~1900 DLM acquire timeouts (RULE-0 fail).
- The PER-HANDOFF signal (`grant_gen` tenure token) is the right granularity (won't
  storm) but is edge-triggered and under-fires ~80% on TCP (sess61 lineage). The
  dg_shadow LRU fix is precisely what made this per-handoff signal reliable.
- What works WITHOUT over-firing: `owner_aba` + `incarn_aba` (always-on in
  `xfs_da_read_buf`, fire only on genuine reuse) and fork-adopt (once-per-acquire on
  grant_gen/epoch handoff).
[[sess17run-HANDOFF-forkadopt-kept-round5-residual-next-granularity]]

## REFUTED — do NOT re-try (all caused DLM timeouts or dropped work)
- **Per-modify epoch invalidation, acquire-side**: epoch-gated force-evict in
  `mxfs_dir_drain_evict_data_blocks` (evict in_ail block whose `b_mxfs_dir_epoch <
  valid_epoch`) → 2142 acquire timeouts + DATASCAN-HEAL=0, died round-5 barrier
  (build CC554745).
- **Per-modify epoch invalidation, read-side**: `mxfs_dir_evict_prior_tenure=1`
  (xfs_da_read_buf:3307–3336, GPT part-2, compares `b_mxfs_dir_epoch <
  mxfs_v5_dlm_inode_dir_epoch`) → 1938 acquire timeouts + 47 rc=-110.
  Root of over-fire: the master dir epoch advances on EVERY dir modify by ANY node, so
  under the storm `stamped_epoch < master_epoch` is true on almost every read.
- **Blanket force-evict** (drop undestaged keep unconditionally on handoff): REGRESSED
  round 5→3, 1 entry→24 entries lost (dropped a CURRENT-tenure un-drained block) — build
  A95DE7B9.
- **dir_release_invalidate=1**: fired 0× (keep-guard skips all release-time blocks).
- **DG_SHADOW_N=16384**: O(N) linear-scan acquire timeouts (keep N small).
Also inert/refuted (this + prior sessions): epoch_convert_gate, adopt_block/adopt_content
(disk-compare races peer pre-flush), sf_merge (LOCAL/LOCAL only), leaf-rebuild (leaks).
[[sess17run-REFUTED-epoch-invalidation-both-sides-causes-dlm-timeouts]]

## 8/tcp residual after the LRU fix — TWO sub-blockers (8 nodes only; 4 nodes fine)

### A. Hot-dir-master EX contention / starvation (the dominant, tractable-perf blocker)
Focused 8/tcp dir_reuse: RDMISS=0 on all nodes, but FAILS via a **P36-RETRY storm on
ino=131**. 8 nodes serialize on the ONE shared dir EX; the now-reliable handoff fires a
fork-adopt reload on EVERY cross-node handoff, and the workload ping-pongs the dir EX
~800×/round → reload per acquire → long retry queue → hard rc=-110 (120s) acquire
timeouts → force_shutdown on the hot-dir MASTER nodes (test1/test2, hash-distributed) →
~67s/round (reached round 6 in ~400s) = RULE-0 slowness fail.
Profiling (RULE 4): `P34-ACQ-SLOW` ino=131 median ~1.85s / max 2.8s = QUEUE wait (not
the read); `P51-REL` release drain_ms 0–1ms (fast); `fua_disable=1` (plain reads). The
cost is the QUEUE, not the reload read. Dir-EX serialization (8 nodes, one dir) is the
inherent bottleneck; dlm_fairness passes in isolation but starves under the storm.

### B. Leaf-hash lost-update / unhealed leaf holes
`P21H-LEAFHOLE=400`, `P22-DATASCAN-HEAL=0`, `P26-DSCAN-MISS`: an entry is in the data
block but its hashval is durably dropped from the LEAF index — a node RMWs a STALE leaf
base (the leaf is a SEPARATE dir block; fork-adopt/LRU fixed the DATA block, not the
leaf's content-level RMW). `dir_leaf_rebuild=1` fires (`P26-REBUILD-OK`) but does NOT
close the holes (once-per-tenure rebuild insufficient under rapid 8-node handoffs, or
the rebuild itself RMWs a stale leaf). Likely secondary to the slowness / barrier break.

## mht (inode_mht_ms, default 300) tradeoff — HUGELY improved by LRU, now SMALL gap
Baseline pre-fix: 799/800 lost EVERY round at all mht. After LRU:
- **mht=300 (default): RDMISS=0 (data loss eliminated), but 8-node dir-EX STARVATION** →
  P34-ACQ-SLOW ~2s queue wait → some acquire hits 120s → force_shutdown (rc=-110) →
  ~67s/round (round 6 of 24) = RULE-0 slowness + shutdown fail.
- **mht=150: RDMISS=0, no shutdown, but leaf holes (P21H=400) + acqTO=236 on masters
    (round 5–8).**
- **mht=50: fast (round 15), but small data loss returns (RDMISS=2–7) + leaf holes +
    shutdown** — the reliable handoff doesn't fully close the sub-50ms fast-handoff race.
Neither mht passes 8/tcp, but the gap is now SMALL (0 at 300, 2–7 at 50). Default kept
at 300.
[[sess17run-FINAL-mht-tradeoff-improved-by-LRU-next-close-lowmht-residual]]

## CRITICAL nuance: two DISTINCT dir_reuse blockers historically
Before the LRU fix, at build 9AF854E6: 8/tcp fails FOCUSED (real round-5 lost-update),
while 4/tcp PASSES focused (4/4) but failed IN-SUITE (`./run.sh 4 tcp` full: 12 PASS
then dir_reuse FAIL 0/4 + cascades) — a cross-test STATE LEAK (leftover /mnt/shared /
inode-daddr reuse collision / DLM residue), same "passes standalone, fails in-suite"
pattern as CLAUDE.md sess49. The LRU fix RESOLVED the 4/tcp in-suite contamination
(now 17/17). Kept here as a documented failure mode to watch for.
[[sess17run-CRITICAL-two-distinct-blockers-8tcp-focused-vs-4tcp-insuite]]

## GPT-5.5 design (RULE 5 consult) — for the round-5+ incarnation-mismatch family
Two parts, both required (superseded in practice by the LRU fix for the data block, but
retained as the design for any incarnation-mismatch residual):
1. **Post-EX / pre-local-ILOCK reload keyed on LEVEL-TRIGGERED di_gen** (not grant_gen
   edges): at the xfs_ilock DLM-EX hook, if in-core `i_generation != authoritative
   di_gen` → force `mxfs_dlm_reload_inode(post_release=true)` = DISCARD old incarnation
   fork + ADOPT disk. di_gen is level-triggered, returned on every grant. Do NOT gate on
   size==0 (the existing P103 reuse-adopt does — why it fired 0×). Generation mismatch ⇒
   discard/adopt, NEVER merge (old incarnation dirents are logically dead).
2. **Per-daddr dir-buffer INCARNATION STAMP checked at buffer lookup.** The buffer cache
   is daddr-keyed; the XFS dir verifier proves "block belongs to ino 131" but NOT "to
   incarnation X of 131", so a stale prev-incarnation XBF_DONE buffer at a reused daddr
   passes and becomes a stale RMW base. Stamp each dir DATA/LEAF/NODE/FREE buffer with
   {ino, di_gen, dir_epoch, kind} at coherent read; at every dir buffer lookup, if
   XBF_DONE && stamp mismatches current {ino, i_generation, epoch} → clear DONE, cold
   reread, verify, restamp. A dirty stale-incarnation buffer = corruption (don't flush).
   Cover the sf→block / block→leaf conversion read paths too.
MXFS already has `bp->b_mxfs_dir_incarn`, `bp->b_mxfs_dir_gen`,
`ip->i_dlm_dir_evicted_incarn`, and `new_incarn=(evicted_incarn!=i_generation)` in
modify_refresh — machinery partially exists.
[[sess17run-GPT-design-incarnation-stamp-dirbuf-plus-digen-reload]]

## NEXT directions (for a fresh session)
Two convergent paths; the gap is now perf/small-residual, not bulk data loss:
1. **Fix the high-mht (300) 8-node EX starvation** so the correct config is also fast:
   reduce per-handoff cost (make the fast-path reload LIGHTER — skip full
   `xfs_inode_from_disk` when di_nextents/extent-map unchanged; only block content
   changed → drain_evict/lazy read suffices), OR add DLM grant-queue anti-starvation /
   fairness for the hot resource, OR MHT batching (hold dir EX longer per node → fewer
   handoffs).
2. **Close the low-mht (50) residual** (RDMISS 2–7 + leaf holes) so a fast mht is also
   correct: give the LEAF block the same reliable-handoff coherence the data block got —
   evict/cold-read + rebuild the leaf hash index from coherent data on EVERY genuine
   handoff (not once per tenure).
Untried transport-level idea: make `grant_gen` reliable on TCP by fixing the edge-loss
in the DLM grant path (distinct from all buffer-layer attempts), enabling a per-handoff
(not per-modify) refresh without the storm. RELEASE-side alternative: a releasing node
invalidates ONLY its own cached dir buffers after the drain (bounded, once per handoff).

## Operational / infra notes
- Reboot ALL nodes clean (`virsh destroy+start`) between runs before trusting any result.
- `DRC_STREAM=1` streams dmesg to `/src/mxfs/tests/tcp/drc_cap/stream_rankN.log` (NFS,
  survives node reboot) — KEEP for diagnosis; `tests/tcp/drc_cap` for NFS capture.
- Harness: `tests/suite/dir_reuse_coherency.sh`.
- Criterion NOT met (3/4 node-counts); marker NOT written.
