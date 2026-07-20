---
name: AAA-ccloop8ba7-sess3-GPT-consult-false-fresh-acquire-lineage
description: GPT consult (sess3 8ba7ae5c): dbl-alloc root ranked = FALSE-FRESH acquire discards CIL-resident AG-meta (H-A>H-B). Probe design: grant-lineage cert +…
metadata:
  type: project
tags: [ccloop-8ba7ae5c, gpt-consult, double-alloc, false-fresh, ag-fence, probe-design]
---

# GPT-5.6 consult (RULE 5, 2026-07-16, sess3 ccloop 8ba7ae5c) — AG double-alloc mechanism ranking

Input evidence: [[AAA-ccloop8ba7-sess3-PROVEN-double-allocation-uv-vs-posixmulti]] (6 uv-dir blocks re-handed
out across 6 AGs; ALL fence probes silent on 24/32 nodes; no shutdown; disk coherently pre-alloc for exactly
those extents; dir fork kept them).

## Ranking
1. **H-A (top): invalidate_ag_meta LOCKED branch stales a CIL-resident/pinned/not-yet-in-AIL bnobt/cntbt BLI
   at a FALSE-FRESH acquire.** BLI_STALE → at unpin the bli is freed → committed alloc never reaches home;
   disk stays coherently pre-alloc; NOTHING writes stale content (all write probes correctly silent); P79
   only covers the in-AIL flavor. Prerequisite: fresh acquire WITHOUT completed prior release (cached-grant
   evaporation / slot-state race / phantom family). 6-AGs-in-10s = one common lock-state event hitting several
   cached grants, not 6 allocator bugs.
2. **H-B (close 2nd): coldread_discard(fresh_peer=true) discards in-AIL+undestaged bnobt/cntbt** — same
   false-fresh prerequisite, later lifecycle stage. Treat A+B as ONE root: "fresh-acquire may destroy local
   AG metadata without proof the prior grant completed its release checkpoint or a real intervening owner
   existed."
3. Rank-1-8 journal-rotation blind spot (dir-extension is NOT uniformly distributed; P88 too narrow) — keep
   collecting journals per-iter.
4. H-D aliasing (two xfs_buf for same phys block) plausible-lower; needs extra event to explain never-durable.
5. Target/SCST ordering: low (inode-fork side of same txns survived).

## Decisive probe set (deploy order)
1. **Grant-lineage certificate (P130)**: per-AG: bump release_done at completed full-drain+unlock; at every
   FRESH acquire, if we had a grant lineage and NO completed release since → P130-FALSE-FRESH (high-sev,
   dump_stack). THE prerequisite discriminator for H-A/H-B.
2. **Destructive-discard lifecycle (P131)**: at EVERY AG-meta xfs_buf_stale/coldread-discard: log bli attached/
   LI_DIRTY/LI_IN_AIL/pin/delwri/li_lsn/undestaged + reason tag (inval-locked/coldread-fresh/coldread-reclaim)
   + comm. Do NOT infer safety from in-AIL alone (CIL-resident is the invisible class).
3. Allocation witness + raw pre-unlock verify (heavier; only if 1+2 don't converge).
4. Physical write ledger (bio-level) — catches bypass writes.
5. Alias detector (per phys interval, warn on overlapping live xfs_bufs).
6. dblalloc_probe content-check: make unconditional in repro; add disk-owner parse + in-core-vs-FUA-disk AGF
   freeblks discriminator (READ-side stale vs WRITE/durability loss).

## Fence gaps named (vs 3-invariant design)
A. No ownership-lineage continuity proof before destructive invalidation ("fresh" ≠ "peer completed Inv-1").
B. Invalidation may destroy unresolved local state (unsafe set = active-tx dirty, CIL-resident, pinned,
   commit-callback-pending, delwri, write-in-flight — in-AIL is NOT the full set).
C. Release quiescence is write-centric: needs AG-use/transaction quiescence (REVOKING gate: block new AG users,
   wait active AG txns commit, capture CIL cutoff, force, wait SPECIFIC BLIs unpin, write, wait, flush,
   publish cookie, unlock). Waits on SPECIFIC BLI lifecycle, NOT global ail_push (avoids cross-AG deadlock).
D. Buffer-generation must bind to PHYSICAL block for the whole reference lifetime (alias-safe), not to one
   xfs_buf object found in a cache walk.

## Ghost dirent (test1)
Same fence family, DIFFERENT lock (dir-DLM + dir data buffer), NOT a semantic consequence of the bnobt loss
(losing an alloc record cannot resurrect a dirent). One-node-only ⇒ retained stale cache object on node1 most
likely (or delete-side update discarded by same CIL/not-AIL stale mechanism). Trace: ghost block's buffer
lifecycle + dir-DLM lineage + raw disk hash post-delete-release.

## Repro plan
Fresh prep + precond+cache_coherency+strong_consistency+posix_multi (~5min/iter, no fio initially),
MXFS_EXTRA_MODARGS="dblalloc_probe=1", pull ALL 32 journals per-iter immediately (beat rotation), static
fork-overlap check on /home/steve/disk.img per-iter. Harness → tests/ per RULE 3.
