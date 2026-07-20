---
name: sess4-END2-classB-root-freed-hint-no-generation
description: sess4 END2 (run27, build 54803BDB): class-B ROOT localized — dangler ENOENTs come from iget CACHE-MISS with fresh struct dlm_stale=1: freed-ino hint…
metadata:
  type: project
---

# sess4 END2 — run27 discriminator result (READ WITH sess4-END-classB-reload-adopt-gap-next-steps)

run27 (build 54803BDBA5FA3410911ED42, dangler=node5_f24.md5 at r7):
- **P-REUSE-RELOAD fired 0×, P4S-LIVESHELL fired 0×** — NEITHER xfs_iget_cache_hit reuse branch executes for the failing igets.
- P-IGET-ENOENT now prints iget_flags: **293× `iget_flags=0x0 reclaimable=0 dlm_stale=1`** (plain lookups, non-reclaimable) + 15× dlm_stale=0.
- Logic: cache_hit CANNOT reach check_free_state with the sess38-branch gates all true (the branch returns -EAGAIN/-ENOENT directly; igrab-fail now goes out_skip). ∴ the 293 prints come from **xfs_iget_cache_miss** — a FRESH xfs_inode struct that already has `i_dlm_stale=1` and `incore_mode=0` while the cluster buffer + FUA read show the dinode VALID (0x81a4).

## ⇒ Class-B ROOT (high confidence, one verify step left)
The **freed-inode hint** (mxfs_dlm_note_inode_freed → heartbeat/evict ring, sess55) is consulted during iget cache-miss (or inode init/from_disk hook): "ino was freed by a peer" → mark dlm_stale=1 and treat as free (skip/override the disk read) to avoid resurrecting stale content. The hint carries **no generation/epoch cutoff**, so after the ino is REALLOCATED the stale hint keeps poisoning every fresh iget cluster-wide → permanent lookup ENOENT dangler (readdir still lists the name from the dir block). The creator's own in-core zeroing (B2) is likely the same consumer running locally.

## NEXT (first actions)
1. `grep -rn 'note_inode_freed\|inode_freed' dlm/ xfs/` → find the ring CONSUMER that sets i_dlm_stale / free-override at iget/cache-miss; read how hints are matched (ino only? gen?).
2. Fix: hint must be generation-aware (record di_gen at free; ignore/clear when disk dinode reads mode!=0 with di_gen != hint gen — that ino was reused) OR cleared on the allocating node's create broadcast. After from_disk of a VALID dinode, never leave mode forced 0.
3. Verify no regression of what the hint fixes (sess55 cross_visibility NL-cache reuse family — the hint exists for real reasons; make it precise, don't remove).
4. Then the criteria ladder (8/tcp ×5 clean → 4/2/1 → full suites).

State: class A (concurrent-EX) remains FIXED & verified through run27 (0 double-grants, 0 readdir loss, rounds 24-35s). Build 54803BDB deployed everywhere; streaming dmesg + full probe set armed; scratchpad runs 19-27 on host.

Links: [[sess4-END-classB-reload-adopt-gap-next-steps]] [[sess4-ROOT-FIX-unlock-fallback-eats-live-request-concurrent-EX]]

## Addendum (post-run27 code trace)
- Ring consumer chain: disklock.c:399 heartbeat monitor replays `rhb->evict` entries → `ctx->evict_cb(data, ino, gen, type)` — **gen IS carried in the ring**.
- evict_cb = `mxfs_dlm_evict_inode_cb` (registered xfs_mxfs_dlm.c:23882, sess56 "Gemini Part 1"). NEXT: read that function — what it does on each hint (sets i_dlm_stale? evicts? does it compare hint gen vs in-core/on-disk di_gen?). The r7-10 onset + permanent poisoning says either it ignores gen, or the marking is applied to FRESH igets via some persistent per-ino side state (check for a hash/bitmap of "recently freed inos" consulted at iget cache-miss — grep i_dlm_stale = true set sites reachable from iget/from_disk).
- Also note: ring baseline logic replays up to ring-depth on FIRST sighting gap (`h - pos > c → pos = h - c`) — a node falling behind replays OLD hints late = late-poisoning source (fits the creator's own in-core zeroing ~11s after create!).

## Addendum 2 — CONFIRMED init bug (grep-proven, fix first next session)
- `mxfs_dlm_evict_inode_cb` (xfs_mxfs_dlm.c:18868) marks CACHED inodes `i_dlm_stale=true` gen-gated (`i_generation <= hint gen` — semantically fine); the problem is the CLEAR side + field lifetime:
- **`xfs_inode_alloc` (xfs_icache.c:91) NEVER initializes `i_dlm_stale`** (0 refs in function) — and likely none of the other mxfs per-inode DLM fields (i_dlm_mode/state/gen/dir_gen/demoter/...? AUDIT ALL). The xfs_inode slab recycles objects → a fresh cache-miss struct inherits the previous occupant's `i_dlm_stale=1` (and any other stale mxfs state) → run27's "fresh struct, dlm_stale=1, iget_flags=0" ENOENTs. FIX: memset/assign all mxfs fields in xfs_inode_alloc (mirror what destroy/reclaim leaves behind); then re-run — the r~7-10 dangler should die. Then check whether the creator-side in-core zeroing (B2) also disappears (it may be the same recycled-state family or the late ring replay).

## Addendum 3 — CORRECTION: Addendum-2 REFUTED
`xfs_inode_alloc` calls `mxfs_dlm_inode_init(ip)` (xfs_icache.c:140) which DOES init i_dlm_stale (xfs_mxfs_dlm.c:17045). Fresh structs are initialized — slab-inheritance theory is WRONG. So the run27 `dlm_stale=1` on non-reclaimable flags=0 shells means the marker (evict_cb / late ring replay) ran on the LIVE cached inode after alloc, and the mode-0 shell persists because BOTH reuse-reload branches are bypassed for it (P4S=0, P-REUSE-RELOAD=0 — measured). Remaining hypothesis to discriminate FIRST next session: these igets ARE cache-HITs whose flow reaches check_free_state WITHOUT entering either branch — find the actual path: add a one-shot dump_stack() (capped 3) inside check_free_state's mode==0 multi-node branch when dlm_stale=1 && !IRECLAIMABLE. The stack names the caller (cache_hit vs cache_miss vs recycle) definitively — stop deducing, measure.

## Addendum 4 — run28 (build 0F5CD6D9518E9E062290730, P4ST armed): DIFFERENT shape, dangler didn't fire
- P4ST-ENOENT-STACK: 0 fires; P-IGET-ENOENT: 0 — the lookup-dangler did NOT occur this run (per-run variability!). Instead: dir drifted 131→132 by r10 (again), then from r11 ALL ranks' readdir DIVERGED on the SAME dirino=132 (drc-DIRID unanimous): ranks 1-2 → readdir=0 (empty view!), ranks 3-8 stuck 668-707/800, persisting r11-16. A third failure shape: intra-inode dir-block mass staleness after the dir-reincarnation event (possibly incarnation-131-vs-132 block confusion / empty-fork reload).
- NEXT SESSION: (1) reruns until the LOOKUP dangler fires with P4ST armed (stack names the iget path — the key B discriminator); expect ~1-in-2 runs. (2) For the run28 shape: victim evidence is in scratchpad run28 (host); check reload/extent-map lines for ino 132 around r10-11 (P62-RELOAD-FORK-SHRINK, P105-ACQ-DIRINODE, P-DE-BLK) — an EMPTY readdir on a 668-entry dir = stale/empty in-core data fork on ranks 1-2. (3) The dir 131→132 drift precedes BOTH shapes — understanding WHY mkdir failed to reuse 131 at ~r9-10 may unify them (131's rmdir-free → reuse blocked by the same stale-shell family at IGET_CREATE time? the reset-for-create branch exists... check P4I-IFREE for ino 131 and the mkdir path around the drift).
- Round cadence stayed healthy (16 rounds); class-A fixes still clean (no double-grants).
