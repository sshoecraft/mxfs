---
name: sess68-decision-reversal-stay-v5-port-mxfs1-coherency
description: sess68 REVERSES sess67 asymmetric pivot (user-directed). DATED (v5 cache_coherency RESOLVED sess130; 17/17 pass ≤8 nodes 2026-07-08): v5 & mxfs.1 were then mirror images: v5 perf-green/coherency-fail, mxfs.1 coherency-green/perf-fai…
metadata:
  type: project
---

# sess68 — DECISION REVERSAL: abandon asymmetric pivot, stay on v5 + port mxfs.1's proven coherency

## The user OVERRULED the sess67 asymmetric-MDS pivot. Do NOT build asymmetric MDS.
User's argument (decisive): MXFS uses CAW deliberately because symmetric shared-disk + SCSI
CAW/ATS is the proven high-performance clustered-FS design — **VMFS** scales it to 64-node
clusters with thousands of VMs. An asymmetric metadata-server forwards every create/unlink/
rename over a network RTT → it would DESTROY v5's already-green native perf. The pivot was a
prior session's flinch, not sound. [[sess67_lessons]] and `decision-pivot-to-asymmetric-mds`
and `/src/mxfs/ASYMMETRIC_MDS_PLAN.md` are SUPERSEDED/SHELVED.

## THE KEY EVIDENCE: v5 and mxfs.1 are MIRROR IMAGES on the same ship gate
- **v5** (`/src/mxfs`, fork of native Linux XFS 6.19): `.criteria_results.json` =
  cache_coherency **FAIL 0/4** (THE blocker, ~90 sessions) but single_node_paired **PASS 104%**,
  rsync_paired **PASS 103%**, everything else PASS. → PERF SOLVED, only COHERENCY fails.
- **mxfs.1** (`/src/mxfs.1`, custom cluster caches, v0.21.13 srcversion 078468BAFD…):
  cache_coherency **PASS 4/4** + zero_silent_loss PASS, but single_node_paired FAIL 252%,
  rsync_paired FAIL 365%, scaling_curve FAIL >1800s. → COHERENCY SOLVED, only PERF fails.
- Each codebase cracked exactly what the other can't. v5 is ONE criterion from ship; that one
  criterion is what mxfs.1 already solved. → Stay on v5; use mxfs.1 as the coherency blueprint.

## HOW mxfs.1 solved coherency (the blueprint to port into v5)
mxfs.1 does NOT use native XFS buffer-cache/AIL/delayed-logging. It owns 3 DLM-aware caches
(`libmxfs/{block_cache,inode_cache,dir_cache}.c`) + its own `alloc.c` (walks AGI/AGF/inobt/
bnobt). Every entry bound to a CAW DLM lock. FOUR hard invariants, each at ONE chokepoint:
1. **FUA-write before DLM release.** inode_cache.c `flush_inode_to_disk` → serialize+CRC+journal
   → `mxfs_pal_bdev_write_fua` (durable before return) → only THEN release lock. (inode_cache.md
   step 8-9; gate `mxfs_defer_dir_fua_disable` / multi-node.)
2. **Invalidate the containing block after an inode write** (kills block↔inode aliasing).
3. **Eager dir flush while holding EX** — dir_cache.c `flush_dir_immediate()` on every add/
   remove/rename → on-disk dir state always current → BAST never finds dirty-unflushed dir.
4. **Full drop + re-read on BAST** — drain holders, flush, drop entry; next access re-parses fresh.
Because mxfs.1 owns the cache there is ONE write path / ONE bast path → invariants hold uniformly.

## WHY v5 leaks (the real root of the 90-session tar pit)
v5 approximates the same invariants (drain pipeline before unlock = FUA-before-release; FUA
reads; dir-gen invalidation) but enforces them through native XFS's MANY cache paths (AIL
checkpoint, delwri, log recovery, xfs_iget IRECLAIMABLE recycle), so each hook plugs only one
path and new corruption modes keep surfacing. Not "symmetric is wrong" — "XFS's single-owner
cache lifecycle leaks the invariants."

## THE SMOKING GUN: same bug, mxfs.1 fixed it, v5 keeps re-hitting it
mxfs.1's cache_coherency 1-2/4 → **4/4** fix (v0.21.13) = clear a REUSED inode's stale extent
map on the cache-hit reuse path (`mxfs_inode_cache_get_new_exclusive` → `mxfs_extent_map_clear`
+ clear inline data + zero nextents/size). Without it a reallocated inode inherited a freed
inode's extent map → file data aliased onto a freed dir block → stale XDB3 reads.
v5 has chased THIS EXACT bug for a dozen sessions (sess48/40/86/90: "inode REUSE stale cache",
"inode double-allocation", "stale extent map"). v5 fix site = xfs/xfs_icache.c
xfs_iget_cache_miss / IRECLAIMABLE recycle path.

## PLAN (sess68+)
1. Stay on v5. Do NOT wire the dormant asymmetric scaffolding (it's inert, harmless; leave or rip later).
2. Reproduce cache_coherency 0/4 on a CLEAN power-cycled 4-node cluster (RULE 4). Note sess67 saw
   a 120s CAW writer-starvation WEDGE too — that must be confirmed/fixed first (a wedging FS can't
   be evaluated); sess50 `defer_for_waiter` anti-starvation (build 86855C4) may be insufficient at 4 nodes.
3. Port mxfs.1's 4 invariants into v5's bast_work_fn drain + iget recycle + dir BAST paths,
   starting with the reused-inode stale-extent-map clear. RULE 4 each: reproduce→instrument→fix→re-verify.
4. Keep v5's native perf green (104%/103%) — never add per-op RTT or per-op device sync.

## INFRA
test1-4 = .114/.143/.140/.174 (system libvirt). sshpass: tools/mxfs_sshpass.sh <host> /tmp/.mxfs_pass <cmd>.
Clean run REQUIRES virsh -c qemu:///system destroy+start ALL 4 then tests/reset4.sh 4; verify
srcversion on all 4. mxfs.1 source = /src/mxfs.1/libmxfs/ (.md files = concise per-module arch).</body>
