---
name: sess48-REFINED-all-durability-passes-residual-is-fua-read-stale-content
description: sess48(ccloop) REFINED: 8/tcp dir_reuse — ALL writer/reader durability+reload checks PASS (P68 DURABLE, DIRREL_DIFFERS=0, P37-STALEBMAP=0, readdir re…
metadata:
  type: project
---

## sess48 (ccloop 4cb2d0a2) REFINED — all durability checks pass, loss still intermittent

Build E871702B = config #1 defaults + diagnostic gates (all gated on dir_relverify, default 0,
so harmless). Repro: tests/drc_dirtyskip.sh "dir_relverify=1" 24 8.

### EVERY durability/coherency check PASSES, yet 8/tcp loses ~1-6 dirents/24-round run:
- **Writer data blocks durable**: DIRREL_DIFFERS=0 (FUA-compare each dir block vs in-core at
  release) AND P25-RELVERIFY-MISMATCH=0.
- **Writer dinode/extent-map durable**: P68-GROWREL-VERIFY all DURABLE (55-76×), 0 STALE-DISK
  (FUA-read di_size/nextents == in-core at every EX release).
- **No writer modifies on a stale bmap**: P37-STALEBMAP-MODIFY=0 (plain-read disk_nx never >
  in-core nx at modify start).
- **Reader readdir reload never bails**: P48-RDRELOAD bailed=0, and nx_before==nx_after in ALL
  cases (9/10/11 consistent) — the reader's in-core extent map already matches disk at reload.

### CONCLUSION
The durable lost-update is NOT explained by: writer data durability, writer dinode/extent-map
durability, stale-bmap modify, reader extent-map staleness, or reader reload bail. ALL the
obvious coherency layers verify clean. The residual is an INTERMITTENT FUA-READ returning STALE
data-block CONTENT (a peer's just-committed dirent absent from the FUA-read image) DESPITE the
block being FUA-durable per the release-time compare — i.e. a deep SCST/target FUA-read
coherency timing gap (FUA-read occasionally pierces to an un-destaged/older medium image), OR a
sub-block content race the whole-block FUA-compare at release doesn't catch. Matches the sess96
note ("evict+reread does not reliably pull a peer's just-committed dir block from SCST").

### TWO variants observed (intermittent, run-to-run):
1. MASS (rare): a peer's WHOLE grow (~74 entries, nextents 8 vs 10) missing from peers — a
   reader-extent-map-staleness instance (seen once with dir_relverify timing).
2. SINGLE/FEW (common, ~1-6/run): individual dirents lost — FUA-read-stale-content.

### NEXT ANGLE (untested): treat it as a target-level FUA-read coherency gap.
- Test fua_disable=1 (read from the coherent SCST WRITE-CACHE instead of FUA-piercing to
  backing) — IF this cluster's SCST cache is cross-initiator coherent, reads would always see
  the latest write. (CAVEAT memory: fua_disable=0 fua_always=1 was the "proven" 4/tcp config —
  but 4/tcp passes anyway; the FUA path may be the 8-node liability.) 
- OR add a reader-side SCSI cache INVALIDATE (not just FUA-read) before the dir-block re-read.
- OR verify the actual SCST emulate_write_cache setting on the cluster (the gen_per_handoff
  comment assumes emulate_write_cache=0 = platter-durable; if it's 1, FUA semantics differ).
Confirm the target caching model FIRST (it determines whether FUA-read or cache-invalidate is
the coherent primitive). See [[sess48-DECISIVE-loss-is-reader-extentmap-staleness-not-writer]]
(superseded on the extent-map point) and [[sess48-FINAL-state-extentmap-staleness-is-next-root]].
</body>
