---
name: sess60-zsl-writer-releases-inconsistent-dinode-bmbt
description: sess60 PROVEN: zsl writer RELEASES dinode di_nextents=14 with on-disk bmbt holding only 13 records. Refuted: reader-FUA, xfsaild-reflush. Root=writer…
metadata:
  type: project
---

## sess60 (ccloop 14d31183) — zero_silent_loss residual ROOT proven writer-side

Build progression: B24B321B (sess59 baseline, ~105-270 silent) →
16FC7EC9 (bmbt-FUA, REVERTED) → FD606B66 (P60 xfsaild-skip-bmbt, REFUTED) →
**503B10EC (P60-RELAUDIT decisive probe, CURRENT)**.

### Two RULE-4 DISPROOFS this session
1. **Reader-FUA REFUTED + reason found.** `mxfs_buf_needs_fua_read` omits
   `xfs_bmbt_buf_ops`, so I added it. But `mxfs_fua_disable = 1` by DEFAULT
   (xfs_mxfs_dlm.c:10250) → the FUA read block (pal/linux/xfs_buf.c:3303,
   gated `!mxfs_fua_disable`) NEVER fires. So the change was byte-identical
   (srcversion reverted to B24B321B) = inert. KEY FACT: with fua_disable=1
   ALL reads are plain-bio hitting the COHERENT SCST shared write-back cache,
   so `loaded < if_nextents` is NOT a per-initiator read-cache artifact — it
   is a genuine writer-side on-disk inconsistency. Reverted the bmbt FUA add.
2. **xfsaild stale-reflush of a RELEASED dir REFUTED.** Built
   `mxfs_buf_xfsaild_skip_bmbt_write` (bmbt analogue of sess23's
   skip_agmeta_write: stale a bmbt buf whose owner dir is in-core + NL).
   Probe `P60-XFSAILD-SKIP-BMBT` fired **0×** cluster-wide → xfsaild never
   pushes a bmbt block for a dir we hold NL. Not the mechanism. (Guard left
   in tree; harmless, never fires.)

### PROVEN ROOT (P60-RELAUDIT, runs ONLY in the BAST-release drain @ ~xfs_mxfs_dlm.c:2833)
`mxfs_dir_bmbt_release_audit(ip)` sums cached level-0 bmbt-leaf bb_numrecs vs
ip->i_df.if_nextents at release. Cluster-wide distinct results for ino=131:
```
 5×  di_nextents=13 leafsum=13 nleaves=1  ok        (stable consistent)
11×  di_nextents=14 leafsum=13 nleaves=1  INCONSISTENT-AT-RELEASE
 6×  di_nextents=14 leafsum=0  nleaves=0  ok        (vacuous: leaves evicted)
```
The releasing WRITER hands EX to a peer with its dinode di_nextents=14 but the
bmbt leaf holding only 13 records. The 14th extent NEVER appears in any leaf
anywhere (max leafsum=13). NOT an eviction undercount: the reloading peer's
`xfs_iread_extents` walks ALL leaves the root points to and also gets
loaded=13 → `ir.loaded != if_nextents` at xfs_bmap.c:1286 → xfs_create
EFSCORRUPTED → FS shutdown → cascade (silent=1600 because shutdown kills the
whole storm; the early-shutdown blast radius, not 1600 individual losses).

### Symptom signature (test16 timeline)
`EVICT-RING-DIRMOD ino=131 gen->2..11` (peer dir-mod burst) → `P138-WAIT
ino=131 mode=5 elapsed_ms=6448` (6.4s EX-handoff wait, sess50 STARVE family,
SEPARATE perf issue) → got EX → `P59-IREAD-MISMATCH loaded=13 if_nextents=14`
→ shutdown. Off-by-ONE every time (the LAST extent added).

### NEXT (open)
Pin down WHY di_nextents increments without the leaf insert landing on disk:
- Enhance P60-RELAUDIT to also log `xfs_iext_count(&ip->i_df)` and
  `xfs_need_iread_extents(&ip->i_df)` + i_dlm_mode: distinguishes
  (a) in-core iext tree=14 but leaf BUFFER=13 (decoupled buffer-vs-iext, or
  bmbt insert hit a different/aliased buffer = sess39 daddr double-alloc
  family) vs (b) di_nextents wrong.
- Candidate: bmbt leaf daddr DOUBLE-ALLOCATION (sess39/42/43) — insert lands
  in buffer instance A(14) but SCST/cache has instance B(13) at that daddr.
- The fix must make the writer flush a CONSISTENT dinode+all-leaves set (or
  not bump di_nextents until the leaf insert is durable) before unlock.

KEEP so far: P60-RELAUDIT probe + skip_bmbt_write guard (xfs_mxfs_dlm.c,
xfs_mxfs_dlm.h, pal/linux/xfs_buf_item.c). Builds on
[[sess59-zsl-residual-bmbt-leaf-disk-staleness]].

### INFRA
Every storm that shuts down leaves ~10-13 nodes D-state (umount hangs);
virsh -c qemu:///system destroy+start them, wait ~12s, all 16 come back with
NFS+module. Outer `timeout` on the criterion must be ≥ 480s (mount+storm+
verify); 320s truncates and corrupts the run into an INFRA fail.
</body>
