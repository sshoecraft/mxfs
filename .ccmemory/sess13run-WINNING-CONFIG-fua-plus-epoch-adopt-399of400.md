---
name: sess13run-WINNING-CONFIG-fua-plus-epoch-adopt-399of400
description: sess13(ccloop) WINNING CONFIG: fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1 → dir_reuse 4/tcp 0/400→399/400, no shutdown. Re…
metadata:
  type: project
---

## sess13 (ccloop 4cb2d0a2) — WINNING CONFIG found for dir_reuse 4/tcp

### Config (build 40AC2A0C, passed via MXFS_EXTRA_MODARGS)
`fua_disable=0 fua_always=1 dir_epoch_adopt=1 dir_epoch_convert_gate=1`

Progression on `./run.sh 4 tcp dir_reuse_coherency`:
- default (fua_disable=1, epoch off): readdir 0/400 & 306/400 + ~150 DABUF_MAP_HOLE shutdowns/node.
- fua only (fua_disable=0 fua_always=1): NO shutdown, readdir 306/400 (rank1=0).
- **fua + epoch_adopt + epoch_convert_gate: NO shutdown, readdir 399/400 on ALL nodes.** P65-EPOCH-ADOPT fires with adopt=1 ~52-58×/node.

So BOTH levers are required: FUA gives coherent (LIO-cache-piercing) reads; epoch_adopt gives reliable cross-node handoff detection (level-triggered, sess64) so a node adopts the disk superset on every real EX handoff. Neither alone suffices (epoch alone=sess10 refuted; fua alone=306).

### RESIDUAL (the final 1/400): ONE durable `.md5` dirent lost per run
- round 2: `node4_f25.md5` gone on ALL 4 nodes; round 18: `node3_f19.md5` gone on ALL 4 nodes. LOOKUP_ENOENT + REREAD_MISS clusterwide = DURABLE loss (not read-side).
- ALWAYS a `.md5` sidecar (the SECOND create wave, when the dir is fuller / block-format / multi-data-block → more free-slot contention). = sess11run PROVEN dir-data-block FREE-SLOT DOUBLE-ALLOCATION: two nodes place different dirents at the same (daddr,off) from bases differing by one in-flight add. Even coherent FUA reads + epoch adopt don't close it → a durability-ORDERING gap (peer's add committed in-core but not yet on the LUN at the adopting node's read) OR a residual concurrent grant.

### NEXT (RULE 4): instrument the contested slot for the residual `.md5`.
Re-run with `MXFS_EXTRA_MODARGS="... dirwr=1"` to get P11-DATALOG (ino,daddr,off,name,comm) for the lost .md5 → confirm which node wrote first/durable and which read stale-base. Likely fix target: make publish-before-handoff a TRUE durability fence for dir DATA blocks (Invariant #1) — A's committed dir-block add must be on the LUN before the master grants B EX. Check the bast_process dir-data drain (xfs_mxfs_dlm.c ~6164) vs the release→master-grant ordering.

### PERF caveat (RULE 0): fua_always=1 ~16s/round = slow. Once residual=0, scope FUA to dir-meta-on-handoff only (don't default fua_always globally — would regress rsync/perf criteria). The criterion harness (prep_node.sh) does NOT pass these params; defaults must change in source OR a scoped mechanism added. Currently dir_epoch_adopt/dir_epoch_convert_gate default 0, fua_disable default 1.
See [[sess13run-BREAKTHROUGH-FUA-removes-corruption-readdir-divergence-remains]] [[sess11run-DIRECTIONALITY-later-writer-stale-bestfree-loses-fix-coherent-refresh]].</body>
</invoke>
