---
name: sess17run-ROOT-round1-firstdirent-loss-convert-gate-inert
description: sess17(ccloop) ROOT: dir_reuse 8/tcp fails at ROUND 1 — first-dirent (node2_f1) durably lost via sf<->block format flip-flop; convert-gate INERT (0 f…
metadata:
  type: project
---

## sess17 (ccloop) — decisive 8/tcp diagnosis (build E3CDB9F1, NFS-captured)

### Baseline (clean reboot, build E3CDB9F1A26D6B027F27B7B)
- `./run.sh 4 tcp dir_reuse_coherency` = PASS (4/4).
- `./run.sh 8 tcp` full = **12 PASS**; FAIL only: dir_reuse_coherency (0/8) + cascades (fence_during_write 7/8, soak, tcp_dlm_scaling 1/8 — all cascade from dir_reuse wedging the cluster/breaking barriers). **dir_reuse_coherency is the SOLE root blocker for 8/tcp.** 2/tcp,4/tcp pass.

### THE failure (100% reproducible, ROUND 1)
NFS-persistent dmesg capture (tests/suite/dir_reuse_coherency.sh now streams to /src/mxfs/tests/tcp/drc_cap/stream_rankN.log — survives node reboot). All 8 ranks round 1: **readdir=799/800, missing_from_readdir=[node2_f1]** — rank2's FIRST file durably lost. NOT a crash (no EFSCORRUPTED/panic/Call Trace in capture). NOT leaf-hash (P21H-LEAFHOLE fires 400×/rank but is HEALED by P22-DATASCAN). The fatal assertion is the readdir COUNT shortfall.

### Mechanism (sess62 lineage confirmed): sf<->block FORMAT FLIP-FLOP
Round 1: fresh shortform dir (mkdir by rank1), then 8 nodes concurrently create 50 files each → sf→block→leaf conversion storm. ino=131 oscillates on disk between fmt=1 (LOCAL/shortform) and fmt=2 (EXTENTS/block) — P26-LKFMT shows `ino=131 fmt=1 err=-2 name=node2_f1` (a node read the dir as SHORTFORM, and that shortform base was MISSING node2_f1 → ENOENT). A converter freezes a STALE shortform base (missing node2_f1) and writes it block/shortform, durably dropping node2_f1.

### WHY the existing convert-serializer is INERT (key new finding)
P65-EPOCH-CONVGATE (mxfs_dir_epoch_convert_gate, default ON, xfs_mxfs_dlm.c:3493) fired **0×**. Root: it lives in `mxfs_dlm_dir_modify_reload_prelock`, called at xfs_inode.c:1420 — BEFORE `xfs_ilock(dp,EXCL)` (1487) which is where `mxfs_dlm_ilock_begin` (xfs_inode.c:200, runs before the local ILOCK rwsem at 225) acquires the DLM EX and the dir epoch becomes current. So the prelock gate ALWAYS sees a STALE epoch (peer's conversion not yet committed/visible) → `ge > valid_epoch` never true → never fires. The serialization signal (epoch advance) only arrives AFTER EX acquire — too late for the prelock gate. `mxfs_dlm_dir_modify_refresh` (xfs_inode.c:1499) runs ILOCK-held (epoch current) but only evicts data blocks / rebase_shortform (shortform-vs-shortform); it does NOT adopt disk-BLOCK over in-core-shortform, so createname then double-converts.

### Locking constraint that makes the fix non-trivial
- mxfs_dlm_reload_inode needs i_lock (the ILOCK rwsem) via down_write_trylock → can run only with NO ILOCK held.
- Reliable epoch only available AFTER mxfs_dlm_ilock_begin acquires DLM EX.
- mxfs_dlm_ilock_begin (xfs_inode.c:200) DOES run before the local ILOCK rwsem (225) — so a reload COULD run there post-EX-acquire pre-ILOCK. The cached-EX fast path there already does P-FASTEX-EPOCH / P63-FASTEX-HANDOFF data-block refresh (xfs_mxfs_dlm.c:11290-11340) but the sess50 guard (11347) SKIPS the in-place fork adopt on continuous-hold to avoid resurrection.

### Refuted/inert same-class fixes (this + prior sessions): epoch_convert_gate (inert), adopt_block/adopt_content (disk-compare races peer pre-flush), sf_merge (LOCAL/LOCAL only), release-side invalidate, acquire-side b_mxfs_dir_epoch, leaf-rebuild (leaks). See [[sess62-HANDOFF-next-fix-is-namesetset-union-merge-epoch-scoped]] [[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]].

### NEXT: GPT-5.5 consult (RULE 5 justified) for convergent cross-node sf↔block conversion serialization that uses the POST-EX-acquire epoch (not the stale prelock epoch) and prevents a converter from freezing a stale shortform base — without resurrecting deletes. Criterion NOT met; marker not written.</body>
