---
name: sess60-residual-writer-side-durable-node1f1-clobber
description: sess60: node1_f1 durable loss CLASSIFIED LOOKUP_ENOENT+REREAD_MISS all nodes. Read-coherency probes SILENT -> it's a WRITEBACK clobber (current-incar…
metadata:
  type: project
---

## sess60 residual — node1_f1 DURABLE dirent loss: classified + narrowed to WRITEBACK clobber

After crash fix (F5D370D8) + readdir gen-bump (A1419A72), build EB619331 adds
the suite `mxfs-drc-CLASS` diagnostic. `./run.sh 4 tcp dir_reuse_coherency`
FAILs intermittently (1-2 rounds/12-21), always node1_f1 (rank1 first file).

### DECISIVE classification (build EB619331, round 4, ALL 4 nodes incl creator test1)
`mxfs-drc-CLASS name=node1_f1 LOOKUP_ENOENT REREAD_MISS` on test1/2/3/4.
=> node1_f1's dirent AND its leaf-hash entry are DURABLY ERASED everywhere
(not lookup-able, not in a 2nd readdir, gone even on its creator). This is a
true DURABLE dirent lost-update — NOT an enumeration miss, NOT a transient
stale-block read.

### REFUTED this session (RULE 4 — all instrumented, do NOT repeat)
- Reader-side size-grow (P60-RDSYNC=0, same-size).
- Reader-side gen-MATCH clean stale-serve (P60-GENMATCH-STALE=0 at failing round).
- Reader-side gen-MISMATCH kept-stale dirty/pin (DIR-STALE-SKIP=0, P133=0).
- Release-side drain gap (bast_process flushes dir data ~xfs_mxfs_dlm.c:4546).
- Double sf->block conversion (P42-SFCONV: one converter per incarnation).
- Conversion-drop (P60-SFCONV-BASE: converter base sometimes HAS node1_f1 yet
  loss still occurs; when node1f_cnt=0 it's just because node1 hadn't created
  yet — conversion is early).
- P58 reload self-skip (=0).

### NARROWED root: WRITEBACK clobber, current-incarnation STALE-TENURE
All READ-coherency probes are SILENT, yet the dirent is durably erased => the
clobber is on the WRITEBACK side: a STALE dir block0 buffer is flushed over the
peer's newer committed block0 on disk, erasing node1_f1. The sess40 ABA
writeback skip (P40-INCARN-ABA-DIRSKIP, pal/linux/xfs_buf.c:2119) keys on
INCARNATION (b_mxfs_dir_incarn) and is REFUTED for this:
[[sess40-ABA-fix-REFUTED-clobber-is-current-incarn-stale-tenure]] — the clobber
writeback has bincarn==cincarn (SAME incarnation), so incarnation-skip misses
it. It is a CURRENT-incarnation STALE-TENURE block (cached from before a peer's
intra-incarnation modification) flushed by xfsaild/writeback. Lineage:
[[sess16-stale-tenure-keepguard-fix]] (buf_gen != i_dlm_dir_gen stale-tenure),
[[sess28-dir-data-block-RDMISS-first-block-clobber]].

### NEXT (RULE 4)
1. Instrument the dir-block WRITEBACK path (pal/linux/xfs_buf.c near P40 ~2119
   and the xfs_buf_submit dir-data branch ~2500): on submit of a dir DATA/leaf
   block0, log owner ino, daddr, b_mxfs_dir_gen vs the owner inode's
   i_dlm_dir_gen, b_mxfs_dir_incarn vs i_generation. Catch the flush that writes
   a STALE-TENURE (buf_gen < inode gen) block0 over disk during a node1_f1-loss
   round. PROVE the stale-tenure writeback.
2. FIX (careful — sess32 AIL-wedge risk): suppress/redirect the writeback of a
   dir DATA block whose b_mxfs_dir_gen is stale vs the owner's i_dlm_dir_gen
   (re-read fresh instead of flushing stale), without wedging xfsaild. See
   sess16 keepguard. Alternatively ensure such a stale buffer is invalidated at
   the BAST/gen-bump point so it never reaches writeback.

### KEEP (net progress this session)
- Crash fix (EDEADLK/ACQBAST igrab-NULL phantom-bast UAF). 0 crashes now.
- Readdir gen-bump (xfs_dir2_readdir.c). Failures every-round -> ~1-2/20.

### PERF (parallel RULE-0): ~13s/round x24 ~= 312s vs 300s TEST_TIMEOUT.

Repro: `./run.sh 4 tcp dir_reuse_coherency` (suite/MQTT). Detect completion via
log "=== done:" marker — `pgrep -f "run.sh 4 tcp"` is UNRELIABLE (matches the
Monitor's own until-loop). Reset: virsh -c qemu:///system destroy+start test1-4.
See [[sess60-crash-fix-and-readdir-genbump-progress]].
