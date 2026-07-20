---
name: sess52_lessons
description: sess52 — PROVEN cache_coherency root = AG/inode DOUBLE-ALLOC; concurrent-EX REFUTED (ex_pop=1); single-holder read-side bnobt staleness
metadata: 
  node_type: memory
  type: project
  originSessionId: 05bc3114-a589-422b-9d5a-759dd123a875
---

# sess52 lessons (2026-06-03)

Build `BDC9BB935D892B24FDFA724` (local + DEPLOYED test1-4, mounted). Adds ONE
pure-diagnostic on DFD5D8F0: modify-time concurrent-EX detector (`mxfs_dlm_caw_ex_count`
in dlm_caw.c → `mxfs_v5_dlm_ag_ex_count` in v5_mount.c → logged in P88-INSTR, pal/linux/xfs_buf.c
when disk_differs==1). KEEP it — it's the proof. No behavioral change.

## PROVEN (RULE 4, direct measurement)
1. **cache_coherency/cross_visibility dominant root = AG free-space + inode DOUBLE-ALLOCATION.**
   Direct on-disk proof: `xfs_dir3_data_reada_verify` "corrupt dir block" hex dumps physically
   contained regular-FILE data ("hello from node 1\n"/"hello from node 2\n") → one physical block
   allocated as BOTH a dir data block AND a file data block. `INODE-REUSE-EVICT incore_ftype=2
   dirent_ftype=1` = inode double-alloc too. `actual=''` test fails = ENOENT (dirent in the
   corrupt double-alloc'd dir block), NOT zero-content — settles the sess49/51 di_size question
   for this mode.
2. **Mechanism = SINGLE-HOLDER read-side AG-meta staleness. CONCURRENT-EX REFUTED.**
   Every P88-INSTR fire (all nodes, all AGs): `disk_differs=1 ag_held=1 buf_gen==pag_gen
   fua_fresh=1 ex_pop=1 ex_nslots=1`. ex_pop=1/ex_nslots=1 EVERYWHERE ⇒ never 2 nodes EX one AG,
   never a dup slot. CAW exclusion is SOUND. The SOLE AG-EX holder writes a STALE low-numrecs
   bnobt (missing peer's committed allocs) whose gen FALSELY == pag_gen → `mxfs_ag_meta_invalidate_stale`
   skips re-read → lost update → double-alloc. This CHECKS+REFUTES the "transient concurrent-EX /
   slot-claim-race" lead sess44/46/47 called "the last unchecked lead" (xfs_alloc.c:2201).

## NEXT (RULE 4)
WHY is the sole holder's bnobt buffer gen-fresh but content-stale? Leading hypothesis: it's
DIRTY/IN-AIL/pinned/delwri (un-refreshable, like the dir-block hook xfs_da_btree.c:2943) — likely
this node's OWN buffer surviving an AG release WITHOUT drain (Arch-Inv-1 violation) OR
mxfs_ag_meta_invalidate_stale gen-stamps fresh without re-reading. INSTRUMENT: add P70-style
dirty/in_ail/pin/delwri fields to the P88 disk_differs==1 log. Then targeted fix (drain-on-release
or force-FUA-re-read on EX acquire) + reset4 + rerun. RULE 5: fix class failed sess42-47; with
concurrent-EX refuted, escalate to Gemini after 1-2 more failed targeted fixes. See [[reference_ship_criteria]].
State: /src/mxfs/state.md (sess52 section at top).
