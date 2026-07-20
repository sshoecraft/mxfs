---
name: sess62-FINAL-content-level-stale-shortform-base-at-conversion
description: sess62 FINAL: dir_reuse 4/tcp node1_f1 loss is CONTENT-level — the sf->block converter's in-core shortform base is MISSING node1_f1 (rank1 published…
metadata:
  type: project
---

## sess62 FINAL — dir_reuse_coherency 4/tcp: CONTENT-level stale shortform base at sf->block conversion

Build at handoff: **37F6F9A6** (baseline-equivalent: all fixes disabled/gated; probes only). Criterion NOT met (1✅ 2✅ 4❌ dir_reuse_coherency, 8 never run).

### DECISIVE NEW EVIDENCE (build F57039C0, adopt_disk_format re-enabled + P62-CRCONV probe)
At the create post-EX-acquire/pre-convert point (xfs_inode.c ~1504), P62-CRCONV logged in-core dir format:
  test2: **27× incore_fmt=LOCAL (1)**, 3295× EXTENTS (2). **P61-ADOPT-DISK fired 0×.**
=> When a node is in-core LOCAL (shortform) at the converting create, **DISK IS ALSO LOCAL** (else adopt_disk_format's LOCAL!=disk_fmt face-1 would fire). So the converter sees disk=LOCAL and converts legitimately — BUT its in-core shortform base is **missing node1_f1** (a CONTENT gap), while the disk shortform (or a peer's) HAD it. The sf->block conversion then drops node1_f1.
- **mxfs_dir_modify_adopt_disk_format REFUTED AGAIN** (now PROVEN why): it compares FORMAT/nextents/size only. A LOCAL-vs-LOCAL **content** gap (same format, in-core shortform missing a peer-committed dirent) is INVISIBLE to it. It also added a FUA dinode read per create (RULE-0 perf hit). Re-disabled (if(0) at xfs_inode.c ~1504); P62-CRCONV now gated behind mxfs.instr.
- My sess62 prelock format-adopt serializer (mxfs_dir_adopt_block) fired **0×** — the prelock hook runs BEFORE dir EX acquire, so its FUA read is a racy snapshot (disk LOCAL). Set default **0** (off, kept for reference, xfs_mxfs_dlm.c mxfs_dlm_dir_modify_reload_prelock).

### REFINED ROOT
The sf->block converter (could be rank1 OR a peer, varies by round) holds/builds an in-core SHORTFORM base that does NOT include node1_f1 (rank1's first dirent), even though node1_f1 is committed to the disk shortform for the SAME incarnation. The reload/adopt at EX acquire is CONTENT-incoherent for shortform: it adopts format+scalars but the in-core shortform dirent set lags the disk shortform (the converter never merged node1_f1 in). Conversion (xfs_dir2_sf_to_block) freezes the stale base -> node1_f1 durably lost. (Consistent with sess61 P60-SFCONV-BASE node1f_cnt=0 / has_node1_f1=0 evidence.) Also possible compounding: >1 converter/round -> logical-block0 split (sess62-REFINED memo: extent[0] flip-flop orphans block0@120). Both reduce to: the converter's pre-conversion dir state (shortform content OR which block0) is not cluster-coherent.

### NEXT FIX (RULE 4, narrowed — content-level shortform coherency BEFORE conversion)
The converter must adopt disk shortform dirents it lacks (same incarnation, ADDITIVE) before sf->block. Options:
1. At the converting create (in-core LOCAL, multinode, after EX acquire), FUA-read disk shortform; if disk has dirents (by name/count) in-core lacks for the same di_gen, MERGE them into the in-core shortform before converting (mxfs_dlm_reload_inode already has a shortform 3-way merge P-SFMERGE — invoke/force it here). CAUTION: additive merge only; a delete-heavy path (rename/remove tests) could RESURRECT deleted entries (sess53 root) — scope to create-only or gate by "disk count > in-core count" (growth only).
2. Or fix WHY the EX-acquire reload leaves the converter's shortform content stale: check the self-skip guards (P52-FREEDREUSE-DIR-SKIP, P116-SELFCLOBBER-SKIP, P33-FROMDISK-DIRSHRINK at xfs_mxfs_dlm.c ~7200-7320, and the sess58/59 dir self-skip-the-skip) — one likely KEEPS the node's stale shortform when it has its own in-flight mods, preventing adoption of node1_f1. Add a probe at reload OUTCOME (adopted vs which-guard-skipped + in-core sf count before/after) for the converting dir to pin it.
3. GPT-5.5 architectural design (publish-before-release + full extent rebuild on acquire + epoch-gated skip) in [[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]].

### Probes in tree (KEEP): P62-DATAINIT-BLK0, P62-DWR-N1F1 (xfs_dir2_data.c, always-on low-flood); P62-REL-DIREXT (xfs_mxfs_dlm.c release, capped); P62-SF2BLK-CALLED (xfs_dir2_block.c, capped); P62-CRCONV (xfs_inode.c, instr-gated); P60-LBMAP (instr-gated). Test snapshots create-phase dmesg/round (drc_create_r${round}_rank${R}.dmesg). Repro: ./run.sh 4 tcp dir_reuse_coherency (fails ~every round, node1_f1). Reset: virsh -c qemu:///system destroy+start test1-4. See [[sess62-REFINED-block0-split-extent0-flipflop-orphans-node1f1]] [[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]].</body>
