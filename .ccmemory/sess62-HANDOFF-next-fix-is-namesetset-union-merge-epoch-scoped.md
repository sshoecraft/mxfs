---
name: sess62-HANDOFF-next-fix-is-namesetset-union-merge-epoch-scoped
description: sess62 HANDOFF: build F3342B5D baseline-equiv. dir_reuse 4/tcp root = converter freezes a shortform base missing node1_f1 (disjoint same-incarnation…
metadata:
  type: project
---

## sess62 HANDOFF — dir_reuse_coherency 4/tcp (criterion 1/2/4/8 tcp 100%)

### STATE
- Build **F3342B5D** on disk (baseline-equivalent: all fix attempts gated OFF — mxfs_dir_adopt_block=0, adopt_disk_format if(0); only low-flood/instr-gated probes added). 1/tcp✅ 2/tcp✅ (sess58, unchanged). **4/tcp FAILS only dir_reuse_coherency** (~every round, node1_f1). 8/tcp NEVER run.
- Criterion NOT met. Marker NOT written.

### ROOT (PROVEN this session, RULE 4, direct evidence — high confidence)
node1_f1 (rank1's FIRST dirent in the reused shared dir) is durably lost because the **sf->block converter freezes an in-core SHORTFORM base that is MISSING node1_f1**, even though node1_f1 is committed in the disk shortform for the SAME incarnation. Evidence chain:
- P62-CRCONV: at the converting create, in-core=LOCAL while **disk is ALSO LOCAL** (P61-ADOPT-DISK fired 0). So it's NOT a format gap — it's a CONTENT gap (in-core shortform missing a peer-committed name).
- The converter's shortform and the disk shortform are **DISJOINT same-incarnation sets of SIMILAR COUNT** (converter has its own ~11 dirents; disk has rank1's ~11 incl node1_f1). => a COUNT comparison ("disk_cnt > incore_cnt") FAILS to detect the missing name (my sess62 count-based adopt fired ~0 and did NOT fix — REFUTED).
- NOT double-grant (P-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0). force_block REFUTED at 4 nodes. adopt_disk_format (format-only) REFUTED (can't see LOCAL-vs-LOCAL content gap). prelock format-serializer REFUTED (runs pre-EX-acquire, racy, fired 0).
- Compounding: P62-DATAINIT-BLK0 shows multiple block0 daddrs per inode across nodes/rounds (logical-block0 split / extent[0] flip-flop) — the same root viewed at the extent-map level (see [[sess62-REFINED-block0-split-extent0-flipflop-orphans-node1f1]]).

### NEXT FIX (narrowed, RULE 4) — NAME-SET union merge before sf->block, EPOCH-scoped
The converter must union the disk shortform's dirents (incl node1_f1) into its in-core base BEFORE xfs_dir2_sf_to_block freezes it. Requirements:
1. NAME-SET comparison (not count): parse disk shortform names (FUA-read dinode); if disk has ANY name in-core lacks (same di_gen) -> union-merge them in. (mxfs_dlm_reload_inode has a shortform 3-way merge P-SFMERGE — drive it, or write a targeted union.)
2. EPOCH/TENURE SCOPING is MANDATORY (the hard part, GPT design): a blanket union merge RESURRECTS deletes on delete-heavy 4/tcp tests (dlm_fairness, tcp_dlm_scaling — currently PASSING) — sess53 PROVED this regression. Must distinguish "peer ADDED node1_f1 (adopt)" from "we DELETED an entry not yet published (do NOT re-add)". Without per-entry/tenure epoch you cannot tell. So scope by: only merge when we are NOT the EX-continuous owner since our last delete, or gate to create-only, or implement the epoch/write-generation the GPT design specifies ([[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]] has GPT-5.5's full publish-before-release + full-rebuild-on-acquire + epoch-gated-skip design).
3. CHEAPER ALTERNATIVE to investigate first: find WHY the converter's EX-acquire reload (mxfs_dlm_reload_inode) leaves the shortform content stale — a self-skip guard (P52-FREEDREUSE-DIR-SKIP / P116-SELFCLOBBER-SKIP / P33-FROMDISK-DIRSHRINK @ xfs_mxfs_dlm.c ~7200-7320, or sess58/59 dir skip-the-skip) likely KEEPS the node's own stale shortform when it has in-flight mods. Add a probe at reload OUTCOME (adopted vs which-guard-skipped + sf name set before/after) for the converting dir to pin it, then fix that guard to do a union (additive) for shortform instead of keep-stale.

### PROBES IN TREE (KEEP — low-flood/gated): P62-DATAINIT-BLK0, P62-DWR-N1F1 (xfs_dir2_data.c always-on); P62-REL-DIREXT (xfs_mxfs_dlm.c release, capped); P62-SF2BLK-CALLED (xfs_dir2_block.c capped); P62-CRCONV (xfs_inode.c instr-gated); P60-LBMAP (instr-gated); P62-ADOPT-CONTENT (xfs_mxfs_dlm.c prelock, behind mxfs.dir_adopt_block=0). Test snapshots create-phase dmesg/round: /root/drc_create_r${round}_rank${R}.dmesg. Repro: `./run.sh 4 tcp dir_reuse_coherency`. Reset: virsh -c qemu:///system destroy+start test1-4. RULE 0: ~13s/round x24 ~ 312s vs 300s TEST_TIMEOUT — even a coherent run risks timeout; needs a per-round cost cut too.</body>
