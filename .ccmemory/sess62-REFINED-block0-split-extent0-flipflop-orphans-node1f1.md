---
name: sess62-REFINED-block0-split-extent0-flipflop-orphans-node1f1
description: sess62 REFINED (B-vs-C probe): nodes DO adopt a disk extent map, but multiple block0s exist (split); inode extent[0] flip-flops to whoever iflushes l…
metadata:
  type: project
---

## sess62 REFINED — the split is an extent[0] flip-flop that orphans rank1's block0

Build 9559A8F7 (probes only). Added P62-REL-DIREXT (xfs_mxfs_dlm.c, in the BAST-release P55 block, capped 3000): decodes the on-disk dinode's data-fork extent[0] daddr AFTER the release drain = what a peer FUA-reloads.

### DECISIVE EVIDENCE (dir ino=131, 4/tcp, node1_f1 lost ~every round)
- **test1 (rank1) ALWAYS grows block0 at daddr=120** (P62-DATAINIT-BLK0: 23× all daddr=120 — the legit first sf->block conversion each round; node1_f1 lives in block0@120).
- **test1's RELEASE publishes ext0_daddr = a PEER's daddr**, not 120: ext0_daddr=75356136 (gen 1671437160), 4186520 (gen 2539058459), 6279744, 98381600, 87915480, and sometimes 120. So by release time test1's in-core extent[0] points to a PEER's block0 — test1 ADOPTED a peer's block0 and ORPHANED its own block0@120 (which holds node1_f1).
- test2 mostly publishes ext0_daddr=120 (adopted test1's block0; test2 does NOT data_init block0 in this run) but also 4186520/6279744/75356136/98381600.

### MECHANISM (PROVEN, refined from the 4-way-split memo)
1. Each round the dir starts SHORTFORM (rank1 mkdir of reused inode 131).
2. Multiple nodes independently convert shortform->block (or grow) DURING THEIR OWN EX TENURE from their own shortform/stale base, each ALLOCATING ITS OWN physical block0 in its own AG (per-node AG affinity): rank1@120, peers@4186520/6279744/75356136/87915480/98381600. EX is serialized (no double-grant) but the CONVERSIONS are not serialized to a single block0.
3. The inode's data-fork extent[0] (logical-block0 -> physical) FLIP-FLOPS to whichever node iflushes its inode last. node1_f1 is durably written into rank1's block0@120, but when the authoritative extent[0] points to a peer's block0 (e.g. 75356136), block0@120 is ORPHANED -> node1_f1 (the first dirent) durably lost on all nodes.
- So it is NOT purely B (release publishes fine — test1 drains+publishes) nor purely C (peers DO adopt — test2 adopts 120). It is that >1 block0 is ever CREATED, and adoption then converges to the WRONG one, orphaning node1_f1's block.

### THE FIX (must SERIALIZE block0 materialization — only ONE block0 may ever exist per dir incarnation)
Prevent the 2nd..Nth converter from allocating a new block0: when a node is about to convert shortform->block (xfs_dir2_sf_to_block) or grow logical-block0, and the disk dinode is ALREADY EXTENTS-format / already maps logical-block0 for THIS incarnation (FUA-check), it must ADOPT the peer's block0 (reload + use the existing extent[0]) instead of allocating its own. The shortform->block race window (each node converts from its own shortform base before adopting the peer's conversion) is the gap. Candidate: at the dir-modify PRE-LOCK hook (mxfs_dlm_dir_modify_reload_prelock, runs with NO ILOCK so reload is safe) FUA-read the dinode; if disk di_format==EXTENTS while in-core is LOCAL (or in-core extent[0] != disk extent[0]) for the same incarnation, FORCE a full reload to adopt disk's block format BEFORE the modify converts. NOTE the prelock hook currently early-returns when i_dlm_mode==EX (line ~2780) — the converter often holds EX cached, so that skip must be relaxed for the disk-ahead-format case. Beware: do NOT roll back own un-checkpointed work (use post_release/epoch gating).
- force_block REFUTED at 4 nodes (split persists). GPT-5.5 full design in [[sess62-PROVEN-ROOT-4way-logical-block0-split-divergent-extent-map]] (publish-before-release + full-extent-rebuild-on-acquire + epoch-gated skip). The single most-promising surgical fix is SERIALIZING the conversion (adopt-disk-block-format-before-convert), since the evidence shows adoption already works once a single block0 exists.

### Probes in tree (KEEP, low-flood): P62-DATAINIT-BLK0 (xfs_dir2_data.c), P62-DWR-N1F1 (xfs_dir2_data.c write verify), P62-REL-DIREXT (xfs_mxfs_dlm.c release), P62-SF2BLK-CALLED (xfs_dir2_block.c). P60-LBMAP gated behind mxfs.instr. Test snapshots create-phase dmesg per round (drc_create_r${round}_rank${R}.dmesg). Repro: ./run.sh 4 tcp dir_reuse_coherency (fails ~every round). Reset: virsh destroy+start test1-4.
