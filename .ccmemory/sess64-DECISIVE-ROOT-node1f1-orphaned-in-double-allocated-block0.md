---
name: sess64-DECISIVE-ROOT-node1f1-orphaned-in-double-allocated-block0
description: sess64 DECISIVE ROOT (P64-N1F1 trace): node1_f1 is durably written to daddr=120 but ORPHANED — the dir's logical block0 winning on disk is a DIFFEREN…
metadata:
  type: project
---

## sess64 — DECISIVE ROOT of node1_f1 loss (and the coupled bnobt corruption): dir logical-block0 DOUBLE-ALLOCATION

### The proving trace (P64-N1F1, build F20F3CAC, RULE 4 decisive)
Added an always-on tracer in the dir DATA/BLOCK buffer WRITE path (pal/linux/xfs_buf.c, after P-DIRWR) that scans each written dir block for the EXACT dirent byte pattern `\x08node1_f1` (namelen=8 + name; uniquely excludes node1_f10-19 namelen=9 and node1_f1.md5 namelen=12) and logs owner+daddr+present+comm, capped 6000 (survives the ring, unlike dirwr=2 firehose).

Round 18 (dir ino 131, all peers miss node1_f1), distinct daddrs written for owner=131:
- **daddr=120: present=1** (49 writes, comm=dd/xfsaild) — node1_f1 IS durably written here by rank1.
- **daddr=2093296: present=0** (194 writes), 2093304 p=0 (26), 4186520 p=0 (64), 6279744/6279760 p=0 — node1_f1 ABSENT.

=> node1_f1 is DURABLE, but in daddr=120. The dir's logical block0 that the PEERS all write their entries into (and that the cold-read verify sees) is a DIFFERENT physical block, **daddr=2093296**, which NEVER contained node1_f1. node1_f1 is ORPHANED in daddr=120; the winning on-disk extent map maps the dir's block0 -> 2093296.

### ROOT (definitive, supersedes the "stale-base RMW clobber" framing)
This is NOT a content RMW lost-update and NOT a shortform merge bug. It is **dir logical-block0 DOUBLE-ALLOCATION**: under the concurrent 400-create storm, two nodes independently convert the freshly-recreated shortform dir to BLOCK/LEAF format, each ALLOCATING ITS OWN physical block for logical block0 (rank1 -> daddr=120 with node1_f1; a peer -> daddr=2093296). The peer's extent map wins on disk; rank1's block0 (daddr=120, holding node1_f1) is orphaned/leaked. This is the sess15/sess62 "logical-block0 split / extent[0] flip-flop / concurrent sf->block double-alloc" — now PROVEN at the byte level.
- It also explains the coupled **bnobt double-free** corruption (sess64): rm-rf (or an extent-map adopt) frees BOTH block0 allocations -> `bno+len>gtbno xfs_free_ag_extent`. And why the epoch disk-superset adopt corrupts (it rebuilds the extent map onto the divergent/orphaned block set).

### THE FIX DIRECTION (next session)
Prevent/reconcile the dir-block0 double-allocation. The sf->block conversion (xfs_dir2_sf_to_block) + first dir-block alloc must be COHERENT across nodes: a node about to convert/allocate block0 must first observe whether a peer ALREADY converted (disk is already block-format with block0 allocated at some daddr) and ADOPT that existing block0 (extent map + content incl node1_f1) instead of allocating a new physical block. The `dir_adopt_block` module param (default ON, "adopt peer block-format layout at modify pre-lock when in-core shortform but disk block") is supposed to do this but evidently does NOT prevent the race — investigate why (it likely runs pre-lock/racy, or only on a format gap it mis-detects when BOTH have converted to block with different block0 daddrs). The reliable serialization point is the EX-acquire reload: on a post_release acquire where disk is BLOCK and in-core is SHORTFORM (or in-core block0 daddr != disk block0 daddr), adopt the disk extent map's block0 daddr — but do it WITHOUT the bnobt-corrupting free (the orphan must be reconciled, not double-freed). The monotonic EPOCH (sess64 plumbing, build-in) is the reliable signal for "a peer converted since our base".

### Build: F20F3CAC = baseline + epoch plumbing (observe-only adopt) + P64-N1F1 tracer (KEEP — capped, the key diagnostic). Epoch adopt still DISABLED. 2/tcp coherence PASS. See [[sess64-node1f1-is-blockformat-not-shortform-refutes-sess62]] [[sess62-REFINED-block0-split-extent0-flipflop-orphans-node1f1]] [[sess15-ROOT-concurrent-sf-to-block-conversion-double-alloc]].</body>
