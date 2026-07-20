---
name: sess27-CONFIRMED-residual-is-dir-extent-map-revert-not-dirent-content-loss
description: sess27(ccloop) CONFIRMED via fresh round-13 capture (drc_catch2.sh): the dir_reuse 8/tcp residual is a DIR EXTENT-MAP/SIZE REVERT during concurrent g…
metadata:
  type: project
---

## sess27 — the dir_reuse 8/tcp residual is a dir EXTENT-MAP REVERT (whole-block loss), not single-entry

Build 965BDBD3, config `dir_gen_per_handoff=1 dir_modify_extent_adopt=1` (deployed). drc_catch2.sh (new, captures the ACTUAL fail round's dmesg from all 8 nodes — the old drc_catch_loss.sh grabbed the stale round-1 .dmesg). Runs 1,2 PASS; run 3 FAIL @ round 13.

### KEY CORRECTION: the "readdir=799 single-entry" was a LIE (stale-file artifact)
`/root/drc_failrounds.txt` is on the persistent root disk and is NEVER cleared at run start, so `head -1` returns a PRIOR session's round-13 799 line. The ACTUAL run-3 failure (from the fresh dmesg RDMISS) is **readdir=728** — ~72 of node3's entries missing (≈ ONE whole dir DATA block), durable (LOOKUP_ENOENT + REREAD_MISS) and AGREED by 6 nodes (1,2,4,5,6,8). Different nodes' failrounds disagree (799 vs 728) only because of the stale-file contamination. Fix any future harness to clear /root/drc_failrounds.txt + drc_*.dmesg at run start, and read the RDMISS from the fresh dmesg, not failrounds.txt head.

### PROVEN mechanism (RULE 4, round-13 window t=221..231s, ino=131):
- **NO read-staleness probe fires** in the create window: DIR-STALE-SKIP=0, P60-GENMATCH-STALE=0 (the P60s in the dmesg are at t=33s, early rounds — cumulative dmesg noise), P63-FASTEX=0, P133-INAIL=0, P106-STALE-EX=0, P-DOUBLEGRANT=0, P-STALEMASTER=0. So it is NOT the classic read-side stale-RMW that 26 sessions chased.
- **P62-RELOAD-FORK-SHRINK** + **P26-DSCAN-MISS**: node4 creates node4_f1/f2, then on a handoff reacquire reloads the disk (post_release=1) and its OWN entries are "not in any data block" — the disk image it adopts is missing them. node8 same pattern.
- **P32-IFLUSH-NXSHRINK** fires (incore_nx < disk_nx, "write SMALLER dir extent map over larger on-disk one") — but those were comm=rm/dlm_mode=EX (rank1's legit rm-rf shrink), so not directly the bug.
- Net: the dir inode's data-fork extent map / di_size REVERTS during concurrent 8-node growth, orphaning whole data block(s) → the ~72 entries in them vanish on every node.

### Why dir_modify_extent_adopt(=1) doesn't fix it
It FUA-reads the disk dinode pre-modify and reloads if `disk_nx != incore_nx` — but the compare is BIDIRECTIONAL: when disk is SMALLER (a peer already reverted it), the node ADOPTS the smaller disk map and drops its own grown blocks, PROPAGATING the revert. The root reverting WRITE (an EX/NL holder flushing a stale smaller extent map over a peer-grown disk) is upstream and unfenced (P32F/P65/P67 fences all default-OFF; their epoch discriminator `cur_ep>valid_epoch` proven inert — self-shrink has valid==cur).

### Per-round handoff count (round 13): each node did ~3-5 dir EX handoffs (P63-HANDOFF ino=131), ~30 total across 8 nodes in the ~7s create phase. inode_mht_ms=300, dir_sf_mht_ms=100 (dir is node-format → uses 300).

### NEXT (sess28): decisive instrumented run with mxfs.dirwr=1 to capture the EXACT reverting write (P-DIRIFLUSH/P-WRACT show every dir-inode flush w/ extent map + dlm_mode). Identify: which node, EX or NL, flushes the smaller extent map that orphans the block. Then fence THAT write (a flush whose extent map is a strict SUBSET of disk for the same incarnation, while a concurrent grower exists) — NOT a bidirectional adopt. Capture dir: tests/tcp/loss_cap2/. See [[sess26-BREAKTHROUGH-genperhandoff-plus-extentadopt-fixes-wholeblock-and-hole-residual-single-entry]].
