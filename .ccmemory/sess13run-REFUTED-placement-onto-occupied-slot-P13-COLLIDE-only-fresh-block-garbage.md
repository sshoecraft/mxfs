---
name: sess13run-REFUTED-placement-onto-occupied-slot-P13-COLLIDE-only-fresh-block-garbage
description: sess13(ccloop) REFUTED the placement-onto-occupied-disk-slot hypothesis: P13-COLLIDE (coherent disk-compare at xfs_dir2_data_log_entry, build 0FDF09D…
metadata:
  type: project
---

## sess13 (ccloop) — placement-onto-occupied-slot REFUTED by direct collision probe

### Probe (build 0FDF09D0): P13-COLLIDE in xfs_dir2_data_log_entry
At each dirent placement in the storm dir, a COHERENT plain-bdev read of the block checks if the target byte offset already holds a DIFFERENT non-free dirent ON DISK (the exact double-allocation signature). Safe in-transaction (plain-bdev temp, no xfs_buf_incore).

### RESULT: REFUTES the cross-node double-placement hypothesis
- Fired only 0-2x/node (test3=0). This round lost 26 entries (374/400) — the probe did NOT fire for ~24 of them. So the losses are NOT "placing onto a peer's durable entry."
- EVERY P13-COLLIDE was at **off=64** (the FIRST entry slot, right after the 64-byte dir3 data header) with GARBAGE disk content (e.g. our=[node1_f16] disk=[\x93\x9d\xd8{...]; our=[node4_f44] disk=[binary]). off=64 + garbage = a FRESHLY-ALLOCATED data block whose empty in-core header is not yet durable, so the disk still holds OLD garbage from that daddr's prior life (the dir free/realloc reuse). = a FALSE POSITIVE of the probe (placing into a fresh block, disk image stale-garbage), NOT a real peer-entry overwrite.

### CONVERGENCE with sess11run FINAL: the loss is the entry vanishing from ITS OWN block
No node places onto a peer's existing durable dirent (P13-COLLIDE clean of real names). So the dirent is NOT overwritten by a peer at the same offset. Combined with sess11run FINAL (entry logged rval=0 then absent from its block at durable_signal, single thread, ILOCK held, no evict): the entry DISAPPEARS FROM ITS OWN DATA BLOCK between placement and durability — an in-transaction / commit-path / fresh-block-durability loss, NOT a cross-node free-slot collision. The sess11run "two nodes same (daddr,off)" (DIRECTIONALITY memory) may have been the SAME daddr REUSED across the free/realloc cycle (different dir incarnations), not a true concurrent double-write.

### NEXT (redirect): chase the entry vanishing from its own block. Candidates:
1. FRESH dir-data-block init durability: a node grows the dir (new data block at a reused daddr), writes its empty header + entry in-core, but the block's on-disk image is never made durable as a valid empty-then-populated block before a coherent (FUA) read/reload re-reads it → the read gets the OLD garbage (or an intermediate) → the just-added entry (and the fresh header) are lost. P13-COLLIDE's garbage-at-off=64 is direct evidence the disk image of these new blocks is stale-garbage. CHECK: does the dir-block-init (xfs_dir3_data_init / the new-block path) + its durability reach the platter before any FUA reload? Is the fresh block's daddr's OLD cached buffer (from its prior life as a different block) invalidated cluster-wide on realloc (ABA daddr reuse — sess36/40 family)?
2. In-transaction freescan/compaction reusing the region (sess11run candidate b).

### Build 0FDF09D0 (P13-COLLIDE + P13-NADD probes, always-on but storm-dir-scoped; plus prior off-by-default levers). dir_reuse 4/tcp still 399-374/400. Criterion NOT met. See [[sess13run-CORRECTION-dir-is-LEAF-format-probe-belongs-in-data_log_entry-loss-varies]] [[sess11run-FINAL-entry-vanishes-in-addname-to-commit-window-not-split-not-evict]].</body>
</invoke>
