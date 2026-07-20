---
name: sess49-residual-after-epochadopt0-is-node1-firstblock-durable-clobber
description: sess49(ccloop): after epoch_adopt=0 (no more shutdown), 8/tcp dir_reuse residual = FLAKY (~50%) DURABLE write-side clobber of node1's FIRST data bloc…
metadata:
  type: project
---

## sess49 (ccloop 4cb2d0a2) — the residual after epoch_adopt=0

### epoch_adopt=0 (build 3B0EB406) RESULT: FLAKY. run49c PASS 8/8 (0 loss); run49d FAIL 0/8 — NO shutdown (SHUT=0, confirmed). So epoch_adopt=0 reliably KILLS the AG-corruption shutdown, but exposes the underlying flaky lost-update.

### run49d failure forensics (ALL 8 nodes AGREE = durable on-disk loss):
- round1: readdir=758/800 (42 short), lookup_fail=0, missing=[] (count-only short)
- round3: readdir=708/800, **lookup_fail=708**, missing=**node1_f1, node1_f2, ... node1_f1.md5, node1_f10..f26** (node1's FIRST ~26 data entries + first .md5)
- CUMULATIVE (758→708 worse each round). P13-COLLIDE 0-3/node (low). DIRTYSKIP all done=0 (benign).

### DIAGNOSIS: a DURABLE write-side clobber of node1's FIRST DATA BLOCK (node1_f1..f26 zeroed/overwritten on the platter). This is the 130-session CORE write-side lost-update — same family as sess36 (xfs_dir3_data_init ZEROES a block holding live dirents node1_f1..f14) and sess27 (intra-block slot-collision RMW: a peer's addname picks node1's occupied offset on a stale base). INDEPENDENT of epoch_adopt (epoch_adopt is reload-side; this is a write clobber). The acquire/release coherency machinery (owner_scan+grant_evict+target_flush+addname_coherent, all ON) reduces but does NOT eliminate it.

### KEY: this is WRITE-SIDE + DURABLE + ALL-NODES-AGREE. Not a reader-staleness (force_coherent refuted, sess27). The node1_f1..f26 block was created durably then OVERWRITTEN durably by a later stale-base RMW or a data_init re-zero.

### NEXT MECHANISM CAPTURE (RULE 4): on a FAILING 8-node run, grep node dmesg BEFORE reboot for:
- P62-DATAINIT-BLK0 cached_has_n1f1=1 (data_init zeroing a block that holds node1_f1 = sess36 mechanism), 
- P31E-DATAINIT-ABA live_dirents>0, P32B-DOUBLEMAP (dir-block double-alloc),
- P13-COLLIDE (slot collision), P11-DATALOG (node1_f1 logged to which daddr then vanishes).
Capture to SOURCE TREE (RULE 3, survives reboot). Then target the proven mechanism.

### CANDIDATE next: if data_init-zeroes confirmed -> add the sess36 protective guard (don't init a block with live owned dirents). If slot-collision -> the GPT iflush-cluster fork-flush fence / leaf-coherence-on-modify. RULE 5 GPT consult is justified (130-session core, proven diagnosis, param space exhausted) IF own mechanism-targeted fix fails.

See [[sess49-BREAKTHROUGH-epoch-adopt-0-fixes-8node-shutdown]] [[sess36-PROVEN-datainit-zeroes-live-block0-root]] [[sess27-SMOKINGGUN-intrablock-slot-collision-off1280-node7-overwrites-node5]].
</body>
</invoke>
