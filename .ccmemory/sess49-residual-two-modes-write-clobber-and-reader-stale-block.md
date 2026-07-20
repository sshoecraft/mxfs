---
name: sess49-residual-two-modes-write-clobber-and-reader-stale-block
description: sess49(ccloop): 8/tcp dir_reuse residual (epoch_adopt=0, no shutdown) has TWO modes: (1) write clobber lookup_fail>0 (run49d node1_f1..f26); (2) read…
metadata:
  type: project
---

## sess49 (ccloop 4cb2d0a2) — the epoch_adopt=0 residual is TWO independent flaky modes

### epoch_adopt=0 (build 3B0EB406) 8-node dir_reuse data so far: 1 PASS (run49c) / 3 FAIL (run49d, sweep-r1, +). NO shutdowns in any FAIL. ~25-50% pass.

### TWO FAILURE MODES (both durable, all-nodes-agree, flaky in WHICH round):
1. **WRITE CLOBBER** (run49d): lookup_fail=708, missing node1_f1..f26 (first data block). Leaf+data both lost. A node RMWs/flushes a stale base block-0, durably overwriting node1's first-wave dirents. EARLY rounds (1-3).
2. **READER STALE BLOCK** (sweep-r1): lookup_fail=0, readdir=751→701 (cumulative short), missing=[]. Entries EXIST (lookup OK) but readdir enumerates a STALE cached data block missing peer entries. LATE rounds (15-18). The gen-invalidation (b_mxfs_dir_gen<i_dlm_dir_gen) / readdir want_block_refresh not firing reliably for that block.

### KEY: epoch_adopt only affected DIRTY/EX nodes (genuine_handoff bypassed the P33/P43 shrink guards → shrink-adopt corruption → shutdown). CLEAN/PR readers were UNAFFECTED by epoch_adopt (guards don't fire for them). So BOTH residual modes are INDEPENDENT of epoch_adopt; epoch_adopt=0 just removed the corruption-shutdown. The refined "adopt-grow-keep-shrink" guard idea is EQUIVALENT to epoch_adopt=0 (guards already only fire on shrink) → won't help.

### REFUTED (don't retry): dirskip=1 / dataclobber=2 write-side enforce skip → CATASTROPHIC (readdir=0/400 empty dir, sess69). epoch_adopt=1 → shutdown.

### NEXT (RULE 4): fresh mechanism capture (tests/drc_capture_clobber.sh — greps P62-DATAINIT-BLK0 cached_has_n1f1, P31E, P32B-DOUBLEMAP, P13-COLLIDE, P40-INCARN-ABA-DIRSKIP, P49-STALEBASE on a FAILING run, saved to tests/_clobber_cap/). Discriminate: mode-1 = data_init-zeroes vs slot-collision vs ABA-flush; mode-2 = which gen-invalidation path misses. Then targeted fix per proven mechanism. If own fix fails → RULE-5 GPT consult (130-session core, proven diagnosis, param space + enforce-skips exhausted/refuted, architectural release-drain-vs-leaf-tear knot).

See [[sess49-residual-after-epochadopt0-is-node1-firstblock-durable-clobber]] [[sess49-BREAKTHROUGH-epoch-adopt-0-fixes-8node-shutdown]].
</body>
</invoke>
