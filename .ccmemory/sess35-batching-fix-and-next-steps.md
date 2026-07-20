---
name: sess35-batching-fix-and-next-steps
description: sess35 build 68B7C405: added MHT batching to the ACQUIRING-BAST honor (GPT item 3) — validation running at relay. Next: measure create-time drop; the…
metadata:
  type: project
---

## sess35 end-state — builds, fixes landed, and the exact next steps

### BUILD CHAIN (all KEEP unless noted): current = **68B7C405**.
- A970F10B = root fix: dedicated `i_dlm_bast_during_acq` flag (honor a BAST deferred during
  ISTATE_ACQUIRING at slow-path post-publish, surviving reload's clearing of i_dlm_stale). PROVEN
  to eliminate the 6s handoff (P34-ACQ-SLOW 5-7→0; P35-ACQBAST-HONOR fires). See
  [[sess35-PROVEN-root-dir6s-is-missing-postgrant-bast-on-upgrade]].
- 68B7C405 = A970F10B + **MHT BATCHING** (GPT plan item 3): at post-publish, when honoring an
  ACQUIRING-deferred BAST on a FRESH EX **dir** grant, keep state CACHED + set i_dlm_bast_pending +
  arm i_dlm_bast_dwork (batch_arm) for the remaining mxfs_inode_mht_ms window instead of releasing
  after ONE op. Logs `P35-ACQBAST-BATCH`. WHY: A970F10B removed the 6s stall but also removed the
  (accidental) batching → per-create dir-EX ping-pong (~65ms/op × 100 = ~6.5s create phase, still
  ~16s/round → 300s TEST_TIMEOUT). Batching lets the create burst fast-path within the bounded
  window (AG affinity makes inode alloc uncontended). Coherency-safe (DLM gates peer; release drain
  unchanged); starvation bounded by MHT. Edits all in xfs_mxfs_dlm.c post-publish (~8888-8995) +
  struct field in xfs_inode.h. Also still carries dlm.c collect_grantee_bast_if_waiters post-grant
  BAST (harmless, fires ~rarely) + P34/P35/P36/P37 always-on traces (consider trimming P36/P37 to
  cut log spam — the dmesg ring WRAPS on a 24-round run).

### VALIDATION IN PROGRESS AT RELAY: tests/drc_run_capture.sh on 68B7C405 (writes full per-node
dmesg to /tmp/drc_full.log — the stdin-detach bug is FIXED: setsid + </dev/null). Check when done:
per-round DRCph create-phase duration (target: 6.5s→~1s) via the markers; P35-ACQBAST-BATCH count;
ensure NO new shutdown/correctness regression.

### REMAINING BLOCKERS for 2/tcp 100% (BOTH must pass; test currently FAIL=timeout+correctness):
1. **VERIFY slowness ~8.4s/round** (test2): 200 lookups after `drop_caches` = ~42ms/op cold FUA
   inode reads. ~200 files pack into ~8 inode clusters, so cluster-read amortization SHOULD give ~8
   FUA reads (~300ms) — but the **sess38 fix (invalidate the inode-cluster buffer on EVERY
   multi-node cache-miss iget, xfs_icache.c xfs_iget_cache_miss)** forces a FUA per iget, defeating
   amortization. FIX DIRECTION: invalidate once-per-cluster-per-grant-epoch, not per-iget (careful:
   sess38 fixed a real create-race coherency bug — don't fully revert). FUA gate: pal/linux/xfs_buf.c
   ~3929 (`!_XBF_FUA_FRESH`). Target cluster is SCST (FUA works); each FUA ~42ms.
2. **CORRECTNESS: P26-DSCAN-MISS scanned~120/200** = reader UNDER-READS the shared dir (acquire-side
   stale dir-block RMW). xfs_da_read_buf XBF_TRYLOCK-skip serves stale (xfs_da_btree.c ~3101, gated
   on !owned_ex). GPT plan item 6 = invalidate the WHOLE dir data fork at the DLM-acquire boundary
   (blocking-safe, before any RMW) instead of the lazy read-time TRYLOCK hook.

### RUN RECIPE: `bash tests/drc_run_capture.sh` (full dmesg, no wrap) OR `./run.sh 2 tcp
dir_reuse_coherency` (timeout 450). reset2.sh only if a node wedges. Per-round phase timing from
`dmesg|grep mxfs-DRCph` (create-start→create-done→verify-done→rm-done). Marker NOT written.
[[sess35-fix-result-and-residual-asymmetric-slowness]]</body>
