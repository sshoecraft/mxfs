---
name: sess26-fua-refresh-data-only-no-shutdown-but-loss-persists-base-is-undestaged-or-plainbio
description: sess26(ccloop): FUA-refresh-destaged data-only (build 8B331267) ELIMINATES DABUF_MAP_HOLE shutdowns (leaf-refresh was the shutdown cause) but durable…
metadata:
  type: project
---

## sess26 — FUA-refresh-destaged: shutdown fixed, lost-update NOT fixed

Builds on [[sess26-CANDIDATE-FIX-fua-refresh-destaged-dir-block-lingering-bli]].

### Result chain (all clean-reboot, 8/tcp dir_reuse)
1. `dir_fua_refresh_destaged=1` LEAF+DATA (build FD17BF68): 1st run PASS 8/8; validation run-1 FAIL with **140× XFS_DABUF_MAP_HOLE shutdowns** (xfs_da_btree.c:2876). FUA-refreshing a fresh LEAF block exposes data-block offsets the STALE in-core data-fork extent map can't resolve → hole → shutdown (sess20 family).
2. `dir_fua_refresh_destaged=1` DATA/BLOCK ONLY (build 8B331267): **SHUT=0** (leaf-exclusion cured the shutdown) BUT durable lost-update PERSISTS (run-1 readdir=798 round1 lost node6_f1+node7_f1; readdir=799 round17 lost node6_f23.md5; all LOOKUP_ENOENT REREAD_MISS).

### What this proves
- The DABUF_MAP_HOLE shutdown = refreshing LEAF blocks against a stale extent map. DATA-only refresh is shutdown-safe.
- The data-block lost-update is NOT cured by FUA-refreshing DESTAGED data blocks → the stale base at the clobber is NOT a destaged-lingering-BLI block. It is EITHER:
  (a) **in-AIL-UNDESTAGED** (b_mxfs_logged_seq != b_mxfs_written_seq): this node already added its OWN un-checkpointed entry onto a stale base, so the block now has un-checkpointed work AND is missing the peer's entry — my destaged-gate (and every safe evict) correctly REFUSES to refresh it (can't discard un-checkpointed work). Too late: the stale read happened BEFORE the first modify.
  (b) served by a **PLAIN BIO** (cache-miss or _XBF_FUA_FRESH set) that reads SCST's per-initiator STALE READ CACHE, never entering mxfs_buf_read_fua at all.

### REFINED NEXT HYPOTHESIS (next session, RULE-4)
The stale base is read BEFORE the first un-checkpointed modify of the tenure. The modify-evict clears XBF_DONE+_XBF_FUA_FRESH, but the subsequent addname base read either (i) is a plain bio that serves SCST stale read cache (FUA never invoked), or (ii) the block is genuinely undestaged. TEST: instrument the addname base read — for the storm dir, log whether the read after modify-evict goes FUA vs plain-bio, and compare the read content's entry-set vs a raw mxfs_pal_scsi_read_fua_bdev of the same daddr (is the peer's entry present on the LUN but absent from what addname got?). If plain-bio-stale: force the FIRST post-evict data-block read of a tenure to FUA (clear _XBF_FUA_FRESH already done; ensure mxfs_buf_needs_fua_read fires — check its gating). If undestaged: the stale base predates the tenure's first modify → must FUA-refresh at modify_refresh BEFORE addname (the evict point), not lazily at read.

### Tree
Build 8B331267 = keeper + 5 gated default-0 levers (dir_newtenure_evict, dir_modify_target_flush, dir_fua_refresh_destaged [now DATA-only], i_dlm_dir_evict_mep field). All default 0 == KEEPER, no regression, 1/2/4 unaffected (gated branch inert). Validation harness: tests/tcp/drc_catch_loss.sh N "MODARGS" (reboots+runs until FAIL, captures fail dmesg). [[sess26-target-flush-refuted-clobber-is-xfsaild-push-of-invalidated-buffer]]
