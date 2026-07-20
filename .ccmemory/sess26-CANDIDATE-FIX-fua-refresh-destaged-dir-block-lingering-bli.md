---
name: sess26-CANDIDATE-FIX-fua-refresh-destaged-dir-block-lingering-bli
description: sess26(ccloop) CANDIDATE FIX (build FD17BF68, dir_fua_refresh_destaged=1): mxfs_buf_read_fua P91-skip kept a DESTAGED (lingering-BLI) multinode dir b…
metadata:
  type: project
---

## sess26 — CANDIDATE ROOT FIX for dir_reuse_coherency 8/tcp durable lost-update

### PROVEN root (RULE 4, this session)
The clobber survives despite the modify-evict (which DOES clear XBF_DONE on the stale base) because of **`mxfs_buf_read_fua` P91-FUA-SKIP-LOGGED** (pal/linux/xfs_buf.c:2741): it skips the FUA SCSI pierce whenever `b_pin_count>0 || !list_empty(b_li_list) || b_log_item` and returns the EXISTING in-core b_addr as "authoritative". For a multi-node dir DATA/LEAF block that is **DESTAGED** (pin==0 && b_mxfs_logged_seq==b_mxfs_written_seq) the attached BLI merely LINGERS in the AIL — there is NO un-checkpointed work — yet P91 (a) serves the STALE prior-tenure RMW base a peer superseded (so the create picks a free slot the peer already used = EQUAL-count/DIFFERENT-fingerprint clobber) AND (b) keeps the stale b_addr that xfsaild later destages over the peer's dirent (sess25's EX-held in_ail=1 background clobber). This is why: evict-always-evicts (sess26 P68) yet base still stale; target SYNCHRONIZE CACHE (write cache) didn't help — the staleness is the kept-in-core buffer / SCST per-initiator READ cache, not platter lag.

### THE FIX (build FD17BF68, gated `dir_fua_refresh_destaged`, DEFAULT 0 pending validation)
In mxfs_buf_read_fua, BEFORE the P91 skip: if `dir_fua_refresh_destaged` && buffer is dir3 data/block/leaf1/leafn ops && destaged (pin==0 && logged_seq==written_seq) → `goto do_fua_read` (pierce). SAFE: a destaged buffer's content is already on the LUN, so the FUA DMA overwrite yields the same-or-newer peer-superset image, refreshing b_addr so any later xfsaild push writes FRESH not stale. pin>0 / undestaged still hard-skip (protects genuine un-checkpointed work — the sess90 bnobt lost-removal concern). ONE fix closes BOTH read-side stale base AND write-side stale destage.

### Result so far
dir_reuse_coherency 8/tcp with dir_fua_refresh_destaged=1: **PASS 8/8, 352s** (== keeper speed, no RULE-0 regression). Keeper is ~50% flaky. 6-consecutive-run validation IN FLIGHT (tests/tcp/drc_catch_loss.sh 6 "dir_fua_refresh_destaged=1"; stops on first FAIL). If 6/6 PASS → flip default to 1, verify 1/2/4 tcp full suite no-regress (FUA-refresh only fires on destaged dir blocks w/ lingering BLI, bounded), then run full `./run.sh 8 tcp`.

### Tree
Build FD17BF68 = keeper + 4 gated default-0 levers (dir_newtenure_evict, dir_modify_target_flush [both refuted], dir_fua_refresh_destaged [CANDIDATE], i_dlm_dir_evict_mep field). With all params default 0 == keeper, NO regression. Code: pal/linux/xfs_buf.c mxfs_buf_read_fua (do_fua_read label + dir-destaged exception); param in xfs/xfs_mxfs_dlm.c. [[sess26-target-flush-refuted-clobber-is-xfsaild-push-of-invalidated-buffer]] [[sess26-FINAL-root-aba-buffer-stale-bli-fua-skip-and-exact-fix]]
