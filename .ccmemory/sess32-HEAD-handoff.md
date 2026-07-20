---
name: sess32-HEAD-handoff
description: sess32 HEAD: dir_reuse loss is WITHIN-tenure (held EX at destage); RMW base always fresh (POSTRMW=0); leading hypothesis = duplicate/ghost xfs_buf pe…
metadata:
  type: project
---

## sess32 HEAD — read first

### STATE
- **1/2/4 tcp = 100%; 8/tcp blocked ONLY by the rare dir_reuse single-dirent loss (readdir 799/800).** CRITERIA NOT MET.
- On-disk build **06F56794** = keeper 37A37B10 + sess32 changes, ALL INERT at default (dir_stale_reconcile=0, dir_tenure_evict=0, dir_postrmw_probe=0). Reboot → keeper-equivalent. Probes: `dir_postrmw_probe=1`+`dir_writeprobe=1`+`dirwr=1` enable diagnostics (P-POSTRMW-BP, P-WMERGE, P-POSTRMW). NOTE the heavy probe perturbs timing (amplifies loss 799→786).

### PROVEN this session (RULE 4 + GPT-5.5 ×2)
1. **NOT mechanism A (stale RMW base).** POST-RMW probe (right after xfs_dir_create_child) shows the in-core block is ALWAYS a superset of disk (disk_extra=0) on a LOSING iter, all 8 nodes. The RMW base is fresh.
2. **The clobber is WITHIN an EX tenure, not post-release.** P-WMERGE at the destage shows `held_mode=5(EX)` (real DLM rawmode, sess69) + in_ail=1 + disk_extra=1. The release fence (xfs_mxfs_dlm.c ~L7857) already loops on `data_durable` (requires NO in-AIL dir blocks) before unlock, so no in-AIL block survives a handoff → mechanism A can't occur.
3. **LEADING HYPOTHESIS = duplicate/ghost xfs_buf per dir daddr (mechanism B, GPT consult #2 Q3).** P-POSTRMW-BP logged **8 DIFFERENT bp pointers for the SAME daddr (12559416) in ~100ms** (one per create), all done=1 disk_extra=0 lseq=0 wseq=0. Interpretation: a stale prior buffer INSTANCE (ghost) for the daddr is destaged by xfsaild while we hold EX on a FRESH instance → reverts the peer's add. **CAVEAT: could be a probe artifact (heavy per-create scan) — MUST confirm cleanly first.**

### REFUTED with evidence (do NOT retry): read-side/acquire refresh; EX-side epoch reval (798 regression via keep-guard bypass); create-time reconcile/dir_merge; ALL param tuning (full proven config still loses); destage byte-graft (bnobt corruption); suppress (relocates loss).

### NEXT SESSION (RULE 4)
1. **Confirm the duplicate-buffer finding CLEANLY** (the current probe perturbs): add a LIGHT probe — at the xfsaild dir-DATA write chokepoint (pal/linux/xfs_buf.c P-WMERGE site), when MERGE-NEEDED fires, call `xfs_buf_incore(daddr)` and compare to the `bp` being written; if DIFFERENT → ghost confirmed (the canonical cached buffer != the one being destaged). Log P-WGHOST. This is decisive and low-perturbation.
2. **If ghost confirmed:** find the churn/stale source — instrument xfs_buf alloc/free/stale for dir daddrs (a logged buffer removed from the rhashtable while still AIL-referenced spawns the ghost). Candidate sources: xfs_buf LRU reclaim, an mxfs invalidate that calls xfs_buf_stale (the acquire-evict clears XBF_DONE only — comment at L6327 says it must NOT stale; verify nothing else does), or freed+realloc of the dir block. FIX = ensure single canonical buffer per dir daddr (don't stale logged buffers) OR at the dir-write chokepoint skip a non-canonical (ghost) buffer write.
3. **If NOT a ghost (same bp, content reverted):** something memcpy's stale disk into b_addr mid-tenure (a re-read serving stale). Check the read path under owned_ex.
4. Whatever the source, GPT's release-side AIL-retire is a backstop ONLY if the stale instance is AIL-referenced; a pure ghost needs the buffer-identity fix.

### REPRO: `bash tests/tcp/drc_repro_loop.sh 6 "dir_writeprobe=1 dirwr=1" 24` (loss ~1/2, readdir 799; add dir_postrmw_probe=1 for P-POSTRMW-BP). 
### Code locations: P-WMERGE detector pal/linux/xfs_buf.c ~L2389-2443 (now logs bp/lseq/wseq/pin); POST-RMW probe xfs/xfs_mxfs_dlm.c mxfs_dir_postrmw_probe (~L5723) called from xfs_inode.c after xfs_dir_create_child; mxfs_dir3_disk_has_extra_inum now NON-static (pal/linux/xfs_buf.c). [[sess32-mechanismB-duplicate-dir-buffers-per-daddr]] [[sess32-DECISIVE-A-vs-B-late-destage-toctou]] [[sess31-HEAD-handoff]]
</body>
