---
name: sess26-subset-guard-refuted-racy-false-positive-fix-must-be-release-side
description: sess26(ccloop) FINAL: write-chokepoint dirent SUBSET guard (dir_subset_guard, real inum subset test) REFUTED — racy plain-read-vs-incore at bio submi…
metadata:
  type: project
---

## sess26 FINAL — subset-guard refuted; fix must be release-side

Builds on [[sess26-PIVOTAL-loss-is-write-side-not-read-fua-pierces-still-loses]].

### Implemented + REFUTED: write-chokepoint dirent SUBSET guard (dir_subset_guard, build CA135E9C)
Added `mxfs_dir3_disk_has_extra_inum()` (pal/linux/xfs_buf.c): real dirent subset test (does the on-disk block hold an inumber the in-core image LACKS = would drop a peer's entry). Wired into the existing dir write chokepoint: for a CLEAN (bdirty=0) in-AIL xfsaild push of a dc_data block, same-incarnation, if disk_has_extra>0 → suppress the write + mark for read-path refresh (gen=0, keep XBF_DONE like the proven P12 skip; the v1 that CLEARED XBF_DONE before xfs_buf_ioend caused a barrier-timeout abort at 110s — ioend on a write needs XBF_DONE set).
- v2 (XBF_DONE kept): ran ALL 24 rounds, no shutdown, 199s (faster than keeper) — but STILL FAIL 0/8, AND caused **readdir=0 on test5 rounds 16,18** (whole dir read empty). The guard fired 12× (test1) / 1× (test8) and SUPPRESSED LEGIT WRITES → a peer cold-read the dir empty.

### Why it fails (structural, matches sess16/sess23)
Comparing the in-core image to a plain-read of disk AT BIO-SUBMIT TIME is RACY: the disk's transient state (a peer's concurrent/in-flight write, or the peer's newer block not yet fully coherent) makes disk look like it has "extra" inums the legit in-core write doesn't — so the guard false-positive-suppresses a NEEDED write → readdir=0. This is exactly sess16's "acquire/write-side disk-compare is structurally racy — peer's newer write often not on the LUN at our compare moment; the fix belongs on the RELEASE side" and sess23's "suppression is the corruptor".

### DEFINITIVE NARROWING (this session)
- Read-side (FUA-pierce all dir DATA base reads, P26-FUAREFRESH 8000×): reads ARE fresh, loss PERSISTS → not read-side.
- Write-side async suppression (subset guard): racy false-positive → worse loss.
- => The fix is NEITHER async read NOR async write chokepoint. It MUST be the SYNCHRONOUS RELEASE FENCE (bast_process / mxfs_dir_flush_data_blocks before DLM unlock), where the node still holds EX and disk is quiescent (no peer racing).

### CONCRETE NEXT DIRECTION (release-side, for next session)
The clobber = a lingering in-AIL dir DATA BLI that xfsaild re-pushes stale AFTER the block's content was superseded. At RELEASE (EX->NL handoff), after the drain writes the block durable, the in-AIL BLI must be REMOVED/COMPLETED so xfsaild can NEVER re-push it in a later tenure. Investigate: does mxfs_dir_flush_data_blocks' xfs_bwrite actually remove the BLI from THIS node's AIL on completion? If the BLI lingers in-AIL post-release (proven: sess26 evict shows in-AIL dir blocks present at re-acquire), that lingering BLI is the re-push source. FIX candidate: at release, after draining each dir DATA block, force-complete/cancel its AIL item (xfs_buf_stale on the CLEAN drained buffer like the P126/P60 AG-meta/bmbt pattern at xfs_buf_item.c:608/638 — those xfs_buf_stale a clean superseded buffer to drop the BLI with no I/O). Apply that same "stale the clean drained dir buffer at release" so no BLI survives the handoff. GPT(sess26-old) verdict: xfs_buf_stale is safe ONLY on a clean (!dirty !in-AIL-undestaged !pinned) buffer — gate strictly.

### Tree / keeper
Build CA135E9C = keeper + gated default-0 levers: dir_newtenure_evict, dir_modify_target_flush, dir_fua_refresh_destaged (data-only), dir_subset_guard, + i_dlm_dir_evict_mep field + mxfs_dir3_disk_has_extra_inum() helper (unused at default). ALL params default 0 == KEEPER, NO regression, 1/2/4 tcp unaffected. dir_reuse 8/tcp still ~50% flaky (unsolved). [[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]] [[sess25-FIX-ail-defer-reduces-dir_reuse-loss-residual-remains]]
