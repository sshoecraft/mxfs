---
name: sess41-FIX-chokepoint-disambiguated-dir-merge
description: sess41 FIX (build 8AEDFD25, default-on dir_choke_merge=1): carry release-path drain-merge removed-set disambiguation to the UNIVERSAL dir-data write…
metadata:
  type: project
---

## sess41 (ccloop 4cb2d0a2) — FIX for dir_reuse readdir=799. Build `8AEDFD25598AAB942139206` (= B17141DA + this). Default-on `mxfs.dir_choke_merge=1`. UNDER VALIDATION (drc_cap8 6-iter).

### Reproduced first (RULE 4): drc_cap8 with `dataclobber=1 dir_relverify=1 dirwr=1` → iter1 round 14 CLEAN 799 (all 8 nodes agree readdir=799, missing `node3_f46.md5`, LOOKUP_ENOENT REREAD_MISS, durable, NO flap). Matches sess40 PROVEN diag. (Later rounds 23/24 lost 17/100 entries = dirwr-flood RULE-0 slowdown → flap mode, an artifact of the heavy logging; round 14 is the real bug.) dataclobber-skip (enforce=1) FIRED heavily during `rm` (count-based, disk superset) but did NOT prevent the 799 — confirming the loss is COUNT-PRESERVING content-divergent (one entry swapped, count equal → count-based detector blind). Clobbering writes are `mode=5` (EX-held, in-tenure, comm=rm/dd/bash).

### Root mechanism (sess40 PROVEN + sess41 confirm): a node RMWs a STALE dir-data base lacking a peer's just-committed+durable dirent and writes it back, durably dropping that entry. All existing guards blind: count-based dataclobber (count preserved), NL/ABA dirskip (write is EX-held), release-fence data_durable (block looks durable).

### The fix — extend the proven-safe merge to ALL dir-data writes
There were already TWO content merges, both insufficient:
1. `mxfs_dir3_data_writemerge` (pal/linux/xfs_buf.c:2231, gated `dir_write_merge` default 0) — UNIVERSAL chokepoint (xfs_buf_submit:3994, BEFORE CRC, covers async xfsaild AND release) but REFUTED: over-grafts → 803 (resurrects our own removes; only had a weak `ourx>0` heuristic).
2. `mxfs_dir3_data_drain_merge` (xfs_buf.c:2419, gated `dir_drain_merge` default 0) — PRECISE (removed-set gated, `mxfs_dir_was_removed`) but ONLY on the RELEASE path (mxfs_dir_flush_one_daddr); the async xfsaild destage clobber BYPASSES it.

FIX: give the UNIVERSAL writemerge the PRECISE removed-set disambiguation. New helper `mxfs_dir_choke_merge_remset(bp,...)` (xfs_mxfs_dlm.c, after mxfs_dir_remset_valid) resolves owner dir inode (radix under pag_ici_lock + NON-BLOCKING down_read_trylock(&ip->i_lock) — excludes ILOCK_EXCL remove-set writer mxfs_dir_record_removed, no UAF/torn read, no deadlock vs buffer-locked caller), and IF dir is EX-held by us (i_dlm_mode==MXFS_LOCK_EX=5) + incarn matches + remset valid → snapshots removed-set (cap 256; over-cap=skip). writemerge then: (a) drops the `ourx==0` early-out when disamb (catches the pure-stale-base subset clobber too), (b) at graft, skips any disk-only dirent whose inumber IS in the removed snapshot (= our remove, don't resurrect). Lossless union, removed-set-precise. Default-on; kill-switch `dir_choke_merge=0`. DATA blocks only (readdir=799 is a DATA-block loss; leaf separate). Probe `P-WMERGE2 ... disamb=N remn=N` (ratelimited, always-on).

### Why correct for dir_reuse: during the CREATE phase (where 799 happens) NO node removes → removed-set empty → graft ALL peer disk-only adds (fully lossless). During rm phase removed-set populated → removes preserved (was the over-graft bug).

### VALIDATE: drc_cap8 6-iter (production speed, no dirwr flood). If 6/6 → re-verify 1/2/4 tcp full + 8 tcp full before criterion. If still loses: check P-WMERGE2 fired (disamb=1); if disamb=0 at the loss, the clobbering write was NOT EX-held/remset-valid (widen) OR the loss is via leaf block (extend to dc_leaf). Supersedes the no-op [[sess40-FIX-dir-writeback-completion-barrier-readdir799]]. See [[sess40-PROVEN-799-is-release-drain-gap-async-writeback-overlap]].
