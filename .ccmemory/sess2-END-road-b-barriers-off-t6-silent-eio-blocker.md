---
name: sess2-END-road-b-barriers-off-t6-silent-eio-blocker
description: sess2 END (build 391F2F21, barriers OFF): B5-iunlink-leak FIXED+verified; barriers-on pace floor proven structural (14.5ms/unlink) → Road B. Blocker:…
metadata:
  type: project
---

# sess2 (ccloop a9a03929) END — Road B locked in; two open barrier-off families

READ WITH [[sess1-END-barriers-off-pace-solved-iunlink-shutdown-blocker]].

## HEAD = build `391F2F2155F3C0D2D6C4D5C` (in tree; VMs last ran it in run60/61)
All changes IN TREE this session:
1. **B5-leak FIX (VERIFIED, KEEP)** — xfs_inode.c xfs_inactive ~2989: on -EDEADLK from the one-shot EX, inline P60-style demote (`i_dlm_demoter=current; mxfs_dlm_bast_process(ip)`) then re-acquire. run49: P2I×7 all rc=0, P2L-INACT-LEAK=0, INACT-SKIP-STALE=0 (run48 had 5 leaks → the r7 shutdown). Probes: P2I ungated, P2L ungated, P82-REM (inode_util.c, mirrors P82-ADD).
2. **dirop_durable_tcp default 0** (xfs_mxfs_dlm.c ~340) — Road B final: barriers-ON pace floor is STRUCTURAL: P137-IFREE ~10-15ms/unlink (force+drain+flush per inactivation), P128-INACT-EXREL deltas 14.5ms, P138 file-bast 10-13ms → best 21.2s/rd vs <20 needed (480/24). run48 with barriers off: 8-14s/rd. DO NOT flip back; fix release-path holes instead.
3. mxfs_reg_clean_release_fast (default 1): skip 2 release flushes for provably-clean REG (P138 stage b 9.2ms + d 2.8ms → file-bast 13.3→10.7ms). EXONERATED for run61 failure (ran with =0).
4. mxfs_leafprobe (default 1): P2R-LEAFR/P2W-LEAFW leaf provenance in xfs_dir2_leaf.c verifiers + P2U-LEAF-USEBLK anomaly probe (fires when bests steer past disize). EXONERATED (ran =0 in run61).
5. **noatime** (pal/linux/xfs_super.c fill_super: `sb->s_flags |= SB_NOATIME`) — UNVERIFIED SUSPECT for run60/61 regression (timing mask-removal).
6. **stale-BAST recycle reset** (xfs_icache.c xfs_iget_recycle: clear i_dlm_bast_pending + BAST→NONE/CACHED) — did NOT fix the create-wave drains (reuse path is CACHE-HIT `P128-REARM-UNPUB`, not iget_recycle!) — UNVERIFIED SUSPECT.
7. Probes: P2G-LOGWHO (xfs_trans_inode.c, ratelimited, names who logs REG inodes), P2D-DRAINWHY (drain loop, why it waits), P138 stage split sa/sb/b1/b2/sc/sd/su + clean=.
8. coord.sh barrier dedupe (distinct-topic count + repoll fallback) — the "overlap" that motivated it was a CROSS-NODE DMESG CLOCK misread (boot-relative!); fix harmless, keep. Cross-node timing MUST use realns= fields.

## Failure state (runs 60/61, barriers off, drc 8/tcp)
- **PRIMARY ONSET (run61): t6 round-5 SILENT `DLM inode reload imap_to_bp failed rc=-5` SWEEPS** — consecutive inos in agno 29 (62916492+) and agno 31 (65011842+), persisting forever (143s→419s). NO "Metadata corruption" print on t6, NO block-layer I/O error → the -EIO is generated INSIDE the read path (NOT verifier-with-print, NOT bio). Other nodes read the same inos fine (likely icache hits). t6 then diverged: stat($D) empty from r5 (drc-DIRID dirino=), all lookups ENOENT (drc-CLASS), ghost creates → EIO storm (Structure needs cleaning) → cluster-wide wipe.
- **SECONDARY (both runs): round-8 ALL-node `xfs_dir3_block_verify` fail daddr 0x48** — platter block has XDD3 (multi-block data fmt) content while readers expect XDB3 (single-block fmt) = dinode-fork vs dir-block-content FORMAT TEAR at block↔leaf transition (sess135 family: check P119-NONEX-FLUSH-SKIP in logs). run49's MAP_HOLE (leaf bests bestcount=2 vs disize=4096) = same tear family, other direction.
- imap is ino-number-derived (im_blkno can't go stale) — REFUTED my stale-imap theory.
- run48 (24 rounds, only iunlink fail) vs run60/61: delta = noatime + recycle-reset + B5 + probes... OR run48 was a lucky sample. Also VERIFY-phase reads: relatime was firing per-file atime→CORE txns (P2D fields=0x1 family); noatime removed them (timing shift everywhere).

## NEXT SESSION
1. **Find the silent -EIO source** (RULE 4): instrument the reload retry loop (xfs_mxfs_dlm.c ~12225) to print bp/b_error/b_flags/DONE + whether xfs_imap_to_bp cache-hit or disk-read; also check mxfs FUA-read wrapper (mxfs_pal_scsi_read_fua_bdev / mxfs_buf_read_fua) error paths that return -EIO without logging. Candidate: sticky b_error on a cached buffer, or FUA-read path failure on t6 only.
2. Bisect the regression vs run48: rebuild with noatime REVERTED + recycle-reset REVERTED (keep B5+probes) → run. If clean ×2 → re-add one at a time. If still failing → run48 was luck; instrument the tear (P119-NONEX / leafprobe=1 + the P2R/P2W history on daddr 0x48's owner).
3. Then: the dir format tear root-fix (dinode+dirblock must destage ATOMICALLY-enough at handoff — likely extend sess135 RELFLUSH to cover the block→leaf grow window; the P2W/P2R provenance will show whose write carried XDD3 without the fork).
4. Ladder unchanged: 8/tcp drc 24rds clean ×5 → 4/2/1 → full `./run.sh N tcp` N∈{1,2,4,8} → YES.

## Infra notes
- MXFS_EXTRA_MODARGS='param=val param2=val' works via run.sh prep (verified /sys/module/mxfs/parameters/).
- Cross-node dmesg clocks are boot-relative — NEVER compare raw [ts] across nodes; use realns=.
- Run artifacts: scratchpad/run49..61 dmesg per node; /tmp/run_dir_reuse_coherency_<RUNID>/ = per-node test stdout (survives run.sh cleanup).
- Budget: test-internal 480s for 8/tcp drc; run wrapper `timeout -k 10 585`.
- P2G-LOGWHO showed verify-phase relatime atime→CORE logging was the AIL-dirt source pre-noatime; with noatime the drain waits during CREATE waves remain (fresh-create dirt + stale-BAST cache-hit reuse path P128-REARM-UNPUB → P15-REL-ABORT → re-arm → drain).
