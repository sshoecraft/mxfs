---
name: sess5-FIVE-ROOT-FIXES-suppression-family-and-probes
description: sess5(a9a03929): FIX-3..FIX-8 landed — P3B relsafe rwsem underflow (run74 root), bounded drain, honest wseq (dir_wseq_at_completion=1), undestaged ne…
metadata:
  type: project
---

# sess5 (ccloop a9a03929) — the write-suppression family unwound

Builds: BD1480DB (FIX-3/4) → 6DE9540D (FIX-5/6/7) → 15A8C8D6 (FUA retry) → **A9DBB70085771B2ADB3510D (FIX-8, current)**.

## FIX-3 (run74 root, PROVEN): P3B relsafe-without-hold rwsem underflow
`cnt=-510` decoded = readers −2 + waiters (bit1), writer CLEAR — NOT a leaked write hold. FIX-2's P3B loop called `mxfs_dir_flush_data_blocks_relsafe` (a lock-CONSUMING fn: up_reads every path) at xfs_mxfs_dlm.c:11149 WITHOUT the read hold; each non-clean iteration = one unmatched up_read. run74: try=0/try=1 → −2 → rwsem permanently unacquirable → next release wedged in drain 400s+ → convoy. Fixed: take mxfs_drain_ilock_read before relsafe (mirror 10212/10575 sites). wr_last=create+0x4e1 was a stale note (raw up_read skips the note hook).

## FIX-4: mxfs_drain_ilock_read bounded (180s → force shutdown, return false)
All callers treat false as "shutdown"; degrade = fence+replay, never a live convoy.

## FIX-5 (run75 root #1, PROVEN by uuid): dir_wseq_at_completion default 1
run75: round-6 grown dir block (bno=2, daddr 85824096) committed; wseq stamped at SUBMIT (param was 0!) so `mxfs_dir_buf_is_undestaged`=false at the gate; NL-window suppressors (P3W nl_released skip=1 @134.195 + P12-DIR-EXGUARD) dropped its ONLY write; emulated-clean ioend retired BLI; P3D-RELINVAL destroyed content. Platter kept a PRIOR-MKFS image (same layout every run → same daddrs; **uuid mismatch** = xfs_dir3_data_verify:327 EFSCORRUPTED(-117=EUCLEAN, NOT crc!) deterministic across remount — P54's crc_ok=1 misled b/c it doesn't check uuid). Note errno: EFSBADCRC=-74, EFSCORRUPTED=-117.
Stamp order in submit: wseq stamp (xfs_buf_submit ~4683) runs BEFORE the skip gate (submit_bio ~3268) — submit-stamping voids every undestaged check.

## FIX-6/7: undestaged buffers never suppressed (P12 ex_guard arm xfs_buf.c:~3880) / never clean-evicted (P3D relinval xfs_mxfs_dlm.c:~2284). dir_skip predicate arms were already guarded via entry bail 23990.

## run76 root (FIXED): FUA READ(16) silent-EIO storm → mount-root sick-poisoning
Storm-time scsi_execute_cmd failures (non-ILLEGAL_REQUEST) returned silent -EIO (kern.c ~630); reload imap_to_bp EIO'd for whole storm ≫ its 30ms retry; root got sick-marked → node lost the whole mount until remount (dirino= empty, readdir=0 rounds 16-24). FIX: bounded retry ×20 w/ backoff inside mxfs_pal_scsi_read_fua_bdev + P-FUA-READ-RETRY/ERR prints. run77: 0 EIOs.

## FIX-8 (run77 root, CAPTURED LIVE test5@302.78): reload adopt reverts own in-flight grow
Under held EX, dd grew dir 131 (leaf split nx6→7, P34C-DIRGROW, leafn births); 4ms later a reload on the P91-protected cluster FUA-read the platter (P34D-RELOAD-FRESHSRC) and ADOPTED pre-grow nx=6 (P133-DINO-READSTALE, P33-FROMDISK-DIRSHRINK "REVERTED smaller") while inode item in AIL → da-btree inconsistent → "Corruption detected"(302.79, xfs_error_report variant — grep BOTH 'Metadata corruption' AND 'Corruption detected'!) → EFSCORRUPTED spiral → test5 zombie rounds 16-24 (readdir=0, its lagged adds = peers' round-21 RDMISS node5_f29-50.md5). FIX: P34E-FRESHSRC-SELFAHEAD-SKIP — skip adopt if pincount>0 || ili_fields || IN_AIL (platter is behind us by definition; peer-ahead only possible when clean).

## Diagnostic probes added (keep)
- P55-TORN-DIFF (xfs_da_btree.c, in P54 block): per-sector diff of in-core failing buf vs plain-read; NO-INCORE-BUF fallback.
- P56X-CRCFAIL (xfs_dir2_data.c read verify): buffer geometry + per-sector crc32c on real CRC failures.

## Open leads (NOT yet fixed)
1. **test1(rank1) EDEADLK storm: 10380× rc=-35** vs ~70 on peers (run77) — PR→EX upgrade denial livelock (CONVBLK-DENY dlm.c:3445; TCP has no writer-priority/defer_for_waiter like sess50's CAW fix). Suspected main slowness/desync amplifier. Candidate: master defers PR re-grants when EX waiter queued (TCP grant policy).
2. drc harness: per-node stderr can die silently (test5's log empty); barrier timeout=120s lets nodes free-run/lag → cross-round contamination noise in postmortems. Consider coord_barrier hard-fail.
3. P74 ABSORB arm (dlm.c:3683) mirror-update-without-reject desync hole (sess4 note) still open.
4. Console capture: 6/8 files 0 bytes in run77 (pty perms/race?) — panics would be lost; fix capture or rely on pstore.

## Infra
- run.sh preserves per-run logs at /tmp/run_dir_reuse_coherency_<RUN_ID>/ on FAIL (copied from mktemp dir).
- fua_verify reads only 512B (1 sector); use sg_dd iflag=fua for full blocks. plain dd (no direct) on guest = guest page cache!
- Envelope data offset = u64 @ byte 88 of sector 0 (bytes); LBA = daddr + off/512. run75's torn daddr 85824096 → LBA 86020784.
- Per-run cycle + detached run77-style launch + 2×~285s foreground polls ≈ one drc run (~8.5min inc. prep).
