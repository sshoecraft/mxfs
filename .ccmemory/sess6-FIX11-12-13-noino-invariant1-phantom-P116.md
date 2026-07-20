---
name: sess6-FIX11-12-13-noino-invariant1-phantom-P116
description: sess6(a9a03929): 3 proven roots fixed — P5-DEFERRED-STALE undestaged discard (FIX-11), noino BAST release drain gap (FIX-12/12b), phantom-EX defeats…
metadata:
  type: project
---

# sess6 (ccloop a9a03929) — noino release family: three proven roots

Builds: BA67B6309 (FIX-10, run81) → 0D74A9E4 (FIX-11+12, run82) → 22E4696E (+12b+script, run83) → 5451F8A3 (+IMAPEIO forensics, run84) → **6D52DE30 (+FIX-13, run85 in flight)**.

## FIX-11 (PROVEN run81 r5): undestaged guard on acquire-reload stale paths
run81 r5: test8's 46 md5 adds (all in bno5@48144232, born by test3 who destaged+released cleanly) were destroyed at 157.307 by P5-DEFERRED-STALE honoring a lingering `b_mxfs_stale_pending` in the post-CIL window (dirty=0 pin=0 delwri=0 but lseq>wseq). P42-RELDUR@160.17 done=0 = drain had nothing left; platter kept peer's older image cluster-wide (LOOKUP_ENOENT everywhere).
Fix at 3 sites: honor point xfs_da_btree.c (~3241) requires `!mxfs_dir_buf_is_undestaged` + drops flag with P5B print when undestaged; H18 setter trylock-OK arm (xfs_mxfs_dlm.c ~14400) skips xfs_buf_stale on undestaged (P5C); trylock-FAIL arm doesn't set the flag when undestaged. Invariant: **undestaged buffer (lseq!=wseq || pinned) may NEVER be staled/invalidated — under Inv-1 platter can't legitimately be ahead of it.**
Result run82: cluster-wide durable loss GONE (7/8 nodes zero fail rounds).

## FIX-12/12b (PROVEN run81): noino BAST release = Invariant-1 hole
BAST for ino whose xfs_iget(INCORE) fails takes mxfs_dlm_noino_bast_work_fn — old drain = `xfs_ail_push_ag_sync_bounded(AG_of_ino)` only. But shared-dir data blocks are allocated AG-AFFINELY BY EACH WRITER (bno5 lived in test3's AG, not ino131's) → never pushed → unlock handed EX with unlanded adds. ALSO fires for LIVE inodes: IRECLAIMABLE (drop_caches) → iget INCORE = -EAGAIN (xfs_icache.c 1135) → noino. Round-7 noino=170 storm = verify-phase drop_caches. Empirical: node8 noino ctr 1→2 across the 157.058 P6U-UNLOCK.
Fix: new `xfs_ail_push_upto_sync_bounded(ailp, max_ms, &target)` (xfs_trans_ail.c; snapshots AIL max LSN, waits until min>target; xfsaild pushes-to-max while ail_empty waitqueue active) + retry×5 then P-NOINO-RELFENCE-WEDGE shutdown (never unlock undrained). 12b: `mp->m_mxfs_noino_drained_lsn` marker (atomic64, xfs_mount.h) — skip push+flush when AIL max ≤ marker (hundreds of noino/round from inode-reuse churn; only first after new commits pushes). Marker stored AFTER coalesced flush (racer skip must be flush-covered). `xfs_ail_max_lsn` accessor added.

## FIX-13 (PROVEN run84 test3@186.65): phantom-EX defeats P116 self-clobber guard → node shutdown
The noino release CANNOT demote i_dlm_mode (couldn't iget) → in-core inode keeps mode=EX/PR while DLM entry is gone (P108 "held_raw=0" phantom, sess52 family). Chain: rank1 rm-rf BASTs test3's IRECLAIMABLE file ino 1935 → noino unlock (drained OK) → rank1 frees ino on disk (xfs_ifree bumps gen →…998, mode=0) → next round dd O_TRUNC opens stale dentry→stale in-core incarnation (gen …997) → reload P103-RELOAD-REUSE-ADOPT wants to adopt freed image, **P116-RELOAD-SELFCLOBBER-SKIP vetoes on sc_grant_held=(i_dlm_mode!=NL)** (pin=0 ili_fields=0 — phantom!) → truncate frees the DEAD map's blocks → P3-SKIP-DBLFREE storm (agno=0 ltbno=297 ltlen=111) → "Corruption of in-memory data (0x8) at xfs_defer_finish_noroll (xfs_defer.c:721)" → **filesystem shutdown** → node zombie (readdir=0; every FS op silent -EIO b/c xfs_trans_read_buf shutdown check has NO alert — that was run83/84's mystery imap_to_bp rc=-5 storm, P-RELOAD-IMAPEIO forensic print confirmed fs_shut=1 log_shut=1). Same test3 shutdown in runs 82,83,84 at round ~6-9.
Fix: sc_grant_held additionally requires `mxfs_v5_dlm_inode_held_rawmode(mp->m_mxfs_dlm, ino) != NL` (DLM table = source of truth; cheap local-mirror read on TCP).

## Run-shape facts (current)
- Baseline round pace 13-15s; 24 rounds+prep ≈ fits 480s barely. Episodic stalls (a node's 22-45s round) = the killer: blows COORD_TIMEOUT=120 barriers → free-run → false cross-round misses (run83 r9 "700/800 everywhere" = shutdown test3 simply created nothing; NOT a data loss).
- test1(rank1) residual: transient readdir shortfall that heals <1s (RDMISS printed missing=[] b/c diagnostic re-ls healed; script now saves FIRST view → mxfs-drc-RDMISS0 line + CLASS keyed to it). Fail rounds 2-7-ish, count 750-797/800.
- drc script probes: RDMISS0 (first-view missing), /tmp/drc_ls1.$$. Cycle procedure: destroy+start all 8, rm /root/drc_*.dmesg drc_failrounds.txt on all nodes (accumulate across runs otherwise!), launch detached, 2×285s foreground polls.
- Serial consoles auto-log to /var/log/libvirt/qemu/testN-serial.log (append=off, truncated each VM start) — no console_capture process needed.

## Open leads
1. run85 verdict on FIX-13 (expect test3 shutdown gone).
2. rank1 transient stale readdir (RDMISS0 evidence next).
3. test1 round-9 lookup_fail=245 (listed-but-ENOENT — leaf-vs-data divergence during test3's zombie state? recheck after FIX-13).
4. P52-RELOAD-FREEDREUSE-DIR-SKIP (13030) has same phantom exposure for DIRS (keeps live in-core dir on gen mismatch unconditionally) — candidate next if dir-shaped corruption remains.
5. EDEADLK PR→EX starvation on rank1 (10380/run77) — untouched this session.
6. noino i_dlm_mode demote at source (post-unlock INCORE iget retry + demote) — deferred; P116/P108 table-checks cover proven cases.
