---
name: sess2-a16ec5f2-MIDSTATE-fixAB-in-probe-artifacts-corrected
description: sess2(a16ec5f2) MID: FIX-A(LIO WCE=1, relfua=0 verified) + FIX-B(holey-adopt, in 65AED359). Zero-leaf theory DEAD (probe artifact: leaf magic@8 not @…
metadata:
  type: project
---

# sess2 (run a16ec5f2) mid-session state — build 65AED359 deployed (watch build)

## Landed + verified fixes
1. **FIX-A (env)**: LIO fileio backstore had `emulate_write_cache=0` + Buffered-WCE mode → `target_check_fua()` rejected EVERY WRITE(16)+FUA (5461 rejections on clyde = all P13-RELFUAWR rc=-5, ALL nodes, forever). Fixed: attrib=1 live + `targetcli saveconfig` + scripts/lio_tcm_setup.sh now sets =1 with rationale comment. VERIFIED: relfua=0 all nodes in run8/9. NOTE: guests now see write-back cache → real SYNCHRONIZE CACHE → baseline round pace 10-15s→15-17s (~+50% flush cost — pace suspect #1).
2. **FIX-B (code)**: P-RELOAD-TORN-DISK-SKIP refusal removed (xfs_mxfs_dlm.c ~12950, now P-RELOAD-HOLEY-ADOPT log-only). PROVEN root of run7's mass-divergence: partial-rm leaves LEGIT holey map (hole at bno=1 from xfs_dir2_shrink_inode); refusal locked all 8 nodes on stale maps forever. VERIFIED: run8 reached r21+ all-verify-PASS (no mass loss), holey adopts ~20/round.

## Probe-artifact corrections (do NOT re-derive these wrong conclusions)
- **"Disk leaf all-zeros" = FALSE.** dir3 LEAF/NODE blocks: first 8 bytes = forw/back (normally 0); magic is a be16 at OFFSET 8; owner@48, count@56, stale@58, ents@64. scripts/dir_leaf_dump.py FIXED accordingly (was reading magic@0). Run9 on-disk leaf verified VALID (magic 3df1, owner=131, count=384).
- PW-DADDR watch (mxfs.watch_daddr param, build 65AED359, chokepoint xfs_buf_submit_bio in pal/linux/xfs_buf.c): first8=0 for leaf writes is NORMAL. Watch stack proved leaf writes flow via mxfs_dir_data_owner_scan ← mxfs_dir_flush_data_blocks ← mxfs_dlm_dir_durable_signal ← xfs_create (+release drains).
- P21H-LEAFHOLE fires on EVERY ENOENT lookup incl ~6400 legit create-phase O_CREAT misses/round — only unlink-context hits matter (pair with do_unlinkat stack or comm=rm during rm phase window).
- drc verify [ -e ] CANNOT distinguish leaf-hash-present vs DSCAN-heal-masked (mxfs_dir2_datascan_lookup heals stat/lookup but NOT removename) → verify passing does NOT prove the disk leaf has the hash.
- dmesg on nodes rotates in MINUTES under EVICT-RING spam; node dmesg dumps >17MB truncate over 25s ssh — use `dmesg | tail -n 45000`, per-node /root/drc_failverify_r*.dmesg snapshots, and cut at last 'Ending clean mount'. failrounds.txt is APPEND-ONLY across runs (check mtime!).

## Confirmed real residuals (evidence-backed)
- **R1 deterministic un-unlinkable name**: run8 r11→r21: SAME name node6_f35.md5 unlink-ENOENT every round (LKERR err=-2 ×2/round, 799 ifrees, rmdir ENOTEMPTY, ino131 gen frozen 3546458518, 319 P62 samples). dd of= reuses leftover so readdir stays 800 → invisible to verify; drives HOLEY-ADOPT ~20/round + pace 20→28s/round → 480s budget blown = run8's actual FAIL (no verify fail at all!). Same-victim-11-rounds ⇒ deterministic structural trigger (hash position/compaction boundary/rebuild edge?). NEXT: after next FAIL, dump on-disk leaf (fixed script) + victim name hash → durable-vs-incore verdict.
- **R2 run9 face**: test1 SHUTDOWN t=7423 Metadata I/O Error at xfs_trans_read_buf_map during xfs_create on ino131 — read buffer hexdump = urandom (FILE DATA where dir block expected) 30s after P-DBLALLOC-BIRTH 'allocating dir block0 over own-stale on-disk dir block' daddr=120. = map/allocator divergence (double-alloc family). P-DBLALLOC 6-17×/node in run9.
- **R3 pace**: run8 15.8→20→28s/round (accumulating churn from R1); run7 was 10→15s. Budget 480s needs ≤20s avg. FIX-A flush cost is the baseline delta suspect; if needed consider fileio O_DSYNC-mode backstore (WCE=1 kept) to make SYNC CACHE cheap — teardown/recreate of backstore required, defer until R1 fixed and pace re-measured.
- **R4**: chronic `DLM inode lock failed: ino=N mode=5 rc=-35` (-EDEADLK) ~800/rm-round every round (unlink holds dir EX, requests file EX → deadlock-avoid deny → P35-DIRHONOR drop-dir-EX + retry cycle). Works but = 800 release/reacquire cycles per rm (rm 4-8s; perf + churn source; suspected enabler of R1's mid-rm leaf edits).

## Infra notes
- Storage topology CURRENT: LIO loopback (tcm_loop) on clyde, fileio /home/steve/disk.img 50G Buffered-WCE, /dev/mxfs-shared, VMs get scsi-block passthrough <shareable/> cache=none. ALL VM I/O converges on clyde page cache = plain reads/writes cross-node coherent; FUA read/write passthrough now honored (post FIX-A). memory 'project_test_cluster_scst' (SCST) is OUTDATED for this LUN.
- run.sh mkfs's per run; ccloop_reset only reboots WEDGED nodes (dmesg persists across runs otherwise!).
- Node /src/mxfs = NFS mount of clyde:/src/mxfs (mxfs-src mount may be absent; scripts run via /src/mxfs path on nodes).
- drc_reliability.sh 3rd arg = MXFS_EXTRA_MODARGS (e.g. 'watch_daddr=6279744').
- Leaf daddr layout is DETERMINISTIC across runs at same round-shape (6279744=AG3 agbno9 recurred r11 in run7+run8).
