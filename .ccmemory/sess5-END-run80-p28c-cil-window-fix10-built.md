---
name: sess5-END-run80-p28c-cil-window-fix10-built
description: sess5 END: build BA67B6309 (FIX-3..10) ready UNTESTED. run79=7/8 (only transient r7 rank1 788→healed); run80=0/8 r1 P28C invalidated CIL-window adds…
metadata:
  type: project
---

# sess5 (a9a03929) END — build `BA67B6309C428709F33650A` (FIX-3..FIX-10, FIX-10 UNTESTED)

READ WITH [[sess5-FIVE-ROOT-FIXES-suppression-family-and-probes]] (FIX-3..8 details + probes + open leads).

## Ladder state
- run75 0/8 (prior-mkfs block exposure → FIX-5/6/7), run76 0/8 (FUA-EIO sick-poisoning → retry fix), run77 0/8 (adopt reverted own grow → FIX-8), run78 0/8 (test4 PANICKED mid-r3; foreign replay window fine — its own accounting said blocks landed; separate adopt-revert arm → FIX-9), **run79 = 7/8** (only rank1 r7: readdir 788→healed-in-1s transient, RDMISS empty, lookup_fail=0), run80 0/8 (r1: node2_f47-50.md5 durably lost cluster-wide → FIX-10 root, captured live).

## FIX-9 (in 70C8C23F): mxfs_dlm_reload_inode ENTRY guard — skip whole reload when pin>0||ili_fields||IN_AIL (P34F-RELOAD-SELFAHEAD-SKIP; clears i_dlm_stale). run78's revert went through a NON-P34D arm (P33-FROMDISK nx 9→1 w/ P34E=0), hence entry-level.

## FIX-10 (in BA67B6309, UNTESTED): xfs_dir2_data.c ~2061 keep-guard — undestaged check was `b_inail && is_undestaged`; CIL-window blocks (in_cil=1 in_ail=0 pin-dropped dirty=0 DONE-restored) fell through → FUA-platter-compare diff (normal for pre-destage!) → P28C-STALE invalidate+reread DISCARDED the wave-tail adds (run80 r1 test2 @69.966, full chain: P3L-BIRTH lseq-reset → P68-EVDECIDE in_cil=1 → P-DE-BLK SKIP → done=0 → P5-UNDEST-SALVAGE → P60-GENMATCH-STALE → P28C-STALE). Fix: unconditional `mxfs_dir_buf_is_undestaged(dbp)` (exact under FIX-5 honest wseq; sess54 destaged-zombie compare preserved).

## Remaining known issues (in priority order)
1. **P60-GENMATCH-STALE (xfs_da_btree.c:3738)** — sibling disk-compare guard; printed in the run80 chain; check whether its ACTION path also lacks an undestaged guard (P28C did the actual invalidate this time).
2. **run79-style transient**: rank1 r7 readdir 788/800 healed <2s (also r7 rank1 in run80!). ROUND 7 + RANK 1 twice = suspicious pattern (r7 = ring/format transition point?). Not yet diagnosed: candidate = clean_skip PR-release handing off with unlanded blocks (xfs_inode_clean blind to dir DATA bufs) IF that path bypasses the P3B fence — VERIFY whether sf/clean fast-release skips 11103's P3B block.
3. test1(rank1) EDEADLK storm (10380×/run77) — PR→EX upgrade starvation, TCP has no defer_for_waiter. Perf+desync amplifier.
4. test4's run78 PANIC cause unknown (no console/pstore) — console_capture MUST be restarted per cycle (was missed in run78; test5 console 0-bytes issue in run77 unexplained — verify capture actually writes).
5. P74 ABSORB mirror desync + drc harness stderr-death/barrier-free-run noise (see other memory).

## Next steps
1. Cycle cluster + `./run.sh 8 tcp dir_reuse_coherency` on BA67B6309 (run81). If the r1-tail loss is gone → ladder to 5 consecutive; expect the r7-rank1 transient class to be the next blocker (fix via item 2).
2. Then full `./run.sh N tcp` N∈{8,4,2,1}; marker only after ALL pass.
3. Infra per run: console_capture restart, save fail snapshots, run.sh preserves logs at /tmp/run_dir_reuse_coherency_<RUNID>/.

## Cluster/infra state at relay
- Cluster is up post-run80 (build 70C8C23F mounted). NEW build BA67B6309 built on host, NOT deployed (deploy = full cycle; nodes insmod /src/mxfs/mxfs.ko via NFS automatically in run.sh prep).
- run80 artifacts: scratchpad/run80/test{2,3}.dmesg; run79: test1.dmesg + fail_r7_rank1.dmesg (122K lines); run78: create_r3_rank4.dmesg + test*.dmesg; slice dump /tmp/slice4.bin on test1.
