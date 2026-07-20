---
name: sess35-run14d-zsl-lsn-destage-and-stale-retry
description: sess35 run14d: 2 PROVEN zsl fixes landed+verified (cross-node LSN destage, pinned-drain log force), 3rd fix (stale-retry FCDB6848) built NOT tested
metadata:
  type: project
tags: [zero_silent_loss, run14d, dir-coherency, lsn, drain]
---

# sess35 (ccloop run14d) — zero_silent_loss: 3 root causes, 2 fixed+verified, 1 fix built-untested

Progression: 84 losses/iter → ~1 durable loss per lossy iter. Iter walls 166s → 102-123s (beats sess17 record).

## FIX 1 (PROVEN + VERIFIED, KEEP): cross-node LSN compare in mxfs_dir_buf_is_undestaged
- P35A probe proved: every false "destaged" verdict had li_lsn < payload_lsn — IMPOSSIBLE locally (payload stamp is copied FROM li_lsn at write submit), so the payload LSN was stamped by a PEER's journal. Cross-node LSN compares are meaningless.
- Misjudged buffers got P133-INAIL-REFRESH: disk re-read over own committed-unwritten dirent inserts (killed node5_dir33 et al within 7ms of mkdir, same EX hold).
- Fix: node-local seq pair on xfs_buf — `b_mxfs_logged_seq` (bumped in xfs_trans_log_buf), `b_mxfs_written_seq` (snapshot in xfs_buf_submit after verify_write). is_undestaged := pinned || logged!=written. Removed mxfs_dir_buf_payload_lsn.
- After fix: 0 P133 fires, 0 create errors, 1600/1600. NOTE: mxfs_buf_is_undestaged (AG-meta version, ~L6650) has the SAME cross-node flaw — not yet fixed; revisit if AG corruption persists.

## FIX 2 (PROVEN + VERIFIED, KEEP): pinned-buffer drain stalls 23-29s
- P-RELFLUSH pin=1 → xfs_bwrite's wait_unpin sleeps without driving the CIL; unpin only at ~30s log-worker tick (test2 stalled whole cluster 23.8s; SESS50-STARVE).
- Fix: `if (xfs_buf_ispinned()) xfs_log_force(mp, 0)` before xfs_bwrite in mxfs_dir_flush_data_blocks AND the bmbt P133-BMBT-RELFLUSH loop. Max drain 29137ms → 135ms.

## ROOT 3 (PROVEN, fix BUILT NOT TESTED — build FCDB684890D2284C2C4BC92)
- Residual ~1 durable CREATOR_MISSING loss per lossy iter (node3_dir16, node9_dir9, node14_dir88…).
- P35E write-lineage probe (dir3 XDB3/XDD3 writes w/ CRC+comm, in pal/linux/xfs_buf.c) proved writes ARE serialized under DLM holds (261 writes, ~0 out-of-hold). P35C/P35D proved post-flush persistent in-core≠disk with MULTIPLE simultaneous divergent in-core copies across nodes (t4/t5 same daddr different CRCs) — superseded-image RMW, not SCST cache lag.
- Mechanism: fast-path EX creates (P-DIRFASTEX) keep re-dirtying dir blocks during the BAST drain; single-shot mxfs_dir_stale_data_blocks then SKIPS them (189 P99-STALE-SKIP fires/iter cluster-wide) → lock handed off with committed-unwritten dirents → peer RMWs stale disk image / our late writeback clobbers → durable loss.
- Fix in FCDB6848: mxfs_dir_stale_data_blocks returns nskip; call site loops flush→log_force(SYNC)→stale up to 500× w/ msleep(1) until nskip==0 (P35F-STALE-RETRY-EXHAUSTED on give-up).

## NEXT SESSION CHECKLIST
1. Power-cycle test1-16 (virsh -c qemu:///system destroy/start), wait SSH.
2. `INSMOD_OPTS="dirwr=1" timeout 480 ./tests/criteria/zero_silent_loss.sh --iters 3` on FCDB6848.
3. Expect: P99-STALE-SKIP still fires (first pass) but P35F-EXHAUSTED ≈ 0 and silent=0. Check losses with the forensic MISSING lines.
4. If pass: strip/gate P35A/P35C/P35D/P35E probes (P35E is unlimited pr_warn — perf cost), re-verify, then run remaining criteria (verify_ship.sh).
5. HARNESS BUG (separate): zsl count via `find | wc -l` + `tr -cd 0-9` concatenates garbage when ssh output has extra lines (iter silent=614417… nonsense; pre_drop=0 once). Fix the count extraction in scripts/sess88_workload_a_modeN_baseline.sh to take the LAST numeric line.
6. Transient readdir undercount (~15-40 entries reappear seconds later at forensics) still unexplained — only matters if it persists after Fix 3.

## Env notes
- 1-iter run ≈ 110s incl. mount; 200s timeout is right for 1 iter, 480s for 3.
- journalctl field gotcha: -o short-precise → $3 is the time (not $2).
- P35E lineage parse + hold-window join script: see transcript (python3 inline, /tmp/p35e.log + /tmp/p35_holds.log).
