---
name: AAA-ccloop46ef-sess5-END-P61-skip-eats-bmbt-commits-fix-design
description: sess5 END: i!=1 chain CLOSED — P61-CHOKEPOINT-SKIP-BMBT fake-ioend eats committed bmbt updates (P76 differs-from-LUN on same owner/daddr seconds befo…
metadata:
  type: project
---

# sess5 END — the i!=1 manufacture chain, CLOSED (RULE-4 evidence complete)

## Final causal chain (run 104051Z, test12, ino=39846019, daddr=66983240)
1. Node commits a bmbt mapping change (dir grow/shrink; e.g. iext=[10,4]) under EX; xfsaild's write of that bmbt child SUBMITS after the EX was released (async destage lag). Release fence didn't land it (fence gap — see below).
2. `P61-CHOKEPOINT-SKIP-BMBT` (pal/linux/xfs_buf.c:~3803, predicate mxfs_buf_xfsaild_skip_bmbt_write = dir-not-EX) **fake-clean-ioends the write**: BLI retired, and b_mxfs_written_seq was stamped at submit ⇒ lseq==wseq "destaged" LIE. The committed image NEVER reaches the LUN.
3. In-core buffer still holds the truth until the evict machinery (guards all satisfied: clean, in_ail=0 post-retire, "destaged") discards it → re-read loads the LUN's PRE-COMMIT leaf ([11,3] missing the grow at off=10) → in-core bmbt time-travels while iext keeps [10,4].
4. Next shrink: xfs_bmbt_lookup_eq(got) → i!=1 (xfs_bmap.c:5289) → EFSCORRUPTED → dirty xfs_trans_cancel in xfs_rename → node shutdown → ~56 failed rv checks/node cluster-wide + 1 dead node (failed=1280). 1-2 nodes/run.

## Evidence
- P75-BMBT-DEL-MISMATCH + P75b neighborhoods (built this sess in xfs_bmap.c at the i!=1 site): iext=[10,4] vs leaf=[11,3] same fsb chain (also [24,3] vs [23,4] earlier) — one committed op missing from leaf; samelun=1 every time (cached==LUN ⇒ committed update never landed, NOT a stale-cache read).
- P76-SKIP-EATS-COMMIT (built this sess at the P61 skip): fires with content-DIFFERS-from-LUN on the SAME (owner,daddr) at 10:46:18-26; crash at 10:46:27. Profile in_ail=0 lseq==wseq (0..13) = post-first-eat state (BLI retired by earlier fake-ioend; wseq stamped at submit even for skipped writes).
- P74-BMBT-RELDRAIN (added to mxfs_dir_flush_data_blocks_relsafe) fired 0: the fence's break condition (!inode-in_ail && !pinned && data_durable) passes on iteration 1, so relsafe (retry arm) never runs. mxfs_dir_bmbt_scan IS consulted by data_durable — but the release path that leaks is likely the bast_process drain+unlock (P35-DIRHONOR, 1335 fires) — CHECK whether that path consults data_durable/bmbt_scan at all.
- rhashtable EAGAIN-continue in the walkers is CORRECT (kernel doc: iterator rewinds; nothing missed) — refuted as cause.

## FIX DESIGN (next session, in order)
1. **At the P61 skip: if content differs from LUN, mark the buffer undestaged instead of lying** — `bp->b_mxfs_logged_seq++` (so lseq>wseq) before the fake ioend. Effects: evict guards (undestaged) keep the in-core truth; the next EX tenure's release fence bmbt_scan sees needs=true and syncs it to the LUN under EX (safe). Cheap, surgical, uses existing machinery.
2. Verify/extend the bast_process drain (P35 path) to consult mxfs_dir_bmbt_scan+data_durable before its unlock (the fence gap that lets the write still be pending post-release).
3. Re-run cache_coherency@32 ×2; expect P76-differs → 0 lost (P76 may still print but next-tenure landing heals), i!=1 → 0, then failures should be only the ~54-fail rv residual — re-triage after.

## Current state
- Tree v0.10.23 build 345C285B deployed. All sess5 fixes in: P73 leafless-remove (uv ghosts SOLVED — got=16 face gone), HOLE_OK datascan/P14 gating (dscan corruption SOLVED), P72 post-read reval, P74 drain (inert), P75/P75b/P76 probes.
- Run progression: uv-ghost 1-fail → dscan-corruption 110-fail → 100/54/56-fail (i!=1 face, 1-2 dead nodes). The 54-56 baseline = one dead node's rename invisibility; kill i!=1 and re-measure.
- test VMs flaky at prep (test11/test20/test31 needed power-cycles); retry prep once before diagnosing.
