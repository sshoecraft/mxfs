---
name: sess6-FIX14-15-cil-window-evict-and-rank1-stale-serve
description: sess6 part2: FIX-14 (P-DE-BLK in_ail-gated undestaged bypass = md5-tail loss root), FIX-15/15b (rank1 stale-serve: honor-wait + H18 dead-trylock repa…
metadata:
  type: project
---

# sess6 part 2 — FIX-14/15/15b + run ladder

Builds: 6D52DE30 (FIX-13, runs 85-86) → BA1D932B (P-DIRSTALE ungated, run87) → 7C4CE4C1 (FIX-14, run88) → **36600ADF (FIX-15/15b, run89 in flight)**.

## FIX-14 (PROVEN run87 r2, node4 daddr 18840944): the CIL-window evict — THE md5-tail-loss root
The acquire-fence dir-block evict (xfs_mxfs_dlm.c ~8425, P68-EVDECIDE/P-DE-BLK) had `(!in_ail || !mxfs_dir_buf_is_undestaged())` — same idiom FIX-10 killed in P28C. CIL-window buffers (committed adds, in_ail=0, dirty=0, pin=0, delwri=0, lseq>wseq) were EVICTED (DONE cleared) on every acquire pass; the next read re-DMA'd the pre-add platter over b_addr; the accumulated wave dirents vanished from the RMW base and the destage wrote the reverted image. Evidence: P-DE-BLK disp=EVICT per add; P13-NADD bp=…cf180 lseq growing while content reverted; P42-RELDUR later saw lseq==wseq done=0 bad=0 (blindness). Fixed at 3 sites: 8425 (P-DE-BLK), 1235 (P59-BMBT-EVICT), 18637 (P133-BMBT-INVAL) — undestaged check UNCONDITIONAL.
**Result run88: peers had ZERO fail rounds 1-10 — cluster-wide tail loss GONE.**

## Remaining after FIX-14 (run88)
1. **rank1-only transient stale-serve** (rounds 2/4/5, 757-794/800): ALL victims LOOKUP_OK+REREAD_SHOWS (nothing lost). Root traced: fresh-PR-grant reload flags stale blocks (b_mxfs_stale_pending); first `ls` maps them while transiently busy (locked/dirty/pin/delwri from the just-settling create wave); honor arm can't invalidate; stale view served; the CLASSIFIER's later maps invalidate (P5-DEFERRED at 107.465 = after count-ls at 107.453) → REREAD_SHOWS.
2. **round-11 dir-visibility catastrophe** (once/run, late): peers stat($D) → dir MISSING (DIRID empty, readdir=0/800) while rank1 sees 785 w/ lookup_fail=328 (leaf-vs-data tear). NOT yet root-caused. Next capture: root-dir (ino 128) block staleness + what rank1's mkdir published.
3. Pace ~35-40s/round when a node's verify stalls (barrier waits); base pace 13-15s.

## FIX-15 (honor-wait) + FIX-15b (H18 dead-trylock repair) — build 36600ADF, run89 tests
- **KERNEL FACT: xfs_buf_incore(flags=0) BLOCKING-locks the found buffer** (get_map→find_lock; xfs_buf.h:299 maps incore→get_map(XBF_INCORE|flags)). Return codes: 0=found+locked, -EAGAIN=found-but-locked, -ENOENT=absent.
- Consequence: H18 walk's `incore(0)` + `xfs_buf_trylock(dbp)` was a SELF-trylock = always false → inline-stale arm DEAD → everything deferred to stale_pending (why P5C never fired; why the flag machinery dominates). FIX-15b: decide INLINE under the held lock — undestaged→P5C keep; else DONE-clear (+gen=0, flag clear). NOT xfs_buf_stale (ghost-cache hazard w/ AIL BLI — sess101).
- FIX-15: honor point (xfs_da_btree.c ~3227) now a bounded wait: incore(TRYLOCK); -EAGAIN→msleep(2) retry ≤25×; found+flagged+busy(dirty/pin/delwri/WRITE)→retry; undestaged→P5B drop-flag; clean→invalidate P5; exhaustion→P5D-STALE-SERVED print.
- P-DIRSTALE (xfs_buf_stale tracer) now ALWAYS-ON capped 200 w/ dump_stack — fired only for legit xfs_trans_binval/xfs_dir2_shrink_inode (rm-rf frees) in run87.

## Infra facts
- All 8 domain XMLs now have serial `<log file>` (test1,5,6,7,8 added via virsh define; applies each cycle). test5 panicked in run85 with NO capture (pre-fix); no pstore in VMs.
- test1 inobt shutdown (run85 @334s): cross-node double-ifree (P-DIFREE-DBL agino=1985 chunk already all-free, agi_freecount=128 vs 64) during test5-death fallout — dormant unless node death; not chased.
- P60-GENMATCH-STALE does a FUA compare-read per hit ≤3000 — instr cost in hot path; consider gating if pace matters.
- imap_to_bp rc=-5 storm = post-SHUTDOWN symptom (xfs_trans_read_buf returns silent EIO when fs_shut; P-RELOAD-IMAPEIO forensic print now in reload fail path shows fs_shut/log_shut).
