---
name: AAA-ccloope8e9-sess1-ROOT-sema-poisoning-4patches-0.10.65
description: sess1(e8e920f7) ROOT FOUND+FIXED: bmbt-evict double-unlock (unlock+relse) poisoned b_sema (+1/reload since sess4-46ef). 0.10.66=C5EF60D5. run66 live.…
metadata:
  type: project
tags: [dir_reuse_coherency, caw, 32node, xfs_buf, b_sema, double-submit, crash, ROOT-FIX]
---

# sess1 (ccloop e8e920f7) — b_sema poisoning ROOT FOUND AND FIXED (RULE-4 complete loop)

## THE ROOT (proven by probe stacks in run65, 1 second after round 1 started)
`xfs_mxfs_dlm.c` had **`xfs_buf_unlock(bp); xfs_buf_relse(bp);`** — and `xfs_buf_relse` IS unlock+rele (xfs_buf.h:375) — at exactly TWO sites (whole-tree grep), both sess4(46efd8b6)-era:
- `mxfs_dir_evict_bmbt_blocks` (was line ~1989): held[]-loop exit after evict/skip
- `mxfs_dir_evict_bmbt_by_root` (was line ~2179): incore(XBF_TRYLOCK) loop exit

Every EX reload of the btree-format shared dir (mxfs_dlm_reload_inode → evict at 18206/18209, from mxfs_dlm_ilock_begin ← xfs_lookup consumer_refresh) DOUBLE-UNLOCKED every held bmbt buffer ⇒ b_sema +1 each pass ⇒ buffers permanently multi-ownable. run65 probes (0.10.65, srcver C970352B) caught it instantly: P-SEMA-OVERUP ×400 (cap) by r3, ALL on ONE bmbt buffer daddr=29306184 comm=dd, count monotonic 2→19 within ONE second, dump_stack = `xfs_buf_unlock+0x1b8 ← mxfs_dir_evict_bmbt_blocks+0x435 ← mxfs_dlm_reload_inode+0x23a4 ← mxfs_dlm_ilock_begin ← xfs_ilock ← mxfs_dlm_dir_consumer_refresh ← xfs_lookup`; P-SEMA-DUALLOCK stacks showed by_root re-acquiring via xfs_buf_get_map with count>0. Explains: kcore b_sema.count=83 (sess2 3e02), all dual-owner shapes: xfsaild delwri trylock succeeding during rm's hold → 54× P-WRCNT-RESUBMIT double submits (validate2) → racing completions → double xfs_buf_item_done → spurious not-in-AIL SHUTDOWN 0x8 + xfsaild NULL-relse oops (test1 r17) → AND write-write wire reordering of same-buffer double submits = a prime single-dirent-loss (r18 exp3200 got3199) vector. Likely also the whole wedge#2/#2a lost-wakeup family's enabler.

## FIX — 0.10.66 = srcversion C5EF60D535AF290C91B4112
Removed the bare `xfs_buf_unlock(bp);` at BOTH sites (comment "sess1(e8e920f7) ROOT FIX" ×2 in xfs_mxfs_dlm.c). Exactly one unlock: relse.

## Kept from 0.10.65 (all still in):
1. P-SEMA-DUALLOCK probe (xfs_buf_trylock/lock, `mxfs_buf_sema_dualock_check`, cap 400, stack×8)
2. P-SEMA-OVERUP probe (xfs_buf_unlock, count>1 after up, cap 400, stack×8)
3. xfs_buf_ioend_work credit protocol (3rd router now mirrors ioend/bio_end: wake_sync consume → P-SYNCWAIT-OVERRIDE path=worker; else ASYNC?relse:complete) — hardening, NOT the primary poisoner
4. xfs_buf_item_done xchg claim → P-BLI-DOUBLEDONE loser (kills the NULL-relse oops class + spurious 0x8 shutdown permanently)

## run66 LIVE: `run_id=20260712T033621Z` launched 03:38Z, pid 1958839
SP=/tmp/claude-1000/-src-mxfs/e215743d-7b2e-4198-91e2-451903616da5/scratchpad, log $SP/run66.log, stream $SP/test1_dmesg_run66.log (ring cleared).
DECISIVE METRICS: P-SEMA-OVERUP==0 AND P-SEMA-DUALLOCK==0 all 24 rounds (they were 400/400 by r3 on run65) + P-WRCNT-RESUBMIT==0 + no FAIL/shutdown + nodes_pass=32/32. Post-run: sweep ALL 32 nodes (`dmesg | grep -c 'P-SEMA\|P-BLI-DOUBLEDONE\|P-WRCNT-RESUBMIT'`).
THEN: 2-3 consecutive clean 24-round 32/caw runs → re-verify 1/2/4/8/16 caw (+ tcp cells) since core changed → YES marker `/src/mxfs/.ccloop/runs/e8e920f7-dcb3-4781-989f-cca95cb2f962/criteria-met`.
Historical failure ladder at 32/caw for reference: r9 meltdown (fixed 0.10.63 ilock walk) → r10 dir-data CRC (canonical block0 0.10.64, publisher proven firing on 7 nodes) → r17 crash (this root fix) → r18 undercount (plausibly same root — watch).
If a run still fails: check P-SEMA first (any hit = second poisoner, stack names it), then mxfs-drc-FAIL classes, then SYSCALL_HANG scsi_execute_cmd family (see wedge-root-has-moved-to-scsi-layer-2026-07-11 + NEW-BUG-mass-unmount-blk_execute_rq-wedge-2026-07-11 — separate block-layer risks, harness fast-aborts now).
