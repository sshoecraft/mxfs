---
name: sess19-readahead-disable-partial-fix-holeB-confirmed
description: sess19 PARTIAL FIX (default reverted to 0): dir_no_reada disables dir readahead — eliminated NOREUSE-8iter leaf-hash loss (GPT Hole B confirmed) but…
metadata:
  type: project
---

## sess19 (ccloop 8ddb16a2) — readahead-disable result + REGRESSION revert.

## CHANGE (KEEP, default 0/opt-in): param `mxfs.dir_no_reada` makes xfs_da_reada_buf a NO-OP for multinode shared dirs (S_ISDIR + m_mxfs_dlm + !single_node). Defined xfs_mxfs_dlm.c (EXPORT_SYMBOL), gated xfs/libxfs/xfs_da_btree.c. **Default 0** (was briefly 1, REVERTED). Final build = E99A445B (deployed both nodes).

## RESULT — PARTIAL FIX + a REGRESSION:
- POSITIVE (GPT Hole B CONFIRMED): with no_reada=1, NOREUSE cc_blockdir_probe (reliably failed ITER 1 before, 155-198/200) ran 8/8 iters CLEAN. So dir-block READAHEAD completing late and re-populating a stale XBF_DONE image past the acquire-evict IS a real stale-base source.
- INCOMPLETE: with no_reada=1, a longer `cc_blockdir_probe 30 50` (reuse) STILL shorted AND `NOREUSE=1 15 50` STILL shorted (leaf-hash, lookup_fail>0, readdir=200). So readahead is ONE source, not the only one. Residual = equal-count leaf-ADDRESS divergence (P-LEAFWRITECLOBBER/READSTALE fired 0× on residual).
- REGRESSION: `./run.sh 2 tcp` with no_reada=1 = 15/16, **crash_consistency FAIL (1/2)** (all others PASS incl cache_coherency/zero_silent_loss). crash_consistency is single-file-write + node-kill + journal-replay (not obviously dir-reada dependent) → likely flaky/timing, but UNCONFIRMED. → reverted default to 0 to guarantee no regression. (Re-validate: does crash_consistency pass at no_reada=0? does it pass at no_reada=1 on a re-run = flaky?)

## RESIDUAL SOURCE (with reada off): DIR-STALE-SKIP fired 10×/node for blk=0 (first data block) buf_gen=0 inode_gen=2 in_ail=1 undest=1 lseq=30 wseq=0 — mostly a freshly-ALLOCATED data block (buf_gen=0 = never disk-read) holding this node's 30 unwritten entries during sf→block conversion (a BENIGN keep, not obviously the loss). The leaf-address divergence (lookup_fail with full count) is the subtle residual — the leaf hash entry's (hashval->data-block-ADDRESS) points to the wrong data offset because the node's data-block LAYOUT/bestfree diverged from the peer's durable layout during concurrent conversion. The COMPLETE fix remains the image-origin freshness barrier on dir DATA+index buffers [[sess19-GPT2-dir-index-freshness-barrier-fix-spec]].

## NEXT (sess20): (1) confirm crash_consistency at no_reada=0 PASSES (restore 16/16 baseline) and whether no_reada=1 crash_consistency fail was flaky; (2) instrument the leaf-build to log the (hashval, computed data-address) vs the coherent disk dirent location to catch the address divergence directly; (3) implement the freshness barrier (dir DATA blocks especially — they feed both dirent placement and leaf addresses); keep dir_no_reada=1 as a validated component once crash_consistency confirmed OK with it.

## STATE: build E99A445B both nodes (= prior detectors + dir_no_reada default 0), cluster mounted clean, dirwr=0, no_reada=0. Official baseline = 16/16 (at no_reada=0, per earlier runs this session). Marker NOT written. [[sess19-noreuse-confirms-fundamental-not-ABA]] [[sess19-GPT2-dir-index-freshness-barrier-fix-spec]]
