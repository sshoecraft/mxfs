---
name: sess19-noreuse-confirms-fundamental-not-ABA
description: sess19: NOREUSE=1 probe (fresh inode, NO rm-rf reuse) FAILS at iter1 (191/200, readdir=200 lookup_fail=9 both nodes = leaf-hash). Rules OUT inode/dad…
metadata:
  type: project
---

## sess19 (ccloop 8ddb16a2) — KEY negative result narrowing the fix.

## TEST: added NOREUSE flag to tests/cc_blockdir_probe.sh (NOREUSE=1 skips the per-iter `rm -rf $D`, so each iter's dir keeps a DISTINCT fresh inode — no inode/daddr REUSE across iters). Ran `NOREUSE=1 cc_blockdir_probe 30 50` (build 8B8D7499, dirwr=1).

## RESULT: FAILED at ITER 1 with a FRESH inode (ino=132): test1 all=191/200; .ccb_1 readdir=200 lookup_fail=9 on BOTH nodes (LEAF-HASH inconsistency — dirents durable in data blocks, 9 hash→address entries missing/wrong in the leaf). P-LEAFWRITECLOBBER fired 0× (equal-count content/address divergence, not a count shortfall).

## CONCLUSIONS:
1. The leaf-hash clobber does NOT require inode/daddr REUSE (ABA). It is FUNDAMENTAL to concurrent same-dir create. → Do NOT pursue an incarnation/ABA-specific fix; it won't cover this. The full whole-dir-image freshness barrier [[sess19-GPT2-dir-index-freshness-barrier-fix-spec]] is needed.
2. FRESH dirs reproduce FASTER (iter1) than reuse-mode (iter9-16). Because each fresh dir does a fresh shortform→block→leaf CONVERSION under concurrency every iter — the conversion is the vulnerable window where the leaf is (re)built, and its hash→DATA-block-ADDRESS entries are computed from THIS node's data-block layout, which diverges from the peer's durable layout → addresses point to wrong/stale offsets → lookup ENOENT even at full count. (Contrast sess18's "transience test" fresh-dir 0-loss-in-20 — that used a less aggressive workload/timing; the aggressive concurrent dd+md5 here hits the conversion race every iter.)
3. The equal-count content-divergent variant (lookup_fail=9, readdir=200) is the COMMON case for fresh dirs; the count-shortfall variant (P-LEAFWRITECLOBBER buf<disk) is rarer. So the fix MUST be freshness/coherency based, NOT count-based.

## SHARPENED FIX TARGET (sess20): the concurrent dir FORMAT-CONVERSION / leaf-build path. When a node grows/converts the dir (sf→block, block→leaf, leaf→node) it must build the leaf from the COHERENT current data blocks (the peer's durable image), not a stale local data-block layout. Per GPT's freshness barrier: dir DATA blocks (not just the leaf) must carry an image-origin epoch and be cold-read fresh on a peer-modified tenure before the conversion/RMW reads them to compute leaf addresses. Validate with `cc_blockdir_probe 30 50` AND `NOREUSE=1 cc_blockdir_probe 10 50` (fresh dirs, must be 0 short + readdir==lookup) + `./run.sh 2 tcp 16/16`. Harness now classifies LEAF-HASH vs DATA-LOSS on a short (sess19).

## STATE: build 8B8D7499 deployed, cluster mounted, dirwr reset to 0, .ccb_* cleaned. Official ./run.sh 2 tcp=16/16. Marker NOT written. [[sess19-GPT2-dir-index-freshness-barrier-fix-spec]] [[sess19-ROOT-leaf-hash-inconsistency-not-data-loss]] [[sess19-holeA-ruled-out-fix-is-read-image-origin]]
