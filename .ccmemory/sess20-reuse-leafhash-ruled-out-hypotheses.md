---
name: sess20-reuse-leafhash-ruled-out-hypotheses
description: sess20 RULED OUT (RULE 4) for reuse leaf-hash loss: (1) xfsaild stale-leaf reflush count-clobber, (2) content-divergent leaf write, (3) NL-released d…
metadata:
  type: project
---

## sess20 (ccloop 8ddb16a2) — reuse leaf-hash loss (dir_reuse_coherency 24-round, criteria.json row 13 FAIL). RULE-4 elimination log so the next iteration does NOT repeat these.

## REPRO: ./run.sh 2 tcp dir_reuse_coherency — reliable, SAFE (no wedge), fails from ~round 16, always node2/rank-2 entries, readdir=200 (data complete) / lookup-fail (leaf hash missing), durable on LUN (pureLUN+direx+8s all stay missing). Builds this session: F8FF8E54 (P20 removed) → 64B8DBFD (added content-divergence leaf detector).

## RULED OUT (each with evidence):
1. **xfsaild stale-leaf reflush, count-short** (sess19 P-LEAFWRITECLOBBER buf_cnt<disk_cnt): did NOT fire while test failed.
2. **Content-divergent leaf write at equal count** (sess20 NEW detector: hashval sum+xor fingerprint of buf vs coherent on-disk leaf, fires on buf dropping any hashval disk has): fired **0×** under dirwr=1 while the test FAILED. ⇒ no leaf write through the xfs_buf_submit_bio chokepoint drops node2's hashes (neither count nor content).
3. **NL-released dir-skip suppression** (mxfs_buf_xfsaild_skip_dir_write / mxfs.dirskip): A/B with dirskip=0 → STILL FAIL, and WORSE (drc-FAIL 13/50 vs ~6-18). So suppression is not the dropper; if anything it caught some stale reflushes.
4. **ABA / prior-incarnation leaf**: P-EVICT-SKIP showed buf_incarn==cur_gen (2263907978) — same incarnation, not ABA.
5. **Readahead** (the sess20 non-reuse fix dir_no_reada=1): reuse variant persists with reada=1.

## ALSO: every P16-DIRBLK-SUBMIT leaf write showed bgen==dgen (current gen, not stale-gen). P-EVICT-SKIP keeps a pinned+undestaged leaf (daddr 2093296) on node2 but that is likely node2's LEGIT current work (P-LEAFWRITECLOBBER silent).

## LIVE HYPOTHESES (next, RULE 4):
A. **A divergent leaf write goes through a submit path the chokepoint detector does NOT sit on** (the detector is in xfs_buf_submit_bio P56 block). dirskip=0 making it WORSE implies real stale reflushes land. ACTION: find ALL leaf-write submit paths; place an un-ratelimited fingerprint trace on EVERY leaf write (log count+sum+xor+comm+bgen for daddr of the leaf) to see if node2's hashvals ever get written and then disappear.
B. **node2's leaf-hash insert is lost IN-CORE / never destaged**: the leaf BLI carrying node2's hash never reaches disk (data-block BLI does). ACTION: instrument xfs_dir2_leaf_addname to log node2's inserted hashval + confirm the leaf buf is dirtied/committed; then confirm whether that leaf buf is ever write-submitted (vs skipped as !DONE in mxfs_dir_data_durable/flush's sess33 !XBF_DONE skip — a leaf invalidated post-commit-pre-destage would be skipped, losing the change).
C. Cross-check: is the leaf even in LEAF format, or is the dir in BLOCK format (single block holds data+leaf)? At 100 entries it's leaf. Confirm daddr 2093296 vs data daddrs.

## CONTEXT: official ./run.sh 2 tcp core 16/16 (criterion met earlier; marker CLEARED by user — work continues). P20 guard removed. readahead-disable kept. Separate corruption-shutdown variant under same churn [[sess20-residual-is-daddr-reuse-corruption-not-leafhash]]. [[sess20-reuse-leafhash-root-pinned-undestaged-leaf-handoff]] [[sess20-dir-reuse-coherency-reliable-repro-characterization]]
