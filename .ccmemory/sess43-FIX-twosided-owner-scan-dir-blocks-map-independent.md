---
name: sess43-FIX-twosided-owner-scan-dir-blocks-map-independent
description: sess43(ccloop): dir_reuse 799 = dland-PROVEN stale-base RMW clobber (count 143->98); two-sided owner-scan REFUTED. Build 39C98098 keeper-safe (param…
metadata:
  type: project
---

## sess43 (ccloop 4cb2d0a2). KEEPER build **39C98098** = 445B37FF-equivalent for 1/2/4 (new param `dir_owner_scan` DEFAULT 0; code+probes inert). Criterion NOT met (8/tcp dir_reuse still ~33% fail).

### CORRECTED test understanding (was wrong all session until the end)
`tests/suite/dir_reuse_coherency.sh` line 162: **rank1 `rm -rf "$D"` at the END of every round** ("Reuse stressor: frees the whole dir so the next round reallocs/reuses the daddrs"). So the storm dir ino=131 is rm'd+recreated EACH round → new i_generation (incarnation) per round, and the dir leaf/data **daddrs are freed and REUSED** next round. Names are rank-scoped+stable (node{R}_f{i}+.md5, EXP=2*8*50=800/round). So the loss is an INSERT/clobber during the concurrent create wave under heavy incarnation+daddr REUSE (incarnation-ABA family, sess40).

### dland WRITE-COMPLETION RING — DECISIVE (mxfs.dirland=1; ring=last ~4096 writes; harness dumps tests/tcp/drc_cap/dland_<host>.txt; fields d=daddr o=owner i=incarn s=sumhash n=dirent_count t=ns c=comm op=buftype)
- **SMOKING GUN: a stale-base RMW clobber.** Global time-ordered, daddr=16745864 incarn=2998320033: test5 advanced count to **143**, then test1 wrote it at **98** (−45 entries), then 97,96,…69. test1 RMW'd/rewrote the block from a STALE cached base (~98, pre-test5) → durably drops test5's adds 99-143. (Caveat: the 98→97→… tail is test1's rm-rf teardown; the 143→98 JUMP is the stale-base overwrite.)
- Block 0 (daddr=120) by contrast ends COHERENT: monotonic count across serialized EX handoffs (test1→102, test2→152, test5→155, all incarn=2990893756 = round 22) → NO double-grant, handoffs serialize, each holder reads prior + adds.
- The "foreign owner o=12050306709998375241" on op=xfs_dir3_le(af) lines is a **dland probe ARTIFACT** (reads owner at the DATA offset 40, but leaf owner is at da3_blkinfo offset 48) → NOT real ABA. Real owner is always 131.

### Mechanism (now solid): a node RMWs a dir DATA block on a STALE cached base (missing a peer's durable adds) and writes it durably → single-/multi-dirent durable loss. Serialization is correct; the base-staleness is the bug. The clobber chokepoint (P-DATACLOBBER-SKIP) is SILENT because at the clobbering write in-core ⊇ disk-AT-THAT-MOMENT (the victim already left disk earlier / count compare misses it).

### REFUTED this session (RULE 4, each built+deployed+reproduced)
1. **Release-side owner-scan flush** (map-independent, lands owned dir blocks out of the in-core extent map — both mxfs_dir_data_durable AND the flushes iterate for_each_xfs_iext and miss out-of-map blocks). Build 2F97A691. P43-OWNERSCAN fired cand>0 (gap REAL, flushed real blocks) → **still FAILED** ⇒ release durability is NOT the gap.
2. **Acquire-side owner retire-evict** (map-independent, at the FAST-PATH handoff P101-FASTEX-EVICT xfs_mxfs_dlm.c ~14369 where storm-dir handoffs go, NOT the slow-path ~14854). Builds 8F9FDAD8 (slow-path only, fired 1×=wrong site) → 97C84E4B (fast-path + P34-style BLI retire). P43-OWNEREVICT fired 53-113× but **evicted=0 ALWAYS** ⇒ at the handoff the owned blocks are PINNED/dirty/!DONE (the node's OWN in-flight work), NOT clean cached stale bases → nothing safe to evict ⇒ acquire-evict INERT. **This is the key negative**: the stale base is the modifying node's own pinned/dirty buffer, so you cannot fix it by evicting at acquire.

### Where the fix must go (next session, RULE 4)
The stale base is the node's OWN cached/pinned dir buffer that it RMWs WITHOUT having merged the peer's durable adds. So the fix is at MODIFY/READ time on the buffer the RMW uses: force a coherent rebase (FUA re-read + union-merge of the peer's durable image) into the buffer BEFORE the addname RMW, OR a write-submit guard that drops a write whose on-disk-superset has inumbers the buffer lacks (the union-merge `mxfs_dir3_data_writemerge`/dir_choke_merge path — sess21/41 said it was INERT because in-core ⊇ disk at the write, but re-test against the dland-proven 143→98 case: was the writemerge probe at the SAME chokepoint that's silent? the merge needs the REMOVED-set disambiguation). Also: the rm-rf reuse means a cross-ROUND stale buffer (prior incarnation) may survive into the next round at a reused daddr — verify the sess40 incarnation-skip (mxfs_buf_xfsaild_skip_dir_write, b_mxfs_dir_incarn != i_generation, P40-INCARN-ABA-DIRSKIP) actually fires and covers the data block at the loss.

### TOOLS/REPRO
- `bash tests/drc_cap8.sh <iters> "<modargs>"` — reboots 8 nodes clean each iter, runs 8/tcp dir_reuse, breaks+captures on first FAIL (RDMISS/CLASS + dland dump). Baseline fails ~iter1-2.
- dland analysis: `tests/tcp/drc_cap/dland_*.txt`; global count-regression finder (find a daddr+incarn whose count drops over time across nodes = stale clobber): see the awk in the session transcript.
- P43-OWNERSCAN / P43-OWNEREVICT probes are in build 39C98098 but gated behind `dir_owner_scan=1` (default 0).
Cross-ref [[sess42-CAPSTONE-read-first-grant-divergence-not-data-base-is-the-frontier]] [[sess40-FIX-dirblock-ABA-writeback-skip-build-B9F9326E]] [[sess61-THE-FIX-implement-sess10-grant-gen-faststale-check]].</body>
