---
name: sess27-SMOKINGGUN-intrablock-slot-collision-off1280-node7-overwrites-node5
description: sess27(ccloop) DEFINITIVE SMOKING GUN: dir_reuse loss is an INTRA-BLOCK SLOT COLLISION — two nodes' addname pick the SAME data-block offset. Round7 d…
metadata:
  type: project
---

## sess27 — THE mechanism, proven byte-exact: intra-block dir-slot double-allocation

dirwr=1 NFS-stream trace (tests/tcp/drc_cap/stream_rank5.log), round 7, lost entry node5_f46.md5, dir block daddr=10466208:

- **112.555108 P11-DATALOG**: node5 logs node5_f46.md5 @ **off=1280**. P-CRNAME-DONE rval=0.
- **112.555190 P11-POSTADD** + **112.555753 P-RELFLUSH** (in_ail=1): block dump ENDS with "... node4_f43.md **node5_f46.md**" → node5_f46.md5 IS in the block, flushed.
- **112.569810** (14ms later, SAME node5 bash thread, adding node5_f47.md5 @ off=1312): block dump now ENDS "... node4_f43.md **node7_f47.md**" → **node5_f46.md5 is GONE, node7_f47.md sits where it was**. RELFLUSH confirms.

### Conclusion (byte-exact): node7's addname allocated **off=1280** — the EXACT slot node5 had just filled — and overwrote node5_f46.md5 with node7_f47.md. An INTRA-BLOCK SLOT COLLISION / free-space double-allocation. node7's free-space accounting (the data block's bestfree, or the node-format FREE/freeindex block xfs_dir2_free bests[]) was STALE: it listed off=1280 as free though node5 had occupied it. This is the SAME root sess11 proved ("dirent bytes logged then vanish, internal to addname") — still live at build 965BDBD3 with gen_per_handoff+extent_adopt.

### Why it evades every detector (reconciles sess27 refutations)
The clobberer (node7) RMWs a base whose DATA-block content lacks node5's add but whose gen MATCHES (P60-GENMATCH-STALE skips in-AIL blocks; DIR-STALE-SKIP needs gen-mismatch; stale_base=0 because dir_gen==loaded_gen). force_coherent doesn't help (the stale base is the in-AIL/freescan accounting, not a clean cold-read). It's WRITE-SIDE (the slot is physically overwritten on the platter). All consistent.

### THE FIX TARGET (next session, RULE 4): free-space coherency at the clobberer's addname
node7 must NOT pick off=1280 while node5_f46.md5 occupies it. Either node7's DATA block is stale (missing node5's add) OR node7's FREEINDEX (xfs_dir2_free bests[]) is stale. DECISIVE PROBE: at xfs_dir2_data_use_free / the addname slot pick (xfs_dir2_node_addname_int), log (ino, daddr, chosen off, the dirent ALREADY at that off if any) for ino<=256 — catch the moment node7 picks off=1280 over an occupied slot, and dump whether node7's bestfree vs the block's actual content diverge (stale bestfree) AND whether node7's block buffer is in-AIL/undestaged/gen-current at that point. Likely fix: on cross-node handoff, force-refresh the node-format FREE/freeindex block AND the data block's bestfree even when in-AIL (the in-AIL keep-guard is preserving node7's stale free accounting). Cross-ref sess11 GPT sticky touched-buffer fence ([[sess11run-ROOT-committed-dirent-reverted-by-evict-before-publish-GPT-fix]], NEVER implemented — no b_mxfs_cluster_undestaged field exists) and [[sess27-DECISIVE-loss-is-write-side-force-coherent-doesnt-help]] [[sess23-NEXT-hypothesis-node-format-freeblock-coherency]] (sess23 already suspected node-format freeindex bests[] staleness).
