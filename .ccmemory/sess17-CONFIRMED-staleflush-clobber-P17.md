---
name: sess17-CONFIRMED-staleflush-clobber-P17
description: sess17 CONFIRMED (P17-CLOBBER-DROP smoking gun): 2/tcp crash_consistency = durable stale-base flush of shared dir block 496 by BAST-drain(kworker)+xf…
metadata:
  type: project
---

## sess17 CONFIRMED ROOT (RULE 4 step 2b) for 2/tcp crash_consistency. Build 6D51CDDF7ADB3947DCA880F (adds P17-CLOBBER-DROP detector), dirwr=1 dirskip=0.

## THE SMOKING GUN (P17-CLOBBER-DROP, pal/linux/xfs_buf.c after P35E): during the create-only workload a dir DATA block's dirent count is monotonic non-decreasing, so any durable write with nent < the max previously written to that daddr = a stale-base clobber. Fired on BOTH nodes, daddr=496 owner=131:
- test1: `nent=22 < prev_max=24 lseq=94 wseq=94 in_ail=1 comm=kworker/u10:13` names=[. .. node1_f1..node1_f20] — the BAST RELEASE-DRAIN (mxfs_dir_flush_data_blocks runs in the bast kworker) durably wrote block 496 with ONLY node1's entries, DROPPING node2_f1/node2_f2 that a prior nent=24 write held.
- test2: `nent=23 < prev_max=24 ... comm=xfsaild/sda` names=[. .. node1_f1..f20 node2_f1] — xfsaild durably wrote a stale 496 dropping node2_f2.

## INTERPRETATION: a node re-acquires dir-EX holding a CACHED block 496 that carries its OWN un-written logged mods (undest=1, wseq<lseq) but is MISSING the peer's committed entries. The refresh keep-guard (mxfs_dir_evict_data_blocks ~2043: skip evict when in_ail && undestaged) correctly refuses to discard the node's own un-written work — but that base never adopted the peer's entries. The node then DURABLY FLUSHES that stale base (via the release drain kworker OR xfsaild) over the peer's durable block -> peer's dirents durably lost. Both write vectors observed. Confirms [[sess17-HEAD-shared-dirblock-staleflush-wseq0]]; the continuous-churn trap [[sess10-gpt-verdict-serialize-tenure-not-epoch]].

## DETECTOR CAVEAT: P17 keys the per-daddr max table on (daddr, owner-ino) ONLY, not i_generation. ino 131 is REUSED every probe iter (rm-rf+remkdir), so prev_max can leak across iters → a fresh iter's smaller 496 could false-positive. BUT the captured names prove it real WITHIN an iter (drop of node2_f1/f2 while node1_f1-20 present = this iter's files, peer's entries specifically dropped). To harden: add i_generation/incarnation to the table key.

## THE FIX (GPT demote-drain-by-ownership, the sound path sess16 HEAD identified): make EX RELEASE the serialization barrier — after flushing ALL modified dir DATA blocks durable (currently mxfs_dir_flush_data_blocks fires P-RELFLUSH only ONCE = flushes just block 496, NOT every modified block; verify it covers all), INVALIDATE them from cache (xfs_buf_stale / clear XBF_DONE only AFTER confirmed-durable per sess33 invariant) so the NEXT acquire cold-reads the peer's durable image. Then the acquire-side undest keep-guard is unnecessary (a properly-released tenure leaves NO undestaged dir blocks), so cold-read adopts peer entries without a block-level 3-way merge. ALTERNATIVE (harder): true block-level 3-way dirent merge (analogue of sess14 shortform sf_merge) at acquire when base is undestaged AND peer advanced gen. RISK: clearing XBF_DONE on non-durable buffer corrupts (sess33); the flush-then-invalidate ordering must be strict.

## STATUS: `./run.sh 2 tcp` = 15/16, crash_consistency SOLE fail (flaky in-suite; passes isolation). Marker NOT written. Reproducer tests/cc_blockdir_probe.sh (fails ~iter 5-14, dirwr=1). Build 6D51CDDF deployed both nodes. [[sess17-HEAD-shared-dirblock-staleflush-wseq0]] [[sess17-detector-refutes-enforce-and-cc-flaky-pass]]
