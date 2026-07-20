---
name: caw-4node-cache_coherency-SESSION3-SUMMARY-START-HERE
description: START HERE (ccloop sess3): 4/caw cache_coherency = cross-node double-alloc of shared block-fmt subdir block (agbno9/AG). bnobt+dir fences present+per…
metadata:
  type: project
---

## ccloop sess3 SUMMARY — 4/caw cache_coherency (START HERE for the relay)

Criteria: 1/2/4/8/16/32 node caw dlm multipath 100%. Blocker analyzed this session: **4/caw
cache_coherency (and zero_silent_loss) FAIL 0/4**. Full chain of memories (read in order):
[[caw-4node-cache_coherency-ROOT-bnobt-doublealloc-NOT-prfence]] →
[[caw-4node-doublealloc-current-code-state-and-next-probe]] →
[[caw-4node-doublealloc-fable-design-fix-freelist-choke]] →
[[caw-4node-doublealloc-REFINED-3faces-aglow-probes-and-fix-plan]] → this.

### THE BUG (proven, instrumented, RULE-4)
The 4 cache_coherency SUBDIRS (cross_visibility/cross_write_read/rename_visibility/unlink_visibility)
are each created by whichever node WINS the mkdir race → each subdir's inode + its BLOCK-FORMAT dir
block (agbno 9 of that node's affine AG) is SHARED and RMW'd by all 4 nodes. A FILE's data block
(.md5 / .txt content) gets ALLOCATED the same agbno-9 block the subdir holds → file write clobbers
the dir block → dir3 read-verify fails (CRC/struct) → FS force-shutdown → all reads EIO → 0/4.
3 faces: pure-file-data double-alloc / undurable-garbage(owner=0) / torn-RMW(valid XDB3 wrong CRC).
NOT PR-fence, NOT a coherency regression (sess2 misdiagnosis corrected).

### RULED OUT this session
- DLM bypass: AG-DLM held at choke (xfs_alloc_vextent_prepare_ag→fix_freelist for alloc;
  xfs_free_extent_fix_freelist for free). All 5 vextent wrappers incl. delalloc-writeback's
  start_ag route through xfs_alloc_vextent_finish (verified).
- Pristine-snapshot (Fable's a): agf_freeblks=261635/261653 (18 used, NOT pristine) at agbno-9 alloc.
- Acquire-side AGF refresh (Fable's a′ / #2): ALREADY PRESENT — mxfs_ag_meta_coldread_discard
  (xfs_mxfs_dlm.c:21206) stales clean bnobt/cntbt/AGF/AGI/inobt/finobt on fresh grant (sess16 filter);
  discards destaged in-AIL bnobt/cntbt (sess121/P121). So AGF IS refreshed on fresh grant.
- Owner-side bnobt durability: P80-INSTR (bwrite-then-FUA-readback disk_differs) did NOT fire → bnobt
  bwrites persist to medium. dir_release_fua_write=1 forces dir blocks to platter (LIO/SCST drop
  REQ_FUA/PREFLUSH); dir_addname_coherent=1 acquire-side FUA-reread guards intra-block dirent dbl-alloc.

### PRIME SUSPECTS NOW (the double-alloc is CROSS-NODE within a shared subdir's AG:
e.g. test1 writes a file into cross_write_read whose dir block is in test2's AG1 at agbno9)
1. **Fable (d) transient CONCURRENT-EX via CAW last-write-wins CAS**: two nodes both believe they hold
   the AG EX (popcount>1 auto-repaired by slot_appears_corrupt before mxfs_v5_dlm_ag_held sees it —
   see xfs_alloc.c:2204-2214 note). Both cold-read the LUN bnobt (agbno9 free), both allocate agbno9.
2. **Owner-durability RACE**: node A allocates agbno9 for the dir (in-core), node B fresh-acquires AG
   and cold-reads BEFORE A's release-drain made the bnobt durable → B sees agbno9 free, allocates the
   file there. (Acquire fence + owner fence each look correct in isolation but the WINDOW between A's
   in-core alloc and A's durable-release may not be closed for a concurrent B acquire.)

### DECISIVE NEXT EXPERIMENT (RULE 4) — do this FIRST next session
Add an un-gated **tenure/DLM-holder ledger** for the agbno-9 collision: at every AG grant/yield AND at
the P-AGLOW-ALLOC/free of agbno9, log (node_slot, agno, DLM mode, ag_dlm_tenure_id, raw CAW slot
popcount of EX holders WITHOUT the slot_appears_corrupt repair — add a dlm_caw helper that reads the
slot raw, per xfs_alloc.c:2211-2213). Run 4/caw cache_coherency ×3-5 to catch the file-data face. Then:
- Two EX holders on the same agno at the same time (popcount>1) → CONCURRENT-EX (d) → fix the CAW CAS
  exclusion (the transport double-grant), NOT the alloc path.
- Single EX holder but the file alloc's cold-read precedes the dir owner's durable release → durability
  RACE → close the acquire-before-owner-durable window (e.g. make fresh-grant coldread FUA-verify the
  bnobt leftmost record is not a block a peer is mid-allocating; or serialize via a per-AG alloc epoch
  in the CAW lock sector that the fresh grant must observe advanced).

### STATE
- Build B6F0D45F (srcversion B6F0D45F7657AE7B54F20C9) deployed: keeper behavior + light un-gated
  P-AGLOW-ALLOC/FREE probes (agbno<64) in xfs/libxfs/xfs_alloc.c. Remove probes before FINAL criteria run.
- Cluster: all 4 VMs booted but mxfs DOWN (shut down by last run). Next session: clean-reset
  (run.sh preps itself), then the ledger experiment.
- Matrix still-open for the criteria beyond this: 4/caw zero_silent_loss (same root), 32/caw
  dlm_scaling (perf, [[caw-32node-dlm_scaling-ROOT-shared-AG0-reread]]), plus untested cells
  (16/caw dir_reuse; many 32/caw). Fix cache_coherency FIRST (foundation).
- Fable consulted once (RULE 5 satisfied). A 2nd consult (Fable→GPT) only AFTER the ledger experiment
  pins (d) vs durability-race and a fix attempt is refuted.
</body>
