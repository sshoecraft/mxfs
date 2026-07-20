---
name: sess42-DECISIVE-clean-round19-block0-double-alloc-at-sf-to-block
description: sess42 DECISIVE (clean dmesg, round19): dir_reuse loss = CROSS-NODE double-alloc of logical-block0 at shortform->block conversion. node1 ALWAYS fsb=1…
metadata:
  type: project
---

## sess42 DECISIVE — dir_reuse_coherency 2/tcp loss = cross-node double-alloc of dir LOGICAL BLOCK 0 at the shortform->block conversion

### Captured with the FIXED dmesg harness (no ring-buffer confound — see [[dmesg-follow-ringbuffer-staleness-trap-drc-cap2-fix]]). Build E8C6B4B6 (held-check fix). Round 19 FAILED, both nodes cold-agree readdir=186/200, missing node1_f1..f14 (block0).

### THE DECISIVE NUMBERS (whole clean run, P-DIRIFLUSH ino=131 incore_blk0_fsb):
- node1 (test1): **3000x fsb=15, ZERO fsb=14**. node1's logical-block0 is ALWAYS physical fsb=15 (daddr 120).
- node2 (test2): fsb=15 (38x, adopts node1's) + **fsb=14 (19x, DIVERGENT, daddr 112)**.
- ⇒ Both nodes allocated the dir's LOGICAL block 0 to DIFFERENT physical blocks: node1->fsb=15, node2->fsb=14. node1 NEVER adopts node2's fsb=14; node2 only SOMETIMES adopts node1's fsb=15. At verify the home dinode's logical-0 points at whichever flushed last (node2's fsb=14) -> node1's fsb=15 block (with f1..f14) is ORPHANED -> lost. lookup_fail=0 (leaf hash still maps names to logical-0).

### ROUND-19 node2 SEQUENCE (clean ts 30153-30160):
1. P95-SAMETYPE-RELOAD ino=131 incore_gen=3672887664 disk_gen=541623489 — node2's cached in-core is the PRIOR incarnation; adopts new empty dir (rm reuse). OK.
2. P62-RELOAD ino=131 incore block-fmt nx=3 -> disk shortform-empty size=6 (rm). Then empty size=6.
3. **6s STALL**: P36-RETRY ino=131 mode=PR retries_left=59..55 (x5) then P34-ACQ-SLOW dur_ms=5995. P-CONVBLK-DENY ino=131 held_mode=PR req_mode=EX -> EDEADLK (BOTH nodes hold PR + want EX = classic PR->EX conversion deadlock; DLM denies one). This is a RESIDUAL ~6s handoff stall the held-check fix did NOT remove (different path: PR->EX upgrade deadlock, not phantom-PR). RULE-0 concern.
4. P62-RELOAD ino=131 incore shortform-empty -> disk block-fmt nx=1 size=4096. node2 "adopts" a 1-block dir — but its block0 is fsb=14 (P-DIRIFLUSH right after: incore_blk0_fsb=14; P34-TRYLOCK-STALE blk=0 daddr=112=fsb14). So the block0 node2 ends up with is fsb=14, NOT node1's fsb=15.

### REFUTED THIS SESSION: double-grant (P-DOUBLEGRANT=0, P-STALEMASTER-GRANT=0 — DLM mutual-exclusion SOUND); release-durability of the dir dinode (build C5BD4E04 forced inode-cluster durable for block/leaf dirs at release -> STILL diverged, only +30x iflushes; REVERTED). So the loss is SERIAL (not concurrent) and not a release-flush gap.

### MECHANISM (best model): node A (rank1=node1) converts shortform->block under EX, allocates logical-block0 at fsb=15, commits to LOG/CIL. node B (node2) acquires EX serially but its reload reads a STALE base (home dinode still shortform-empty because A's conversion is in the log not yet checkpointed to the home block, OR node2's own cached cluster buffer is kept by P91-RELOAD-PROTECT), so B does NOT see A's block0 and CONVERTS AGAIN, allocating logical-block0 at fsb=14. Neither node's reload reconciles to the other's block0 -> stable 14<->15 split. (P91-RELOAD-PROTECT fired for ino=0x83 but correlation was confounded by ring-buffer in the C5BD4E04 run; re-check on the clean E8C6B4B6 logs.)

### NEXT FIX CANDIDATES (RULE 4): 
1. Prevent the SECOND shortform->block conversion: before xfs_dir2_sf_to_block (xfs/libxfs/xfs_dir2_sf.c / xfs_dir2_sf_addname overflow path) allocates block0 for a SHARED multi-node dir, FUA-verify the on-disk dinode format; if it is ALREADY block-format (peer converted), force reload+adopt the peer's block0 and append, do NOT allocate a rival block0.
2. Make node B's EX-acquire reload AUTHORITATIVE: defeat P91-RELOAD-PROTECT (xfs_mxfs_dlm.c ~6273) for the dir-inode reuse case so it FUA-reads node A's committed block-format home dinode (the protect guard keeps node B's stale cached cluster -> empty base -> re-convert).
3. Separately fix the residual 6s PR->EX conversion deadlock (P-CONVBLK-DENY / P34-ACQ-SLOW dur_ms~6000) for RULE 0.
Tree: E8C6B4B6 = baseline + held-check stall fix (KEEP, [[sess42-FIX-held-check-mode-blind-false-negative-PR]]). See [[sess42-ROOT-dir-block0-divergent-alloc-dinode-not-durable]].
</body>
