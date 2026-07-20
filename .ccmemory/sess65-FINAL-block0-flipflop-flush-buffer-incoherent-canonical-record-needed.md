---
name: sess65-FINAL-block0-flipflop-flush-buffer-incoherent-canonical-record-needed
description: sess65 FINAL: node1_f1 root = dir inode-131 extent[0] FLIP-FLOPS (fsb 15/262153/6291465) across nodes+time; node1_f1 durable in block0=120 but reader…
metadata:
  type: project
---

## sess65 FINAL — node1_f1 root fully isolated; needs a DURABLE canonical block0 record

### Decisive evidence chain (this session)
1. node1_f1 is DURABLE in dir block0=daddr=120 (fsb=15, AG0): P64-N1F1 present=1 on EVERY write to daddr=120, NEVER present=0. It is NOT content-clobbered.
2. rank1's sf->block conversion base HAD node1_f1 (P62-SF2BLK names=[node1_f1...). Conversion doesn't drop it.
3. The loss is the dir INODE-131 data-fork extent[0] (logical block0 -> physical fsb) being INCOHERENT: P-DIRIFLUSH ino=131 shows test1 flushing extent[0] as fsb=15 (1631x), fsb=262153 (204x), fsb=6291465 (322x) — the SAME node publishes 3 DIFFERENT block0s over the run. Readers whose cold-read dinode has extent[0]!=15 read a block0 lacking node1_f1 -> miss it. So it's an extent[0] FLIP-FLOP, not content loss.
4. Multiple block0s (15/262153/6291465 = daddr 120/2093296.../50M...) exist because nodes each converted sf->block in their node-affine AG across rounds; the inode extent[0] never stabilizes to one.

### Why the fixes tried this session can't converge it
- **dir_epoch_adopt=1**: makes a node adopt whatever disk's extent[0] currently is on a post_release reload — but disk flip-flops, so nodes follow the flip-flop. Partial convergence only.
- **dir_iflush_fence=1** (lowest-block0-wins, skip flush when incore_b0>disk_b0): fired 0x. ROOT obstacle: at iflush the comparison uses the LOCAL cached dinode cluster buffer (dip), which is NOT cross-node coherent — each node's local buffer matches its own in-core block0, so divergence is invisible at flush time. A correct fence needs a FUA disk read of the true dinode in xfsaild/iflush context = deadlock-prone (cluster buffer lock + SCSI path) + ~2000 reads/run perf hit (RULE 0). Build 283EE4CF carries the fence gated OFF + P65-IFLUSH-FENCE probe.
- **dir_merge / force_block default ON**: corrupts 2/tcp (reverted).
- **pending-dirent replay**: timing gap (loss observed only at cold-read, no tx).

### THE FIX (GPT-5.5 option C, now clearly required): a DURABLE, cluster-visible, WRITE-ONCE canonical block0 record per dir incarnation. The dir inode extent[0] alone is insufficient because (a) flush-time cluster-buffer cache is incoherent and (b) multiple conversions race. Implement: at FIRST sf->block conversion (holding dir EX), allocate block0 AND log a canonical record {dir_ino, di_gen, block0_fsb} atomically (a small logged item / hidden btree / reserved field) + mirror in the DLM LVB. Every later converter/modifier reads it (LVB fast-path, durable record authoritative) and REUSES that exact fsb (adopts) instead of allocating a new block0. iflush must refuse to publish extent[0] != canonical. No extra DLM acquire (already hold EX); no inline orphan free.

### SAFE BASELINE: build 283EE4CF = all new module params default OFF (dir_iflush_fence, dir_epoch_adopt, dir_pending, dir_merge, dir_force_block, dir_adopt_block) = baseline behavior. Probes retained: P65-IFLUSH-FENCE, P65-EPOCH-ADOPT, P64-N1F1, P-DIRIFLUSH, P62-REL-DIREXT, P42-SFCONV. node1_f1 still lost (4/tcp 0/4 every round; 2/tcp intermittent). Criterion NOT met.
See [[sess65-HANDOFF-two-stage-node1f1-extent-split-then-content-clobber]] [[sess65-CORRECTION-epoch-adopt-only-partial-convergence]] [[sess64-DECISIVE-ROOT-node1f1-orphaned-in-double-allocated-block0]].</body>
