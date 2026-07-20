---
name: sess65-REFINED-loss-is-stale-cached-block0-RMW-even-single-conversion
description: sess65 REFINED root: dir double-conversion is INTERMITTENT (round2 yes, 3/5 no) but node1_f1 lost EVERY round — so single-conversion rounds still los…
metadata:
  type: project
---

## sess65 REFINED — node1_f1 loss is primarily a STALE-CACHED-block0 RMW (not just double-conversion)

### Decisive baseline measurement (build 621FD271, NO flags, 4/tcp)
Per-round P42-SFCONV ino=131 node count:
- round 2: test1=1 AND test3=1  (double conversion)
- round 3: test1=1 only
- round 5: test1=1 only
node1_f1 lost in EVERY round (4/4 fail). So in rounds 3/5 only ONE node converts (one block0, which HAS node1_f1) yet node1_f1 is still lost. => double-conversion is INTERMITTENT and is NOT the sole cause.

### Implication
The primary loss mechanism is a dir block0 CONTENT lost-update: even with a single canonical block0 (containing node1_f1), a peer RMWs block0 from a STALE CACHED copy (missing node1_f1) and writes it — the P64-N1F1 present=0 writes to divergent daddrs (8372968 etc.) seen earlier. This is the classic dir-DATA-block cache-coherency lost-update (sess17 union-merge / sess41 P-DATACLOBBER / sess97 i_dlm_dir_evicted_gen / sess79-90 family), NOT (only) the sf->block double-alloc.

### Why prior sess65 angles missed
All sess65 fixes targeted the extent[0]/block0 ALLOCATION (conversion serialization, lowest-block0-wins, iflush fence, epoch adopt). But the dominant cause is block0 CONTENT staleness on the RMW READ side. P58 ex_pop fired 0x (no concurrent-EX double-grant via the self-skip path).

### NEXT SESSION — two coupled bugs, fix the CONTENT one first:
1. **(primary) dir block0 content RMW reads a stale cached block** → ensure every dir-block RMW FUA-re-reads the current on-disk block0 when a peer may have modified it (i_dlm_dir_gen/evicted_gen coherency at the create's read of block0). Verify with P64-N1F1: after fix, block0 writes should ALL be present=1. Candidate: the read-time dir-block invalidation (xfs_da_read_buf, sess-tcp v0.4.7 gen-invalidation) is missing/ineffective for the create RMW path under inode reuse.
2. **(secondary) intermittent sf->block double-alloc** (round 2) → the DLM canonical-block0 record (docs/canonical_block0_fix_plan.md).

### SAFE BASELINE: srcversion 621FD271 = all sess65 module params default OFF; xfs_iops.c pristine; pal.md updated. Criterion NOT met. See [[sess65-CHURN-block0-daddr-instability-plus-stale-base-writes]] [[sess65-convgate-0x-epoch-prelock-cant-serialize-conversion-need-dlm-record]] [[sess65-GPT-design-pending-dirent-replay-fixes-node1f1]].</body>
