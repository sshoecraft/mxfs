---
name: sess37-drc-real-root-is-stale-block0-leaf-RMW-not-datainit
description: sess37 dir_reuse 2/tcp: P31E datainit clobbers are BENIGN (prior-incarn reuse, on-disk inode shortform). REAL root = stale block0/leaf RMW (P34-TRYLO…
metadata:
  type: project
---

## sess37 — dir_reuse_coherency 2/tcp: REAL root re-characterized (RULE 4)

Criterion = full `./run.sh 2 tcp` 17/17; dir_reuse_coherency is the sole failing test. TIMING is
solved (MHT=300). This is the CORRECTNESS face. Build base this session: 4734B03F (P31E/P31F instr)
→ 92F442C7 (bounded-retry fix, instr gated off).

### MAJOR COURSE CORRECTION: the P31E/P31F "datainit clobbers" are BENIGN.
sess31-36 chased `xfs_dir3_data_init` zeroing block-0 (P31E-DATAINIT-ABA) as the "proven root". This
session added `caller=%pS` + `P31F-BMAP` (in-core extent map vs coherent plain-read of on-disk inode).
DECISIVE: at EVERY clobber the **on-disk INODE 131 is SHORTFORM/small** (`disk_fmt=1 disk_nx=0
disk_size=6` for sf_to_block; `disk_nx=2 disk_size=4096` for leaf_addname) with `disk_gen==incore_gen`.
So the block being zeroed is **NOT part of the current durable dir** — it's a **prior-incarnation
freed-block leftover** (dir is rm-rf'd+recreated each round reusing inode#131 + daddrs; freed dir
blocks keep old dirent bytes, never zeroed). The test **PASSED once with 31 P31E fires** → benign.
Callers: `xfs_dir2_sf_to_block+0x1fe` (block 0) and `xfs_dir2_leaf_addname+0x605` (block 1). The
recurring `first_name="node2_f50.md5"` / `live_dirents=16` are leftover bytes, not live current data.
→ P31E/P31F now GATED behind `mxfs_instr_enabled` (their synchronous plain-reads PERTURB timing and
MASK the race — a heisenbug: extra latency flips the test PASS).

### REAL ROOT: stale cached block-0 / leaf-block RMW lost-update (P34-TRYLOCK-STALE).
The actual failure modes (FLAKY, vary per run): (a) DATA loss — `readdir=182/184/188`, missing
node1_f1..fN **contiguous first files** (block-0 dirents); (b) LEAF-HASH loss — `readdir=200
lookup_fail=4` STUCK on node1_f47..50.md5 (leaf hash entries gone, data present). BOTH nodes agree
(durable on-disk). Mechanism: the read-time dir-block invalidation hook (`xfs_da_read_buf`,
xfs_da_btree.c ~3101) uses `xfs_buf_incore(..., XBF_TRYLOCK, ...)`; on `-EAGAIN` (buffer locked) it
SKIPS invalidation and serves the STALE cached buffer → an RMW on that base durably erases the peer's
committed dirents (block 0 → first-N lost) or leaf-hash entries (leaf blk=8388608 → node1_f47-50.md5
lost). PROVEN: **P34-TRYLOCK-STALE fired 64×/29× on blk=0 daddr=120/112 AND blk=8388608 (leaf)**.

### Bounded cond_resched retry REFUTED (RULE 4 step 2a).
Added a 64× `cond_resched()` retry loop on -EAGAIN in the read hook → `P34R-RETRY-OK = 0` (NEVER
recovered); P34-TRYLOCK-STALE still 24/68. So the buffer is held PERSISTENTLY for the whole window
(self-lock, or node's own delwri/AIL writeback of the STALE block 0 in flight), OR cond_resched
returns immediately (no real wait). Waiting in the read path is the WRONG locus.

### NEXT (next session): fix at EX ACQUIRE, not at read.
The modify happens under the dir-inode EX; the stale base should be invalidated at slow-path ACQUIRE
(no concurrent self-modify, blocking documented-safe per sess97) — the eager evict
`mxfs_dir_drain_evict_data_blocks` (xfs_mxfs_dlm.c ~3198) uses TRYLOCK + CLEAN-only + lacks ABA
bypass, so it skips the stale block 0/leaf. Plan: at acquire, force-invalidate ALL the dir's cached
DATA+LEAF blocks (block 0 + leaf at o8388608) so the tenure starts coherent. Watch for the sess64
PINNED-buf re-read shutdown (must keep pin guard). Re-run drc_cap2.sh (instr off) ≥3× for a reliable
PASS, then full `./run.sh 2 tcp`=17/17. Tools: tests/drc_cap2.sh + grep P34-TRYLOCK-STALE/drc-FAIL.
Marker NOT written. [[sess36-PROVEN-datainit-zeroes-live-block0-root]] [[sess36-correctness-aba-dirblock-clobber-fix-plan]]
