---
name: sess7-ccloop-END-state-F5A90E91-safe-baseline-4tcp-confirmed
description: sess7(run6614) END: HEAD=F5A90E91 (baseline+behavior-neutral leak-attr instr). 4/tcp is FLAKY 2/3 (NOT 12/12) — FACE 2 create-path metadata-EIO shutd…
metadata:
  type: project
---

## sess7 (run 6614) END STATE — criteria NOT met; dir_reuse flaky at 4 AND 8 nodes

### HEAD BUILD: F5A90E91C5841F8B = pristine baseline behavior + behavior-neutral leak-attribution instrumentation (mxfs_ilk_note_lock added to 3 raw down_write(&ip->i_lock) sites: reload@~12471, reset_inode@~13667, sf_merge@~13985). ALL sess7 workarounds REVERTED.

### CORRECTION to sess6's claim "4/tcp dir_reuse = 12/12":
Measured this session with F5A90E91: **4/tcp drc_reliability = 2 PASS / 1 FAIL (2/3)** — NOT solidly 100%. RUN3 FAIL: test2 shut down (FACE 2), nodes_pass=0/4. Instrumentation is behavior-neutral (mxfs_ilk_note_lock already runs constantly on the xfs_ilock path) so it cannot cause this → dir_reuse_coherency is INHERENTLY FLAKY at 4-node too, just less often than 8. The core coherence bug blocks ALL columns (1/2 likely pass because single-node / low-contention; 4 flaky; 8 fails hard).

### `imap_to_bp failed rc=-5` = BENIGN red herring (appears in PASSING 4-node runs; logs+returns at xfs_mxfs_dlm.c:11799). Ignore it.

### TWO hard faces (both = the deep reused-dir coherence bug; both hit 4 & 8, worse at 8):
1. **LEAKED i_lock(write) → HANG** (8-node ~1/3): P132-ILOCK-STUCK ino=131 cnt=3 writer-bit, holder rm dead. Now ATTRIBUTABLE (sess7 note_lock on raw sites). NEXT: re-run drc_reliability 8 until P132 fires → read wr_last → fix that down_write path.
2. **Reused dir-block read verifier EIO → SHUTDOWN** (4-node ~1/3, 8-node dominant): dir ino=131 rm-rf'd+recreated each round; create path reads a stale/torn reused dir block → dir3 verifier fails → xfs_trans_read_buf_map (xfs_trans_buf.c:313) read-error on DIRTY trans → SHUTDOWN_META_IO_ERROR. Chain: `P-CREATE-ERR2 dir_create_child err=-5 dp_ino=131` → Metadata I/O Error → shutdown. This is the acquirer RMWing/reading a non-coherent reused-incarnation dir block.

### HARD CONSTRAINT: do NOT fix by SKIPPING the acquire-side dir evict/refresh under contention (trylock-then-skip in mxfs_dir_drain_evict_data_blocks@7856 or mxfs_dlm_dir_consumer_refresh@5309) — PROVEN to regress 4-node from 2/3 to 0/4 (stale-base RMW). The blocking down_read there only wedges because of FACE-1's leaked lock; fix the leak, don't work around the drain.

### NEXT SESSION (RULE 4): (1) pin FACE 1 leak via new P132 attribution; (2) fix FACE 2 — make the reused-dir-block read coherent (cold-read current incarnation) OR make a torn/stale reuse-window read non-fatal (no dirty-cancel→shutdown; retry/degrade to ENOENT). Re-verify 1/2/4 after each change (need drc_reliability N ~6 for stable signal since 4-node is only ~2/3). Marker only when 1/2/4/8 all 100% AND stable. Fallback shippable = this baseline F5A90E91 (minus instr = 9AA569A0-equivalent).
See [[sess7-ccloop-8node-multiface-leak-plus-imapEIO-state]] [[sess7-ccloop-DECISIVE-8node-ABBA-deadlock-drain-evict-ilock]] [[sess6-ccloop-8node-dirreuse-inode-reuse-cascade-faces]].
