---
name: sess123-tenure-id-FIXED-agi-corruption-now-starvation
description: sess123 (ccloop): tenure_id fix (build FA1D1C0D) ELIMINATED the 12-session AGI unlinked-list corruption (P71/P117 gone on all 4 nodes). Remaining blo…
metadata:
  type: project
---

## sess123 — BREAKTHROUGH: tenure_id fix eliminated the AGI unlinked-list corruption

### Build FA1D1C0D3FA6E5BD4A34C52 — KEEP (verified correctness win)
Implements Gemini's DLM-tenure cache lifecycle (see [[sess123-tenure-id-agi-coherency-design]]), replacing the failed b_mxfs_ag_gen / mxfs_buf_is_undestaged() LSN preserve-vs-discard heuristics for AG-meta buffers. Five edits, all KEEP:
1. `xfs/xfs_buf.h`: added `u64 b_tenure_id` to struct xfs_buf.
2. `xfs/libxfs/xfs_ag.h`: added `u64 ag_dlm_tenure_id` to struct xfs_perag.
3. `xfs/xfs_mxfs_dlm.c` ~7036 (genuine fresh-CAW-acquire, P102-ACQ site): `pag->ag_dlm_tenure_id++` (NOT at reclaim paths 6786/6845/6868 — those keep the same tenure since the slot was never yielded / Invariant #1 not run).
4. `xfs/xfs_mxfs_dlm.c` top of `mxfs_ag_meta_invalidate_stale` (after dirty/in_ail computed, before the gen branches): **tenure guard** — `if (pag->ag_dlm_tenure_id && cbp->b_tenure_id == pag->ag_dlm_tenure_id) { xfs_buf_relse(cbp); return; }`. A current-tenure buffer is this-node-authoritative (we hold AG EX → no peer advanced disk) → NEVER discarded mid-tenure. Only PRIOR-tenure buffers fall through to the gen-based cold-read (preserves sess117 bnobt fix — prev-epoch drained artifacts carry old tenure id → still discarded).
5. Stamp `b_tenure_id = pag->ag_dlm_tenure_id` after each successful AG-meta read: `xfs_read_agi` (xfs_ialloc.c), `xfs_alloc_read_agf` (xfs_alloc.c), `xfs_btree_read_buf` (xfs_btree.c, AG-type only).

### PROVEN result (RULE 4, clean power-cycle+reset4, fua_disable=1 instr=0)
test_unlink_visibility: the P82-ADD→P117-discard→P71 NULLAGINO AGI corruption + force-shutdown is GONE on ALL 4 nodes (grep P71-INSTR/Metadata I/O Error/Corruption/EFSBADCRC = 0 on test1/test2/test4; test3's 2 hits are the DIFFERENT failure below, NOT AGI). This is the bug that blocked ~12 sessions (sess19/42/43/102/103/110/117/120/122). The sess122 "disable P110" resume plan was WRONG (P110 was a backstop masking this); P110 is left LOG-ONLY (harmless now).

### REMAINING BLOCKER (new top problem): parent-dir inode-EX STARVATION
test_unlink_visibility still FAILs, now purely on SLOWNESS:
- `unlink_30_files: avg=36284ms min=6274ms max=123174ms` (30 unlinks taking up to 123s).
- test3 shut down: `DLM inode lock unrecoverable: ino=135 mode=5 rc=-110 — shutting down` at mxfs_dlm_ilock_begin (xfs_mxfs_dlm.c:4356). rc=-110=ETIMEDOUT (120s CAW timeout) on the parent-dir EX inode lock.
- ino=135 = the shared `unlink_visibility` parent directory. dmesg shows a STORM of `P-EVICT-DISPATCH`/`EVICT-RING-DIRMOD ino=135` with gen climbing 67→76 in milliseconds = the parent-dir EX lock ping-ponging across all 4 nodes (each unlink needs EX to remove a dirent), throughput collapses, a node misses the 120s window → ETIMEDOUT → shutdown.

This is the SESS50-STARVE / CAW writer-starvation / slow EX-handoff family (see [[sess50_lessons]] defer_for_waiter, [[sess49_lessons]] slow barrier visibility). The slowness was always lurking BEHIND the corruption; now it's exposed. Per feedback [[feedback_timing_is_first_class]], this slowness IS a ship failure.

### NEXT (RULE 4)
Hypothesis: concurrent same-dir unlink → 4 nodes thrash the parent-dir (ino=135) inode EX lock; the eviction-ring dispatch + per-handoff drain overhead makes each EX handoff so slow that 30 unlinks take 100s+ and hit the 120s CAW timeout. Investigate mxfs_dlm_ilock_begin (xfs_mxfs_dlm.c:4356) EX-acquire path + the EVICT-RING-DIRMOD storm; whether defer_for_waiter (sess50) is engaged for inode locks; whether the per-handoff dir drain can be batched. Consider RULE-5 Gemini consult on EX-handoff fairness/batching if 2-3 attempts fail.

### Iteration rules (BINDING) — unchanged
- Power-cycle ALL 4 (`sudo virsh -c qemu:///system destroy+start`) → `INSMOD_OPTS="fua_disable=1 instr=0" bash tests/reset4.sh 4` → verify srcversion + dmesg -C → run subtest. test3 currently shut down → needs power-cycle before next run.
- Subtest: `MXFS_NODE_OFFSET=0 MXFS_TESTS_DIR=/src/mxfs/tests bash tests/run_tests.sh --nodes 4 --phase cluster --test test_unlink_visibility --pass-file /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`.

Related: [[sess123-tenure-id-agi-coherency-design]] [[sess50_lessons]] [[sess49_lessons]] [[feedback_timing_is_first_class]]
