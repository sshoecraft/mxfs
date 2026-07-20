---
name: sess28-SMOKINGGUN-EXholder-destages-stale-inAIL-base-bgen0-mergeneeded
description: sess28(ccloop) SMOKING GUN: dir_reuse loss = the dir EX-HOLDER destages a stale in-AIL block (held_mode=EX, in_ail=1, dirty=0, bgen=0) carrying its o…
metadata:
  type: project
---

## sess28 — THE write-side mechanism, proven from saved failure dmesg (P-WMERGE + held_mode)

### Decisive evidence (build C1B4BFC0, dir_writeprobe=1, /root/drc_failverify_r10_rank*.dmesg — survives ring rotation)
EVERY clobbering dir-DATA write at the bio chokepoint:
`P-WMERGE owner=131 daddr=... disk_extra>=1 incore_extra=1 held_mode=5 in_ail=1 dirty=0 bgen=0 kind=data — MERGE-NEEDED`
(held_mode=5 == MXFS_LOCK_EX; enum NL=0,CR=1,CW=2,PR=3,PW=4,EX=5). test8: disk_extra=154 incore_extra=1 (one write about to revert 154 peer entries). test1 daddr=120: a few pure-stale (incore_extra=0).

### THE MECHANISM (byte-exact, reconciles diff1=0 read-coherent + write-side loss)
The dir EX HOLDER destages a STALE in-AIL block:
- held_mode=EX -> the holder STILL holds EX at destage (it RE-ACQUIRED since this block was modified).
- in_ail=1, dirty=0 -> the block's mods are COMMITTED (in AIL) but NOT yet destaged.
- bgen=0 -> the block's base is a PRIOR tenure (b_mxfs_dir_gen=0, acquire-evicted/never-restamped = stale).
- incore_extra=1 -> the holder's OWN add (from tenure T1) is in the block.
- disk_extra>=1 -> a PEER added entries (in tenure T2, while the holder had released EX) that the holder's stale in-AIL base never saw.
Sequence: holder adds A in T1 (commits to AIL, base coherent at addname = diff1=0) -> holder RELEASES EX -> peer adds B in T2 (durable on disk) -> holder RE-ACQUIRES EX (T2', held_mode=EX) -> xfsaild destages the T1 in-AIL block (base + A, missing B) -> OVERWRITES disk (base + B) -> peer's B durably LOST. The read was coherent at addname (diff1=0); the staleness is that the in-AIL block's BASE went stale between commit and destage.

### WHY existing guards miss it
- ex_guard / P12-DIR-EXGUARD: gated on dir_NOT_held_ex -> holder HOLDS EX -> skipped. (sess22 flagged exactly this.)
- acquire-side drain_evict: KEEPS in-AIL-UNDESTAGED blocks (sess101: can't evict our own committed-unwritten work) -> the stale-base in-AIL block survives reacquire -> destages stale.
- subset suppression: drops it -> SHUTDOWN (pure-stale) or readdir=316 (drops legit merge-needed). REFUTED.

### THE FIX (next session): re-apply the holder's in-AIL delta onto the CURRENT disk base
The holder's T1 add (A) is legit and must be preserved; its base is stale (missing B). The block must be written as base+A+B (3-way merge), NOT the stale base+A. Two viable sites:
1. **At REACQUIRE (preferred, transaction context)**: when the holder reacquires EX and finds an in-AIL-undestaged dir DATA block with bgen<dir_gen (stale base), read current disk, and within a transaction RE-LOG the holder's delta (A) onto the fresh disk base (base+B) so the leaf/freeindex hash blocks are updated coherently too (a data-only graft fails the test's lookup_fail check — leaf hash not updated). This is the data-block analogue of the SHORTFORM 3-way merge in mxfs_dlm_reload_inode.
2. At write chokepoint: graft disk_extra (peer adds) into in-core before write — BUT only fixes readdir (data block); lookup_fail persists (leaf hash not updated cross-block, no txn). Insufficient alone.
NOTE: for dir_reuse (ADD-only) a naive union (graft disk_extra) is loss-safe (no removes to resurrect), but lookup needs the leaf updated -> reacquire-site txn re-apply is the correct universal fix. Capturing the base/delta: the holder's delta IS in the buffer's BLI logged regions, OR snapshot the pre-modify base per dir-data buffer at first xfs_trans_log_buf.

### Keeper C1B4BFC0 (all levers off). See [[sess28-HANDOFF-head-build-C1B4BFC0-next-step-3way-merge]] [[sess28-DECISIVE-loss-is-writeside-read-coherent-diff0-p28c0]] [[sess22-GPT-fix-design-freeslot-doublealloc-readdir799]] [[sess101...]].
