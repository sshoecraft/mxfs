---
name: sess44-FINAL-bug-is-acquire-side-stale-read-dlm-serializes-correctly
description: sess44 FINAL triangulation: P44-MODGRANT proves the DLM serializes correctly (all 38394 modifies at mode=EX held=1, monotonic realns, NO double-grant…
metadata:
  type: project
---

## sess44 (ccloop) FINAL — triangulated: the bug is ACQUIRE-side stale read; DLM serialization and release durability are BOTH proven correct/sufficient

### P44-MODGRANT probe (build C532B4BF→keeper 3062493A, gated behind instr): at every modify of the storm dir (ino=131) log (i_dlm_mode, mxfs_v5_dlm_inode_held=ACTUAL grant, i_dlm_ex_holders, i_dlm_stale, i_dlm_epoch, ktime_get_real_ns wall-clock, comm).

### RESULT (clean reboot, FAIL run, round3 lost node7_f32/f41/f42.md5 + node8_f25.md5): ALL 38394 modify events = `mode=5(EX) held=1 exh=1`. ZERO mode=EX-held=0 (the sess42 cached-EX stale-grant). Cross-rank realns are MONOTONIC (sorted) with clean ~60-event per-rank bursts; the only "interleave" (R3/R5 alternating at a tenure boundary) has realns DELTAS of 1.8–5.8ms = legitimate rapid EX HANDOFF (network-RTT scale), NOT sub-RTT concurrent modify. MXFS_LOCK enum: NL=0,CR=1,CW=2,PR=3,PW=4,EX=5 (so 5=EX confirmed).

### CONCLUSION (RULE 4, triangulated by elimination — all three legs proven):
1. **DLM serializes correctly** — every modify under a genuine, exclusively-held EX grant; no two nodes modify ino=131 at overlapping wall-clock. REFUTES double-grant / cached-EX-stale-grant / MHT-window concurrency (sess42's deeper-root hypothesis).
2. **Release durability is sufficient** — a whole-AIL push-to-completion before unlock (all AGs) STILL loses an entry [[sess44-DECISIVE-release-completeness-not-the-gap-bug-is-acquire-or-concurrency]]. REFUTES the 40-session release-drain-gap focus.
3. **∴ the loss is ACQUIRE-SIDE**: a node acquires a fresh EX grant, but its first addname reads its OWN STALE CACHED dir-data buffer (from a prior tenure) instead of the peer's just-released image, computes a free byte-offset from the stale bestfree, and writes its dirent at an offset a peer already used → intra-block double-alloc [[sess44-PROVEN-offset-collision-double-alloc-aoff1600-four-dirents]].

### THE ACQUIRE-SIDE HOLE (code, for next session): `xfs/libxfs/xfs_da_btree.c` ~3216 — the read-time dir-buffer revalidation is gated `((!owned_ex && dp->i_dlm_dir_gen != 0) || mxfs_ex_reval)`. During addname we HOLD EX (owned_ex=true) → revalidation SKIPPED → the cached (stale prior-tenure) buffer is served as the RMW base. The keeper relies on `mxfs_dir_newtenure_evict` (default ON, xfs_mxfs_dlm.c ~3932) to force-evict+cold-read the stale base at the first modify of a new tenure (epoch advance) — but the loss persists, so it UNDER-FIRES (epoch/gen not advancing on every handoff, or the evict races the rapid ~2-6ms handoffs, or it evicts only CLEAN buffers and the base is the node's own in-AIL buffer).

### NEXT (RULE 4): instrument `mxfs_dir_newtenure_evict` / the EX-acquire path — at the FIRST addname after acquiring EX on ino=131, log: did newtenure_evict fire? what was the cached dir-data buffer's gen/epoch vs the inode's? was it cold-read or served-cached? Then make the EX-ACQUIRE cold-read RELIABLE and ATOMIC across data+leaf+freeindex (per-block invalidation CORRUPTS — leaf-hash vs data-entry desync, REFUTED sess44 dir_coherent_modify + sess40 dir_refresh_inplace). The safe primitive: at EX grant (new epoch), BEFORE any addname, invalidate+cold-FUA-read the WHOLE dir fork (all data+leaf+free blocks together) so bestfree is computed from the peer's image. Caveat: must handle the node's OWN in-AIL buffer (now durable since release is complete — so eviction IS loss-safe, unlike when release was suspected incomplete). Build 3062493A = keeper (P44 probe gated behind instr/dirwr; all sess44 levers default-off; == baseline 5F0C1457 for 1/2/4; 2/tcp dir_reuse PASS). Tools: P44-MODGRANT (instr=1), P13-NADD/LADD offset trace, DRC_STREAM=1.
