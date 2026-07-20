---
name: sess45-WINNING-config-and-remaining-work
description: sess45 WINNING 8/tcp config: dir_release_fua_write=1 + dir_addname_coherent=1 + memb_settle_ms=20000 → 3/5 PASS (0 MASS), up from 0/5. Residuals: dir…
metadata:
  type: project
---

## sess45 WINNING CONFIG — the path to 8/tcp (READ FIRST next session)

### Build on disk: C074A836 = dir_release_fua_write=1 (DEFAULT, platter-lag fix)
+ membership beacon (dlm.c update_active_nodes "MXFS-MEMBERSHIP active_count")
+ run.sh convergence gate (prep waits all N nodes report active_count==N)
+ self-fence (v5_mount.c: stamp last_memb_change_ms on peer disconnect+reconnect).

### WINNING lever set (best result this session):
`dir_release_fua_write=1` (default) + `dir_addname_coherent=1` + `memb_settle_ms=20000`
→ 8/tcp dir_reuse **3/5 PASS, 0 MASS** (batch8_addnamecoh.log). HUGE: baseline was
0/5 (3 SINGLE 2 MASS); the whole 44-session blocker.
- dir_release_fua_write makes the PLATTER current (writer-side, validated 4/tcp 3/3).
- dir_addname_coherent (xfs_mxfs_dlm.c:5363, default 0) FUA-rereads the target dir
  block before the first add into a CLEAN block; invalidate+restart if in-core !=
  platter → prevents the PROVEN intra-block free-slot DOUBLE-ALLOC. It was refuted
  in sess28 ONLY because the platter LAGGED then (no writer-FUA); now complementary.
- memb_settle_ms=20000 (vs default 6000) eliminates the formation-ramp MASS split-brain.
Testing now (batch8_winning.log): + tcp_death_grace_ms=40000 over 8 iters to attack
the FLAP residual.

### TWO REMAINING 8-node residuals (the 2/5 fails):
1. **dirty-block double-alloc (SINGLE)**: dir_addname_coherent SKIPS dirty/in-AIL/
   pinned blocks (xfs_dir2_data.c:1636) — "never touch own dirty work". A
   dirty-stale-across-handoff block (sess61: bufgen < i_dlm_dir_gen, node kept a
   dirty stale block0 across a handoff) still double-allocs. The sess61 hard case:
   can't blindly refresh a dirty buffer in a live trans. NEXT: detailed-capture WITH
   addname_coherent=1 (tests/drc_detail8.sh "...dir_addname_coherent=1") to confirm
   the residual SINGLE still shows P13-COLLIDE on a DIRTY block, then extend the
   coherent reread to dirty-stale (bufgen<dirgen) blocks via drain-at-acquire (NOT
   mid-addname).
2. **host-load FLAP (MASS/empty)**: 8 VMs on clyde starve → TCP socket stall >grace
   → false death → split-brain. self-fence + memb_settle reduce but don't eliminate.
   tcp_death_grace_ms bump under test. May be partly environmental (oversubscribed
   host); the FUA-write/addname FUA add I/O load.

### MECHANISM PROVEN (tests/drc_detail8.sh, no instr):
P13-COLLIDE ino=131 daddr=14652640 off=2776 our=[node7_f8.md5] disk=[node8_f8.md5]
= node7 placed onto node8's durable dirent. NO doublegrant/stalemaster/flap → DLM
serialized; it is an ACQUIRE-SIDE stale-IN-CORE-base double-alloc (disk current via
FUA, in-core stale).

### NEXT STEPS (priority):
1. Read batch8_winning.log result (grace40 effect on FLAP + SINGLE rate).
2. If high pass-rate: make dir_addname_coherent=1 + memb_settle_ms=20000 (+grace?)
   DEFAULTS, rebuild, RE-VALIDATE 1/2/4 tcp (full suite — addname_coherent adds
   per-add FUA cost: watch RULE-0 slowness on rsync_paired/scaling at 2/4) + 8/tcp.
3. Extend addname_coherent to dirty-stale blocks for the SINGLE residual.
Harnesses: tests/drc_batch8.sh (dist), drc_detail8.sh (mechanism), drc_cap4.sh.
See [[sess45-BREAKTHROUGH-8node-loss-is-intrablock-doublealloc-addname-coherent-fix]]
[[sess45-RESURRECTED-platter-lag-fix-dir-release-fua-write-default-on]]
[[sess61-FINAL-dirty-keep-guard-in-drain-evict-is-the-gap]].
