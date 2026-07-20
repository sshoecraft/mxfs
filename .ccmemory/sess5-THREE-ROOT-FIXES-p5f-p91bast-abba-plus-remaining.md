---
name: sess5-THREE-ROOT-FIXES-p5f-p91bast-abba-plus-remaining
description: sess5: 3 ROOT FIXES landed+verified (P5F adopt-guard, P91-BAST-PROTECT strand fix, P5D ABBA breaker). Remaining: 1-dirent/9rounds loss + 27s/round pa…
metadata:
  type: project
---

# sess5 (ccloop a16ec5f2) — three proven root fixes, two remaining blockers

Build history: `0F5CD6D9`(start) → `5EEF85D0`(P5F) → `19E885B1`(P91-BAST) → `F560EC18`(AG probes) → **`6E8DFC0C` (current: +P5D ABBA fix)**. All fixes in-tree in xfs/xfs_mxfs_dlm.c + dlm/dlm.c + dlm/v5_mount.c.

## FIX 1 — P5F-FRESHSRC-SELFCLOBBER-SKIP (class-B dangler root #1) — VERIFIED
run29 t4 ledger, ino 8390566 "node4_f39": on the CREATOR, P107-PUBLISH acquire ran a reload; FUA-fresh read returned the platter's PRE-create FREED image (our IALLOC cluster write still in flight); P34D adopted it over the LIVE in-core inode → xfsaild flushed mode=0 back over the valid dinode (P4C-IFREE-WR) → create durably UN-created, dirent remains → permanent cluster-wide ENOENT dangler. FIX at xfs_mxfs_dlm.c ~12760: extend sess52's dir-only guard with the P116 discriminator (fresh image FREE + in-core allocated + (pinned||ili_fields||in-AIL||i_dlm_mode!=NL) ⇒ keep protected buffer). Fired+worked in run30 (1×), 0 self-clobbers since.

## FIX 2 — P91-BAST-PROTECT (iflush-strand wedge root) — VERIFIED
run30 t7 ino 8388770: P113-DRAIN-WEDGE iflushing=1 lb_flags=0x50(ASYNC|STALE) lb_onlist=0 rescued=0. The BAST-path cluster-buffer stale (xfs_mxfs_dlm.c ~9333) was UNGUARDED: staling a cluster buffer with attached committed-not-written co-resident ili (255 li_empty=0 fires/run) → delwri walker drops it unwritten → IFLUSHING orphaned in AIL forever (P136 rescue can't requeue STALE bufs) → creates never destage → readers see mode=0 (dangler #2) → multi-second BAST drains → cascade. FIX: apply mxfs_buf_has_uncheckpointed_mods guard (same as iget-miss/recycle/reload twins). run31+: P113=0, P91-BAST-PROTECT ~170×/node, lookup_fail dangler GONE.

## FIX 3 — P5D-PREWAIT-DEFERRED-BAST (create-vs-create ino↔AG ABBA) — VERIFIED run34
run31/33 timelines: T7 dd holds dir-131 DLM EX + blocks in xfs_dialloc on AG-4 (P1-AGWAIT stack, trans_dirty=0); its dp BAST is DEFERRED to xfs_trans_free by mxfs_dlm_ilock_end Approach-A (journal_info set) — so the v0.3.148 ILOCK drop never made the dir yieldable. T6 dd holds AG-4 (trans-deferred unlock) + blocks re-locking dir-131. Both retry 60×1.02s → AG side -110 (v5_mount.c:1595) → xfs_create dirty-cancel → SHUTDOWN → dead node → readdir=0 + drc-FAIL 704/800 cascades (runs 30/31/33 all this family; rank2/3 "dirino=" empty = shutdown node). FIX at __mxfs_ag_dlm_lock slow path (~19500): before BLOCKING on peer-held AG, if current trans CLEAN (!XFS_TRANS_DIRTY) and t_mxfs_inode_unlocks non-empty → mxfs_trans_drain_inode_unlocks(dtp) fires the deferred BASTs (dir hands off; Mode-A safety preserved because only clean trans). run34: 0 shutdowns, 0 -110, P5D fired 0× (nb-probe path dodged; fix is the backstop).

## AG-handoff instrumentation added (ungated, ratelimited): P5B-AGBAST-SEND (v5_mount.c send), P5R-AGREL/-ENOENT/-STALEGEN (dlm.c master), P5U-AGUNLOCK/-ENOENT (dlm.c holder), P5N-AGBAST + P5W-AGBAST-BAIL/COMMIT (xfs, dirwr-gated). P10-INSTR REL/ACQ (dirwr-gated) shows per-AG grant history.

## REMAINING BLOCKER A — residual durable dirent loss (~1 entry / 9 rounds)
run34 round 9: node3_f11.md5 added t276.03 (P13-NADD daddr=10466208 aoff=1896), GONE by verify t283.6 (P26-DSCAN-MISS scanned=801, all 8 ranks agree = durable). Window t274.6-274.9 shows 3 nodes adding into dbno=4 (daddr 10466208) from DIVERGENT epoch bases: t4 b_epoch=623, t3 b_epoch=621, t2 **P46-GROW newdbno=4 b_epoch=618 dirty=1 DIFFER** (test2 materialized the block as new-grown from a base 5 epochs old!). Stale-base RMW family, likely the sess61/62 "block materialization on stale base / tenure-cookie" area. NEXT: rerun with dirwr=1, catch P35E-DIRWR/P50-WR/P29-DATAWRITE ledger for the victim daddr; investigate P46-GROW fresh-materialization epoch check.

## REMAINING BLOCKER B — pacing: ~26-27s/round vs 480s budget (24 rounds needs ≤20s)
Runs 32-34 all timed out at round 17-20 with correctness otherwise CLEAN. Healthy reference 332s (~14s/round, older build). P36-RETRY ino=131 EX 1.02s-stalls sprinkle every round (each = full ACQUIRE_WAIT_MS timeout+retry; sess35 fixed the 6s variant; residue at ~1s cadence remains). These stalls are both pacing cost and deadlock precursors. NEXT: measure per-phase time (create/verify/rm), count P36-RETRY per round, attack the 1s handoff stall (grant/release notification path), and re-record TIMEOUT_BUDGETS after healthy PASS.

## Environment/cadence facts
- run loop: reboot 8 VMs (virsh destroy/start, 45s settle) → `timeout 595 [env MXFS_EXTRA_MODARGS="dirwr=1"] ./run.sh 8 tcp dir_reuse_coherency` → collect /root/dmesg.stream per node into scratchpad/runNN/.
- node-id map run33: t1=2174163247 t2=1081988425 t3=3078267044 t4=3721138023 t5=1683149032 t6=1170310814 t7=2327386309 t8=1204687500 (P4L-ALLOC owner= on own log).
- drc test: tests/suite/dir_reuse_coherency.sh — per round: rank1 mkdir → barrier → all create 50f+50md5 → barrier → all verify (readdir+per-entry lookup) → barrier → rank1 rm-rf → barrier. EXP=2*T*NF=800.
- criteria ladder: 8/tcp drc ×5 clean → full `./run.sh N tcp` suites N∈{1,2,4,8} (sess49 memory: criterion = FULL suite per N).

Links: [[sess4-ROOT-FIX-unlock-fallback-eats-live-request-concurrent-EX]] [[sess4-END2-classB-root-freed-hint-no-generation]] [[sess49-criterion-scope-is-full-suite-and-verification-plan]]
