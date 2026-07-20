---
name: compiled-dir_reuse-duplicate-iqn-async-destage-toctou
description: sess31 compiled: duplicate-IQN infra bug was the 8-node flakiness; residual dir_reuse loss is an async xfsaild-destage TOCTOU.
metadata:
  type: project
tags: [compiled, sess31, dir_reuse, iscsi-iqn, async-destage, toctou, cache-coherency, dir_merge, tcp-dlm]
---

## sess31 compiled — the 8-node flakiness was infra (duplicate iSCSI IQN); the residual is an async xfsaild-destage TOCTOU

Two threads run through every sess31 memory: (1) the ~30-session "8-node coherency flakiness" was largely an **infrastructure bug**, not mxfs; and (2) once that was fixed, a single genuine mxfs bug remained — a **rare single-dirent loss in `dir_reuse_coherency` at 8 nodes**, proven to be an async-xfsaild-destage TOCTOU that no create-time or read-time merge can close. No kernel edits shipped this session; build stayed **37A37B10** (keeper). CRITERIA (8/tcp 100%) NOT MET at session end — do not write YES.

### THE BREAKTHROUGH — duplicate iSCSI InitiatorName (infra, not mxfs)
[[sess31-BREAKTHROUGH-duplicate-iscsi-iqn-was-the-8node-flakiness]]
- Shared LUN is a **QNAP TS-453Pro iSCSI target at 192.168.1.4:3260** (`iqn.2004-04.com.qnap:ts-453pro:iscsi.target-0.f35772`) — NOT SCST on clyde (the topology memory was stale).
- **6 of 8 VMs shipped the SAME default IQN** `iqn.2004-10.com.ubuntu:01:68299635f96d` (test1,4,5,6,7,8). Only test2/test3 had unique names. Duplicate IQNs make the QNAP drop/conflict colliding sessions → `connection1:0: detected conn error (1020)` flapping every ~2.5s → that node's `/dev/sda` I/O fails → mxfs sees EIO → readdir=0 (whole FS view gone) → coordinated test fails 0/N, then every subsequent test sees the wedged node as 3/4 = CASCADE.
- **Why it hid ~30 sessions**: 2/tcp passed 17/17 because only test1+test2 run and test2's IQN is unique (test1 sole user of the dup) → no collision. 4/tcp and 8/tcp failed because test4 (and at 8: test4-8) collide with test1. The wedged node mimicked an mxfs coherency bug exactly (dir_reuse "node4 readdir=0", crash_consistency "durable empty .md5 sidecars") — all really EIO from the flapping session.
- **Diagnosis signature**: `dmesg | grep -c 'conn error'` (healthy=0; colliding=100s and still counting, last ts ≈ uptime); `iscsiadm -m session` shows the QNAP portal; compare `/etc/iscsi/initiatorname.iscsi` across nodes — any duplicate = bug.
- **Fix (applied, persisted on each VM root disk, survives virsh destroy/start)**: unique `InitiatorName=iqn.2004-10.com.ubuntu:01:test<N>-mxfs-node` on test4,5,6,7,8 (test1 keeps old name, now unique). QNAP has no restrictive ACL. Verified test4 post-reboot conn_errors=0, /dev/sda 217 MB/s.
- **Second infra fix**: node root disks were 100% full (test1/test4) from ~20GB `/var/log/{syslog,kern.log}` — an always-on mxfs printk probe flood via rsyslog, cumulative over ~30 sessions. That ENOSPC broke `dkms_install` (1/tcp fail). Truncated logs → 1/tcp 16/16. The flood refills over runs; consider gating the always-on printk or auto-truncating in run.sh prep.

### Post-fix standing (build 37A37B10 deployed)
[[sess31-STATUS-8tcp-residual-is-clean-single-dirent-loss-only]] [[sess31-HEAD-handoff]]
- **1/tcp = 16/16**, **2/tcp = 17/17**, **4/tcp = 17/17** (was 13/17 cascade before the IQN fix) — all clean.
- **8/tcp = 17/17 on 3 of 4 full runs (~75%)**. Runs A & B = 17/17; run C = 14/17, its ONLY root failure being the clean single-dirent loss below (then cascading to fault_netpartition / tcp_dlm_scaling). This criterion was NEVER passing before the IQN fix.

### THE SOLE RESIDUAL — dir_reuse single-dirent loss (mechanism proven)
[[sess31-DECISIVE-round1-standalone-repro-confirms-sess28-mechanism]] [[sess31-KEY-loss-is-async-destage-TOCTOU-create-and-read-merges-ineffective]]
- Symptom: durable loss of exactly one dirent, consistently **node1_f4.md5** (rank1's md5 sidecar #4). All 8 nodes readdir **799/800**, LOOKUP_ENOENT, REREAD_MISS — data dirent AND leaf hash both gone. `lookup_fail=0`. No shutdown, no infra. This is the genuine sess20-30 dir-data lost-update.
- **Smoking gun** (test5/rank5 create-phase, dir inode=131, reconfirms sess28): `P-WMERGE owner=131 daddr=16745864 disk_extra=1 incore_extra=1 held_mode=5(EX) in_ail=1 dirty=0 bgen=0 kind=data — MERGE-NEEDED`. An EX-holder (test5, re-acquired) async-destages an **in-AIL dir-DATA block whose base is STALE (bgen=0, prior tenure)**: disk_extra=1 = disk holds the peer add (node1_f4.md5) the in-core base LACKS; incore_extra=1 = test5's own add the disk lacks. Destaging the stale base reverts node1_f4.md5. Exactly ONE such event per loss (single-dirent).
- **Timeline**: `P25-RELVERIFY-MISMATCH=0` (data coherent at every EX *release*) → staleness develops AFTER release. test5 T1 lands its add coherently → peer adds node1_f4.md5 to disk → test5 T2 re-acquires; the read-side gen hook sees bgen=0 ≠ dir_gen=3 but **CANNOT invalidate** (block in_ail = test5's own un-destaged work; clearing XBF_DONE corrupts) → test5's next addname RMWs the stale in-AIL base → xfsaild destages stale later → clobbers node1_f4.md5.
- Heavy release-side context: `P34-LEAF-DRAIN` fires ~19k×/run; **9593× are CACHED=0** (leaf block uncached at release → release-drain can't destage it, the in-code "Inv 1 leaf gap"). Suspicious for the leaf-hash half of the loss; not yet proven causal.

### Reliable repro (round-1, standalone — NOT reuse-churn dependent)
Loss reproduces at **ROUND 1**, ~1 in 2-3 iters (~1 per 3 full runs / ~1 per 70 dir_reuse-rounds).
- Reboot all 8 first (run.sh REUSES the mount and only applies insmod modargs on a FRESH insmod). Modargs are insmod-style — **NO `mxfs.` prefix**.
- Loop harness: `tests/tcp/drc_repro_loop.sh [ITERS] [MODARGS] [ROUNDS]` — reboots 8 nodes then loops 8/tcp dir_reuse until a fail round, DRC_STREAM on. Launch background with `setsid ... </dev/null &` (plain nohup gets reaped); poll the log for "HIT" (steve cannot write /root).
- One-shot capture: reboot, then `MXFS_EXTRA_MODARGS="dir_writeprobe=1 dir_relverify=1" MXFS_TEST_ENV="DRC_STREAM=1 DRC_ROUNDS=6" ./run.sh 8 tcp dir_reuse_coherency`. Clobber is in the **CREATE-phase** snapshot `/root/drc_create_r1_rank<N>.dmesg` (NOT the verify-phase drc_fail dmesg). `dir_writeprobe=1` enables P-WMERGE; `dir_relverify=1` enables P25-RELVERIFY-MISMATCH.
- Note: `dir_writeprobe=1` also INDUCES the loss (slows destage) — makes it a reliable trigger. DRC_ROUNDS=8 is too few to distinguish a fix (loss rate too low); use 24 + DRC_STREAM.

### Why every merge approach fails — merge gate runs once-per-tenure
[[sess31-merge-gate-once-per-tenure-is-why-dir_merge-ineffective]] [[sess31-ROOT-merge-gate-skips-99pct-targeted-fix-design]]
- P-MERGEGATE probe (build **BCFA3AA6** = keeper 37A37B10 + gated probe, inert at default): with `dir_merge=1 dirwr=1`, **decision=SKIP on ~99% of creates** (test1: 60 SKIP / 1 RUN; test2/5/8: 100 SKIP / 0 RUN). `mxfs_dir_merge_peer_into_tp` (xfs_mxfs_dlm.c:5291) has a perf gate (~5331) that returns early unless `dir_gen != evicted_gen`, and after a complete merge ADVANCES evicted_gen=dir_gen → runs **ONCE PER TENURE** (first create after acquire), skips every subsequent create.
- That one run's snapshot missed the lost entry (`P18-MERGE-TP added=0` on all 8 nodes for dir ino=131) — in-core already matched the disk image it read; node1_f4.md5 became durable AFTER the once-per-tenure snapshot but BEFORE the async destage. Re-running the merge per-create closes the window but → **DLM lock timeout shutdown** (`DLM inode lock unrecoverable: ino=131 mode=5 rc=-110`, mxfs_dlm_ilock_begin:12916; the sess29 perf-doomed-merge wall). Classic correctness-vs-perf wall.

### Levers TESTED this session
[[sess31-KEY-loss-is-async-destage-TOCTOU-create-and-read-merges-ineffective]] [[sess31-mht800-mitigation-passes-but-wedges-under-load]]
- **`dir_merge=1 dir_force_block=0`** (create-time transactional union-merge via xfs_dir_createname) — INEFFECTIVE. Still loses node1_f4.md5 round 1, 799/800. No shutdown, wall=499s (slow — reads all dir blocks per create). A create-time merge cannot close the window (peer add lands durably after our snapshot, before our destage).
- **`dir_addname_coherent=1`** (read-side FUA reread at addname; `mxfs_dir_addname_coherent_refresh`, xfs/libxfs/xfs_dir2_data.c:1603) — INEFFECTIVE. CLEAN-only; skips the in-AIL block which IS the failure case (sess28 already showed this).
- **`dir_write_merge=1`** (destage-time data-only bio-submit graft) — HARMFUL. Causes **bnobt double-free SHUTDOWN** (`ltbno+ltlen>bno`, xfs_alloc.c:2254 → xfs_free_ag_extent) at ~round 7, plus leaf-hash lookup_fail=1. Updates data+bestfree+CRC but NOT leaf/freeindex/free-space-btree → AG corruption. Strictly worse; **do not retry** (confirms sess30 refutation with a harder symptom).
- **`inode_mht_ms=800`** (node-format dir min-hold-time; default 300) — passes 8/tcp 3 consecutive short runs (wall 113s) but **WEDGES bast_work_fn under sustained load** (runs 4-5, same mount): test4 `mxfs_dlm_bast_work_fn` stuck in stack traces, dropped its mount. Longer hold defers peers' BASTs → drain wedges. Probabilistic (shrinks window, doesn't close it) → can never reach 100%. A moderate value (400-500) might reduce loss without wedging but still can't hit 100%. Default 300 restored. (tcp_dlm_scaling uses SHORTFORM dirs, `dir_sf_mht_ms=100`, separate — wouldn't regress but the wedge kills it.)

### Targeted fix designed and partially implemented (UNVERIFIED)
[[sess31-ROOT-merge-gate-skips-99pct-targeted-fix-design]] [[sess31-IMPL-stale-block-reconcile-fix-needs-validation]]
- Design: whole-dir merge is too slow per-create (DLM timeout), so run a **cheap per-block transactional reconcile only when a stale block was kept**. In acquire-evict/modify-refresh, when a DATA block is KEPT stale (SKIP branch in `mxfs_dir_drain_evict_data_blocks` ~6128 and `mxfs_dir_evict_data_blocks` ~3055), flag it; at the next create transaction, FUA-read ONLY that block, re-add via `xfs_dir_createname` any peer dirent the in-core lacks (transactional → leaf/freeindex/freespace stay coherent, unlike the write_merge graft).
- Built (build **8E4B6D08** = keeper 37A37B10 + fix + gated P-MERGEGATE probe): new lever **`mxfs.dir_stale_reconcile` (default 0)** — keeper behavior unchanged at default. New fn `mxfs_dir_reconcile_stale_data_blocks(tp, dp)` (xfs/xfs_mxfs_dlm.c, after mxfs_dir_merge_peer_into_tp; call site xfs/xfs_inode.c:1726). New flag `MXFS_IF_DIR_DATA_STALE (1U<<22)` (xfs/xfs_inode.h), set in the drain_evict SKIP branch (~6360), test_and_clear'd by the reconcile. Prints `P31-RECONCILE`. Header decls in xfs/xfs_mxfs_dlm.h.
- **Validation INCONCLUSIVE**: v1 (`is_stale = in_ail && undestaged`) passed 7/7 at DRC_ROUNDS=8 but **P31 fired 0×** = INERT (loss-block is NOT in_ail at evict/reconcile — it's a CLEAN stale prior-tenure base); reconcile=0 also passed 5/5 at 8 rounds, so 8 rounds can't distinguish. v2 (`is_stale = b_mxfs_dir_gen != dir_gen`, the correct discriminator — loss-block had bgen=0 < dir_gen) is in 8E4B6D08 but **NOT YET TESTED**.
- **NEXT (RULE 4)**: reboot, run `dir_stale_reconcile=1 dir_writeprobe=1` DRC_ROUNDS=24 DRC_STREAM=1 — confirm `P31-RECONCILE` fires with re-added>=1 AND no loss/shutdown/DLM-timeout, wall <2× native (RULE 0; FUA reads add cost). A/B with `dir_stale_reconcile=0` MUST still lose (else inconclusive). If clean: make default=1, re-run 8/tcp ×3 (17/17 each) + re-verify 1/2/4 tcp. If P31 still inert: also set the flag in the `mxfs_dir_evict_data_blocks` (~3055) keep branch, not just drain_evict.
- OPEN pre-verify question: confirm the kept-stale block's disk image actually contains the peer's add at modify time (publish-before-notify should FUA-write+flush before granting EX). If the FUA read does NOT show node1_f4.md5, root is instead a publish/transport-coherency gap or a TCP DLM double-grant — a different fix.

### The architectural conclusion (all sources converge)
The clobber is fundamentally an **async xfsaild-destage TOCTOU**. Read-side and create-time merges snapshot too early; the destage-time non-txn graft can't be transactionally consistent (corrupts bnobt). The only non-refuted fixes:
1. **Never async-destage a multi-node dir DATA block** — write dir DATA blocks SYNCHRONOUSLY at EX release with full in-AIL drain (Invariant 1: land our add A before EX handoff), not lazily by xfsaild in a later reacquired tenure. Closest to GFS2/OCFS2 glock-release semantics; biggest, most-correct change. The release fence is xfs_mxfs_dlm.c:7488 (`mxfs_dir_data_durable` gate → `mxfs_dir_flush_data_blocks_relsafe`); root of the gap is that at T1 release, A was NOT landed (release-drain coverage gap), so the in_ail block survives to T2' where acquire-evict can't invalidate it.
2. **Transactional 3-way re-apply at re-acquire/addname** (the per-block reconcile above, or promoting `mxfs_dir_addname_coherent_refresh` from a bare FUA re-read into a real txn merge): when an addname RMWs a block that is stale (bgen≠dir_gen) AND in_ail, within the addname transaction read coherent disk and re-add the peer's unique dirents so data+leaf+freeindex all update coherently.

### Session-end state
Cluster rebooted clean, default config (reconcile OFF = keeper-equivalent), all 8 nodes up, build **8E4B6D08** deployed (keeper 37A37B10 behavior at default). CRITERIA (8/tcp 100%) NOT MET.
