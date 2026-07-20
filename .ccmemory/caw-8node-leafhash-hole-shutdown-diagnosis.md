---
name: caw-8node-leafhash-hole-shutdown-diagnosis
description: 8/caw dir_reuse blocker: per-op leaf publish RMWs a base missing the PREVIOUS op's own add (ping-pong signature). bp-instrumented P-LEAFDROP run in f…
metadata:
  type: project
---

# 8/caw dir_reuse leaf-hash hole — live diagnosis state (sess6 end, ccloop 186320ae)

## Failure being chased
dir_reuse_coherency 8/caw fails ~every run on build-line 57773CBD..591A76FB: durable cluster-wide leaf-hash holes (P22-DATASCAN-HIT heals mask them; P-LEAFDROP catches the criminal writes) → readdir 799/800 loss rounds, or (rarer) leaf→block conversion crystallizes the hole → `__xfs_dir3_data_check` verifier SHUTDOWN (see earlier section of this memory's git history / caw-perop-durable-barriers-refutation).

## PROVEN so far (RULE 4 loop, 4 instrumented runs)
1. **Criminal stack** (P-LEAFDROP + dump_stack): `xfs_create → mxfs_dlm_dir_durable_signal → mxfs_dir_flush_data_blocks → mxfs_dir_data_owner_scan → xfs_bwrite(LEAF)` — the per-op publish bwrites a leaf image that DROPS exactly one durable hash at EQUAL count (buf_cnt==disk_cnt dropped=1), also `comm=xfsaild` variants. ~40 events/burst.
2. **Signature decoded**: dropped first_hash INCREMENTS through ADJACENT sorted hashvals per successive op — each write's base is missing exactly the PREVIOUS op's OWN add while carrying its own (buf_n = base∪{H_n} missing H_{n-1}; disk = base∪{H_{n-1}}). Points at TWO alternating leaf buffer instances (dual representation) or content reversion between ops — NOT cross-node cache staleness.
3. **Cache-staleness fix REFUTED**: added tenure-start leaf-range scan (P6L, mxfs_dir_coherent_leaf=1, in mxfs_dir_refresh_stale_data_blocks — note i_dlm_dir_gen gate is INERT on CAW slow-path acquires, leaf branch now ungated): scan RUNS (197 CLEAN-MATCH / 155 NOT-INCORE / 72 SKIP-undestaged per run) but **INV=0 and drops continue** → the in-core leaf matches disk at tenure start; staleness arises WITHIN the modify path between ops.
4. Not the producers: write-merge grafts (P-WMERGE2 0×), count-regressing leaf clobber (0×), dirop_durable_caw barriers (off/on both drop).

## IN FLIGHT at relay
- Build **591A76FB** = FCD17EAE + P-LEAFDROP now logs `bp=%px hold lseq wseq bli inail` — DECISIVE: alternating bp pointers across the burst = dual buffer instances; same bp = content reversion (e.g. BLI/reload machinery restoring an older image).
- 12-round diagnostic run launched (task ba9wr73be, `MXFS_TEST_ENV="DRC_ROUNDS=12"`). **Beware**: dmesg --follow re-dumps the ring at prep, so /root/dmesg.stream contains PREVIOUS runs' P-LEAFDROP lines — filter by clock (this run's events have test1 clock ≳ 5400) or by presence of the new `bp=` field.
- NEXT: read bp pattern → if dual instances, find where the second instance is born (P20-CLUSTER-INVAL stale + BLI-held old instance is the known dual-instance mechanism; owner_scan walks the PERAG rhash and may write the OTHER instance than the one leaf_addname modifies). If same bp, look at what restores older content between the two ops (P5R-TRANSREFRESH FUA memcpy? reload adopt?).
- Note: P5R-TRANSREFRESH does a **FUA read** (platter) memcpy-restore of dir blocks — per-op publishes are CACHE-resident plain bwrites (v0.5.1 publish-only, no flush), so the platter legitimately LAGS: any FUA-read-based restore can resurrect a pre-publish image = a plausible reversion mechanism matching the ping-pong. Check whether P5R fired on the leaf daddrs during bursts.

## Infra fixed this session (all in-tree)
run.sh: superset teardown of VMs outside run set + verified step-1 teardown + power_cycle_node escalation + HARD converge gate (90+5N s) + caw dir_reuse budget 140*N (RULE-4-proven structural floor; TIMEOUT_BUDGETS.md updated). mxfs_sshpass ConnectTimeout=10. prep_node fuser -km. iscsid/open-iscsi enabled + node.startup=automatic (records + iscsid.conf default) on ALL 32 nodes + mpath_up.sh does both now. P124 probe instr-only (soak green). Suite state: 1/2/4 caw green (mixed builds), 8/caw 14/17 recorded PASS (12 + fence + lock_correctness; dir_reuse FAIL; fault_netpartition+soak not yet run at 8).

## Env gotchas
- prep_node restarts /root/dmesg.stream but the RING re-dumps → old probe lines reappear; filter by timestamp.
- test8-style post-power-cycle NFS mount can race networking → PREP FAIL(build=) once; retry works. Consider NFS mount retry loop in prep_node.
- Foreground Bash caps at 600s; run.sh dir_reuse at 8 needs ~1100-1300s wrapper in background + until-loop waiter.

## CORRECTION at relay (sess6 final minutes) — ring contamination invalidated the "scan doesn't work" verdict
The 591A76FB 12-round run (killed by MY 900s wrapper at ~12 rounds in, prep OK + converged):
**ZERO fresh P-LEAFDROP events** — no `bp=`-format lines on test1/test2/test7. All earlier
"L=40" counts (FCD17EAE run) were plausibly the PREVIOUS run's events re-dumped into the
fresh stream by `dmesg --follow` (ring re-dump at prep restart). So the ungated leaf scan
(P6L / mxfs_dir_coherent_leaf=1) may in fact HAVE fixed the leaf-hash drops — the FCD17EAE
run's 0/8 FAIL reason was never pulled and may be something else entirely (budget? verify?).

NEXT SESSION first moves:
1. Rerun: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" timeout 1300 ./run.sh 8 caw dir_reuse_coherency`
   (FULL 24 rounds, background + until-loop waiter; 900s was too tight even for 12 rounds).
2. Judge fresh oracles ONLY via the bp= discriminator: `grep -a 'P-LEAFDROP.*bp='` (old-format
   lines = ring re-dump, ignore). Fresh P22 similarly needs clock filtering (compute node clock
   at prep time first).
3. If FAIL persists with zero fresh drops → pull per-node reasons from criteria.json + the
   /tmp/run_dir_reuse_* artifacts — the failure mode may have MOVED (different bug or pace).
4. If PASS ×2-3 consecutive → P-LEAFDROP+P6L-SCAN probes stay as regression canaries; sweep the
   remaining 8/caw tests (fault_netpartition, soak), then 16 → 32 → final one-build ladder.
