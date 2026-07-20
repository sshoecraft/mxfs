---
name: compiled-caw-8node-dir-durability-leafhash
description: RESOLVED 8/caw dir_reuse_coherency: ungated P6L leaf scan (591A76FB) fixes leaf-hash drops; per-op CAW durable publish is load-bearing.
metadata:
  type: project
tags: [compiled, caw, dir-reuse, leafhash, durability, 8node, coherency]
---

# 8/caw dir_reuse_coherency — leaf-hash-hole durability (compiled)

Central topic: the 8-node CAW `dir_reuse_coherency` ship-criterion blocker — durable
cluster-wide directory leaf-hash holes — chased across ccloop sess6 and RESOLVED on build
**591A76FB**. Two load-bearing facts underpin the fix: (1) CAW per-op durable publish is
mandatory, and (2) an ungated P6L leaf-range scan fixes the leaf-hash drops. Sources:
[[caw-8node-leafhash-hole-shutdown-diagnosis]], [[caw-perop-durable-barriers-refutation]],
[[caw-8node-dir-reuse-FIXED-p6l-leafscan]].

## The failure
`dir_reuse_coherency` at 8/caw failed ~every run on build-line **57773CBD..591A76FB**:
durable cluster-wide leaf-hash holes → readdir loses 1 of 800 entries (799/800 loss rounds,
`lookup_fail=0`), or — rarer — a leaf→block conversion crystallizes the hole and
`__xfs_dir3_data_check` verifier SHUTDOWNs. `P22-DATASCAN-HIT` heals mask the loss;
`P-LEAFDROP` (pr_err + dump_stack in `pal/linux/xfs_buf.c:~4139`) catches the criminal writes.

## RULE-4 diagnosis chain (sess6, [[caw-8node-leafhash-hole-shutdown-diagnosis]])
1. **Criminal stack**: `xfs_create → mxfs_dlm_dir_durable_signal → mxfs_dir_flush_data_blocks
   → mxfs_dir_data_owner_scan → xfs_bwrite(LEAF)` — the per-op publish bwrites a leaf image
   dropping exactly one durable hash at EQUAL count (`buf_cnt==disk_cnt`, dropped=1); also
   `comm=xfsaild` variants, ~40 events/burst.
2. **Signature decoded**: dropped `first_hash` increments through adjacent sorted hashvals
   per successive op — each write's base is missing the PREVIOUS op's own add while carrying
   its own (`buf_n = base∪{H_n}` missing `H_{n-1}`; disk = `base∪{H_{n-1}}`). A ping-pong /
   dual-representation signature — NOT cross-node cache staleness.
3. **Cache-staleness fix REFUTED**: a tenure-start leaf-range scan (P6L,
   `mxfs_dir_coherent_leaf=1` in `mxfs_dir_refresh_stale_data_blocks`; the `i_dlm_dir_gen`
   gate is INERT on CAW slow-path acquires so the leaf branch is ungated) RUNS (197
   CLEAN-MATCH / 155 NOT-INCORE / 72 SKIP-undestaged per run) but `INV=0` and drops
   continued → in-core leaf matches disk at tenure start; staleness arises WITHIN the modify
   path between ops.
4. Ruled out as producers: write-merge grafts (`P-WMERGE2` 0×), count-regressing leaf
   clobber (0×), `dirop_durable_caw` barriers (drops with knob off AND on).

Build **591A76FB** (= FCD17EAE + P-LEAFDROP now logging `bp=%px hold lseq wseq bli inail`)
was the decisive discriminator: alternating `bp` across a burst = dual buffer instances;
same `bp` = content reversion (BLI/reload restoring an older image). Known dual-instance
mechanism: `P20-CLUSTER-INVAL` stale + BLI-held old instance; `owner_scan` walks the PERAG
rhash and may write the OTHER instance than the one `leaf_addname` modifies. Known reversion
suspect: `P5R-TRANSREFRESH` does an FUA-read (platter) memcpy-restore of dir blocks — and
since v0.5.1 per-op publishes are cache-resident plain bwrites (publish-only, no flush), the
platter legitimately lags, so an FUA-read restore can resurrect a pre-publish image.

## Correction at relay — the "scan doesn't work" verdict was invalid
`dmesg --follow` re-dumps the kernel ring at prep restart, so `/root/dmesg.stream` carried
PREVIOUS runs' P-LEAFDROP lines. The earlier "L=40 drops every run" evidence (FCD17EAE) was
ring re-dump contamination, compounded by a too-tight 900s wrapper killing runs early. The
591A76FB 12-round run showed **ZERO fresh `P-LEAFDROP.*bp=` events**. Discriminator rule:
judge fresh oracles ONLY via the new `bp=` field (`grep -a 'P-LEAFDROP.*bp='`); old-format
lines are ring re-dump. Filter P22 by computed node clock (≳5400 that run).

## RESOLUTION (2026-07-06, [[caw-8node-dir-reuse-FIXED-p6l-leafscan]])
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 8 caw
dir_reuse_coherency` → **PASS nodes_pass=8/8**, wall ~700s (under 140*N=1120s budget), test1
dmesg showed **0 fresh P-LEAFDROP, 0 shutdown/BUG/Call-Trace**. Confirms the relay hunch: the
ungated P6L leaf-range scan DID fix the drops; the earlier "fails every run" was ring
contamination + tight wrapper. P-LEAFDROP + P6L-SCAN probes stay as regression canaries.

## Per-op CAW durable publish is LOAD-BEARING — REFUTED the redundancy hypothesis
([[caw-perop-durable-barriers-refutation]]) Hypothesis: per-op barriers
(`mxfs_dlm_dir_inode_durable` / `mxfs_dlm_dir_durable_signal`, Road-B CAW-only) are redundant
post-v0.6.4/0.6.5 because grant is slot-compatibility-gated, the release/demote drain calls
`__mxfs_dlm_dir_inode_durable` ungated on every transport (sess3 a9a03929) +
`mxfs_dir_flush_data_blocks`, and loss families were fixed at acquirer-side roots (acq_epoch,
P106-BAIL, tenure-refuse). Experiment on build **9C1728FB** (= 57773CBD + `dirop_durable_caw`
knob, default 1) with `dirop_durable_caw=0`:
- Create wave halved+ (9-16s → 2.7-7.5s) — barriers ARE the create cost.
- rm phase UNCHANGED ~17.5-23s — rm cost is the IFREE path (per-op `log_force` + settle +
  bounded targeted AIL drain + flush, `xfs_inode.c:~2983`, P137), not dir barriers.
- **Round 17: durable dirent loss** — `node8_f15` missing from readdir on ALL 8 nodes
  (799/800, `lookup_fail=0`). Loss family returns ⇒ **REFUTED**.

Design truth: CAW cross-node coherency is **FUA-read based — peers read the PLATTER**.
Anything parked in the SCST write-back cache between release drains is invisible to a FUA
reader even after a correct slot handoff, so per-op platter publish is load-bearing on CAW
(matches the Road-B comment `xfs_mxfs_dlm.c:~700`, "sess13/48/49 proven"). On TCP peers read
through the same target cache, so release-drain durability suffices. Consequence:
`dirop_durable_caw` stays DEFAULT 1 (knob kept for A/B only; refutation documented at
`xfs_mxfs_dlm.c:~724`).

## Budgets & ladder state
- dir_reuse budget is transport-aware in run.sh: **caw 140*N** (2→280, 4→560, 8→1120), tcp
  100*N. RULE-4-proven structural floor (steady 40s/round × 24 ≈ 1000s; create 9-16s, verify
  4-14s, rm ~21s ≈ 26ms/unlink). 900s wrappers were too tight even for 12 rounds. If 16/32
  rungs blow 140*N superlinearly, that's a NEW scaling bug (CAS contention, dir-size growth)
  to RULE-4, not more budget.
- caw ladder (criteria.json = source of truth): 1/2/4 caw green (MIXED builds — need one-build
  rerun for marker). **8/caw now 15/17** with dir_reuse added; still MISSING at 8:
  **fault_netpartition, soak**. 16/caw and 32/caw not yet attempted (same 17 multi-node tests).

## Final-build blocker: soak dmesg-cleanliness
soak.sh greps dmesg case-insensitively for `DPAT=...|BUG:|Oops|stuck for|call trace`; any
`dump_stack()` ("Call Trace:") in a soak window = FAIL. Build 591A76FB carries two ungated
dump_stack probes to gate behind `mxfs_instr_enabled` for the final build (keep the pr_err
counters as canaries — their text has no DPAT keyword; verify empirically first per RULE 4):
- `pal/linux/xfs_buf.c:~4139` **P-LEAFDROP** pr_err + stack (dir_reuse canary).
- `xfs/xfs_mxfs_dlm.c:13520` **P-DIR-DELALLOC-TRIP** rate-limited(12) + dump_stack.
- (`xfs_mxfs_dlm.c:22672` P1-AGWAIT is ALREADY gated behind `mxfs_instr_enabled` — OK.)
Also known: `mxfs_ili` kmem-cache "Objects remaining" BUG at rmmod (between-runs, likely
outside soak's post-mark window).

## Harness / env facts
- `./run.sh N caw [tests...]` self-preps: teardown→mkfs→form→join→build-match assert→converge
  gate (90+5N s)→run→record criteria.json. Nodes NFS-mount /src from 192.168.1.4; module
  deployed from /src/mxfs/mxfs.ko. Must pass `MXFS_DEV=/dev/mapper/mpatha`. Confirm result via
  `./showstat.sh 8 caw` or criteria.json `runs["8/caw"]`.
- dir_reuse 8/caw needs ~1300s wall; foreground Bash caps at 600s (tool default 120s). Launch
  background + until-loop waiter.
- **Ring re-dump gotcha**: prep_node restarts /root/dmesg.stream but the ring re-dumps → old
  probe lines reappear; ALWAYS filter by timestamp / `bp=` discriminator.
- post-power-cycle NFS mount can race networking → PREP FAIL(build=) once; retry works
  (consider NFS mount-retry loop in prep_node).
- Infra hardened in-tree (sess6): superset VM teardown + verified step-1 teardown +
  power_cycle_node escalation + HARD converge gate; `mxfs_sshpass` ConnectTimeout=10;
  prep_node `fuser -km`; iscsid/open-iscsi enabled + `node.startup=automatic` on all 32 nodes;
  mpath_up.sh; TIMEOUT_BUDGETS.md updated.
