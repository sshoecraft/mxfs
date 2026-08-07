---
name: ccloop-c7ee71c6-sess164-0.11.459-RIG-VERIFIED-begin-release-conserved
description: sess164: 0.11.459 deployed 32/caw, FULL BOARD 27/27 PASS in budget; begin=clean=revoke=31520 exact per-node, backstop/phantom/publive=0. Step 4 NEXT.
metadata:
  type: project
tags: [mxfs, sess164, foreign-replay, authority, begin-release, rig-verified, board-green]
---

# sess164 — 0.11.459 rig-verified: begin_release wiring measured clean

## Measurement (the sess163 task #3, executed this session)

Deployed 0.11.459 (sv F6077665E740E6ED1A6B472) to all 32 nodes,
`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster` = 139s (budget 240s).
Full board in 5 foreground chunks, every 32/caw-applicable test:
**27/27 functional PASS, all within RULE-0 budgets**, timings match the
Aug 4 baseline (cache_coherency 24s, rsync_paired 45s, crash_consistency
75s, dir_reuse 105s, dirent_durability 65s, ag_strand_repair 79s). Only
`open_defects` red (policy cell). No perf regression from the hooks.

**Authority counters (new `tests/authority_stats_sweep.sh`, parallel ssh):**
- `release_begin == release_clean == revoke == 31,520` cluster-wide and
  EXACT at every node individually — perfect conservation through prep,
  coherency, rsync, dir_reuse, crash_consistency (node kill + rejoin),
  fence_during_write, netpartition, dirent workloads.
- `backstop == 0` strictly: zero P246-AUTH-LATE-REVOKE — the 7-hook wiring
  covers the entire real release population; no uninstrumented path fired.
- `phantom_loss == 0`, `pub_live == 0`, P247/P248 warns absent on all 32.

Ledger next-field updated: D-FOREIGN-REPLAY items 1 (stuck-notify, sess151)
+ 2 (begin_release, sess162/163, verified here) marked DONE with this
evidence; item 3 (lifecycle-shape re-consult, sess133 item 4 + sess150
census) still owed; item 4 = step-4 work is the core remainder.

## Probe-number note

P246/P247/P248 collide with dlm_caw.c LREQ probes (P247-LREQ-NOMEM,
P248-LREQ-*). Checked: number reuse is PRE-EXISTING convention tree-wide
(dozens of numbers shared); the full `P<n>-NAME` string is the identifier.
No renumbering — grep full strings, never bare "P24[678]".

## Tooling

`tests/authority_stats_sweep.sh [N]` — parallel per-node sweep of
`/sys/kernel/debug/mxfs/*/inode_authority` relinquish counters + the four
AUTH warn probes from dmesg, with cluster sum. ~15s for 32 nodes. Counters
are module-lifetime (atomic64 statics) — a node that reloads mxfs.ko
restarts at zero; srcversion column makes that visible.

## NEXT: step 4 (per sess163 (D) ruling — BEFORE active step 5)

Recovery descriptor + IMAGE_REPLAY_DONE marker + victim-manifest freeze
(overlaps D-FOREIGN-SLICE-INTENTS-ABANDONED item 1). Hazards to close, from
the ruling: full authority-namespace match (class+agno+epoch+victim/slice
identity+recovery incarnation); epoch non-reuse proof; transaction-atomic
rejection; tenure-release invariant (older-epoch images destaged-or-
represented before release); descriptor/DONE crash-resumable + serialized;
DONE-before-purge with real flush/FUA ordering. Step-5 shadow parts
(parser/evaluator/counters/prospective-decision recording) may land early.

## Housekeeping

Compaction backlog 194 unfolded (sess163 folded 9 with the authority-arc
article). Largest uncompiled clusters: lreq/waiter-cancel sess111-125
(~20), fence lifecycle sess132-142 (~12), authority-measure sess102-110
(~11), bast-dispatch sess126-131 (~7), fence/descriptor sess62-93 (~30).
dlm+pal awareness doc refresh still due.

Cluster STATE: left UP, 32/caw mounted + converged on 0.11.459, marker
current — next session can run tests directly without re-prep.
