---
name: sess64-WIN-incarnation-gated-epoch-adopt-1of24-no-corruption
description: sess64 CORRECTED: epoch-adopt-via-P33/P43-shrink-guard-bypass is a DEAD END (intermittent bnobt double-free; incarnation gate didn't eliminate). Stab…
metadata:
  type: project
---

## sess64 — epoch-driven disk-superset adopt via reload_inode is a DEAD END (corrects the premature "WIN")

### Stable build on disk: 04E74E78 = 5E78DEE0 baseline + epoch PLUMBING (KEEP) + epoch ADOPT DISABLED (observe-only P64-EPOCH-OBS). Baseline-equivalent behavior. 2/tcp coherence tests verified PASS.

### What was tried and REFUTED this session
- Monotonic per-dir epoch (dg_shadow.epoch, wire, level-triggered compare) — PLUMBING WORKS, closes the 80% edge-bit under-fire. P64-EPOCH-OBS confirms epoch advances EXCLUSIVELY on post_release=1 (slow-path) reloads.
- Driving the disk-superset adopt by having the epoch BYPASS the P33/P43 keep-stale guards (xfs_mxfs_dlm.c ~7564/7663/8017), gated post_release=1 + same-incarnation (di_gen match):
  - Run drc_s64h: 1/24 fail (node1_f1), shutdown=0.  Run drc_s64i (identical build): **test3/test4 SHUTDOWN** — `bno+len>gtbno xfs_alloc.c:2428 xfs_free_ag_extent` (bnobt DOUBLE-FREE during rm-rf). **HIGH VARIANCE — not a reliable fix.**
- ROOT of why it corrupts: **P33/P43 are SHRINK/revert guards** (in-core BLOCK dir vs SMALLER disk shortform / disk-one-growth-behind). Bypassing them adopts the SMALLER disk image → frees the in-core block-format data blocks → if those blocks are inconsistent with the in-core AG bnobt/cntbt free-space state (the deep sess42-47 AG-coherence gap), the subsequent rm-rf double-frees → corruption. The incarnation (di_gen) gate REDUCED but did NOT eliminate it.
- DECISIVE LOGIC: the dirent CONTENT loss (node1_f1) is a SAME-SIZE missing-one-entry loss, NOT a shrink. So it does NOT flow through the P33/P43 shrink guards at all. Bypassing those guards therefore CORRUPTS WITHOUT FIXING THE LOSS. The epoch-via-reload-adopt path is the wrong mechanism.

### node1_f1 residual root (the real remaining bug)
node1_f1 = rank1's FIRST file. On a failing round: rank1 SEES it (served from its un-dropped in-core dir cache), ALL peers cold-read disk and MISS it ⇒ node1_f1 is **durably absent on disk** = a peer clobbered it (RMW'd a block whose base lacked node1_f1 and wrote back durable), or it was never published. This is the pin-tailed-stale-base / publish-durability RULE-0 wall (refreshing the clobberer's stale base needs SYNC log_force=too slow, or guaranteed release-side durability — P-SF-DURABLE-FAIL=0 claims durability yet node1_f1 still drops, so that claim has a hole for the first-entry/sf→block case).

### NEXT SESSION
1. KEEP the epoch plumbing (correct, reusable). Do NOT re-try the P33/P43 bypass.
2. Pursue GPT's actual design: on stale epoch, DISABLE the fast-path serve and force a clean slow-path NL→EX RE-ACQUIRE that atomically reloads the WHOLE coherent set (dinode + dir data/leaf blocks + AG free-space meta) — avoiding the in-place partial adopt that desyncs inode-vs-AG state. See [[sess64-GPT-design-per-dir-monotonic-epoch-replaces-handoff]].
3. OR directly instrument node1_f1 publish-durability: add a probe at rank1's BAST-release fence confirming the dinode/block holding node1_f1 is actually bwritten before grant handoff; and at the clobbering peer, whether its first-create base for that block contained node1_f1.
4. There are ≥2 coupled failure modes (dirent content loss + AG-free bnobt corruption under rm-rf reuse + PR-reader frozen view); 100% needs all. See [[sess64-epoch-plumbing-done-adopt-surfaces-bnobt-corruption]] [[sess64-NEXT-epoch-adopt-must-respect-incarnation-guards]].</body>
