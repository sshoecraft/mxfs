---
name: compiled-dir_reuse-newtenure-evict-bli-retire-round1-format
description: sess34-35: newtenure-evict+BLI-retire took dir_reuse 8/tcp to 4/5; residual round-1 loss = block→leaf conversion not bumping dir_gen.
metadata:
  type: project
tags: [compiled, dir_reuse, dlm, xfs, format-conversion, cache-coherency, bli-retire]
---

Central topic: closing the `dir_reuse` 8/tcp durable-dirent-loss criterion across sess34-35. Two threads: (1) the acquire-side **new-tenure force-evict + BLI-retire** fix that lifted `dir_reuse` from ~50% to 4/5 PASS; (2) the isolation of the sole residual — a **round-1 format-transition (block→leaf) divergence** where dir_gen is not bumped on in-place conversion — plus the long list of param levers refuted along the way. Keeper build lineage: `275EF4D4` (sess34 start) → `B191F20A` (4/5) → `2EAA0090`/`4703FA18` (per-block, 4/5) → `6ABE6DEE`/`734EAB23` (epoch-never-0, additive).

## The proven loss mechanism (sess34)
Loss-write = a release-drain `bwrite` of a **current-tenure** (`b_epoch==valid_epoch==master_epoch`, `disk_extra=1`, undestaged, `comm=rm`) dir block that is a **stale base** (missing a peer's add). The block was KEPT by the modify-evict undestaged keep-clause `(in_ail && !new_tenure && is_undestaged)`. At the FIRST modify of a NEW tenure that "undestaged" is a FALSE POSITIVE — Invariant 1 already drained it durable at our prior release, before the peer's tenure. The P34-DRAINEPOCH probe proved the loss-block is current-tenure and uniformly `disk_extra=1` (legit rm-rf removes), so **flags cannot discriminate** legit-remove from the rare loss — the only real discriminator is PROVENANCE (which inumber). See [[sess34-HEAD-removed-set-drain-merge]].

## Drain-side graft — DEAD END (refuted twice, do not retry)
Pivoted away after re-confirming sess29/sess33's wall. `i_dlm_dir_removed[]` per-inode removed-set (populated in `xfs_dir_removename`→`mxfs_dir_record_removed` under ILOCK_EXCL, reset on `valid_epoch` change, freed in `xfs_inode_free_callback`) DID disambiguate correctly — `mxfs_dir3_data_drain_merge` grafted surgically 1-2×/node, not 100s, proving inumber-vs-removed-set separates peer-add from our-remove. But the graft itself fails global consistency:
- `8F1E17A0` (per-block name dedup): round3 `readdir=801` + lookup_fail `node7_f17` — CROSS-BLOCK dup (peer entry in in-core block A grafted again draining disk block B) + leaf desync.
- `DBD82AB2` (+ whole-dir GLOBAL in-core dedup `mxfs_dir_name_incore_global`, walks ALL in-core DATA blocks TRYLOCK): round1 `readdir=801` + lookup_fail `node3_f50`, IDENTICAL on all 8 nodes (on-disk dir corrupted). Global IN-CORE dedup is insufficient because the dup entry can live on a DISK block never cached this tenure — can't verify global name-uniqueness without reading ALL disk blocks (too expensive). Graft-at-drain ABANDONED; `dir_drain_merge`/`dir_drain_epoch_skip` stay default-0, removed-set infra retained inert. `dir_drain_epoch_skip` also independently refuted (loss-block is current-tenure at the drain site). See [[sess34-REFUTED-drain-graft-pivot-newtenure-evict-retire]].

## THE WIN — new-tenure force-evict + BLI-retire (sess34)
Acquire-side, principled fix in `xfs/xfs_mxfs_dlm.c mxfs_dir_evict_data_blocks`. At the first modify of a new cross-node tenure (`new_tenure` = master dir epoch advanced), bypass the undestaged keep-clause → force-evict the stale prior-tenure base (clear DONE → cold re-read). sess26 had set `dir_newtenure_evict=0` because clearing DONE left a ZOMBIE in-AIL BLI that reflushed the stale image → `readdir=0`. **The sess34 fix RETIRES that BLI** (`xfs_buf_item_done`, ~xfs_mxfs_dlm.c:3718 `!undurable` branch, gated on `new_tenure` — distinct from the existing `!undestaged`-gated zombie_retire at ~3754). Loss-safe because at new_tenure the block is durable (Inv 1). Modify then cold-reads the peer's image → fresh base → correct RMW, no graft, no leaf-desync.

Result (`B191F20A`, `drc_repro_loop.sh 6 "dir_newtenure_evict=1" 24`): **4/5 PASS** — iters 1-4 clean 8/8, iter5 FAIL round13 `readdir=799` lookup_fail=0 (clean single-dirent loss). Loss freq dropped ~50%→~20%. `dir_newtenure_evict` promoted to **DEFAULT 1** (inert for shortform dirs via early return-true; single-node/1-tcp/tcp_dlm_scaling unaffected). See [[sess34-WIN-newtenure-evict-plus-bli-retire-passes]].

Residual root: `new_tenure` fires only on the FIRST evict-call of a tenure; a stale base `XBF_TRYLOCK`-skipped on that call (P36-EVICT-LOCKED, transient in-flight I/O) escapes — on later calls `new_tenure=false` so the keep-clause preserves it → RMW'd stale → 799.

## Per-block enhancement to close the TRYLOCK gap (build 2EAA0090)
`srcversion 2EAA009009BEA7F6231D9A9`, default-on. (1) On the new_tenure FIRST call only, sync `i_dlm_dir_valid_epoch = cur_mep` BEFORE any modify so every this-tenure block stamps `b_mxfs_dir_epoch==cur_mep` (avoids the sess26 mid-tenure-sync readdir=0 trap). (2) Undurable keep-clause: a block with `b_mxfs_dir_epoch < cur_mep` (prior-tenure stale base) bypasses the keep → force-evicted on ANY evict call (catches TRYLOCK-skipped blocks on retry). (3) Retire broadened to `new_tenure || (b_epoch < cur_mep)`. SAFE: `valid_epoch==cur_mep` all tenure so current work (`b_epoch==cur_mep`) is never flagged. Code at xfs_mxfs_dlm.c ~3819 (prior_tenure clause) + ~4012 (P34-NEWTENURE-RETIRE).

Result (`drc_repro_loop.sh 8 "" 24`, default-on): iters 1-4 PASS 8/8 across ~115 steady rounds (per-block fix eliminated the common steady-state loss), iter5 FAIL. dmesg "shutdown/Corruption" hits are ONLY rmmod-time slab leaks (`mxfs_ili`/`mxfs_inode` objects remaining, "scsipr unregister on shutdown failed") — module-teardown noise, a pre-existing cleanliness bug, NOT test failures. See [[sess35-progress-2EAA0090-dir_reuse-4of4-pass]].

## The residual is TWO faces (sess35)
iter5 exposed both (from `drc_failrounds.txt`):
- **Round-1 face**: `readdir=790/800` (10 lost), ALL 8 nodes coherent, missing `[node3_f1, node6_f28/29/39/40/48/49, node8_f7/8/16]`, LOOKUP_ENOENT + REREAD_MISS (durable). The fresh-dir format-transition (shortform→block→leaf→node) concurrent-create loss. P78-FMT-TORN-FIX fired 1248× on ino=131 at round1 start.
- **Steady 799 face**: round17 `readdir=799/800` (1 lost), SOME nodes only (test7/8, not test1) — sess34's rare residual, still present.

Key epoch observation: P64-MASTER-HANDOFF fired only ~7×/round despite thousands of creates / 29133 KEPT `undurable=1` EVDECIDE on ino=131. Dir epoch (`dg_shadow[].epoch`, dlm/dlm.c ~2602) advances only on cross-node handoff (`last_owner!=owner`); one node does ~57 creates/tenure then hands off. Both `cur_mep` (xfs_mxfs_dlm.c:3601) and `i_dlm_dir_valid_epoch` (set on acquire ~11563 from `dir_grant_epoch`) derive from the SAME `dg_shadow` epoch — if epoch doesn't advance on a handoff, per-block fix AND P16/P23 fail identically. See [[sess35-dir_reuse-two-residual-faces-round1-and-799]].

## Epoch-starts-0 divergence — the round-1 enabling condition
GPT-5.5 consult #1 (RULE 5) + instrumentation (`6FE8A391`, EVDECIDE+epoch fields, focused round-1 repro): failing round-1 window (ino 131, 8 nodes) = 60691 evict-decisions, **ZERO `staleprt=1`** (read-side kept-stale-prior-tenure REFUTED for cur_mep!=0), BUT **57093/60691 (94%) ran `cur_mep=0 AND valid_epoch=0`** — epoch UNTRACKED; 37892 of those were `undurable=1` (KEPT). `cur_mep`/`valid_epoch` derive from `dg_shadow[].epoch` which starts at 0 (dlm/dlm.c:2631) and bumps only on owner-change. When 0, the per-block prior-tenure evict (needs `cur_mep!=0`) AND P16/P23 overrides (need `valid_epoch!=0`) are ALL DISABLED. GPT root: during fresh-dir growth epoch=0 disables stale-base eviction → stale data/leaf/**freeindex** buffers survive a handoff → a later creator's `xfs_dir2_node_addname` allocates from stale bestfree/freeindex → overwrites a LIVE dirent slot → small, durable, globally-coherent slot-level loss. NOT FUA failure (SCST honors FUA, all coherent), NOT double-grant, NOT wholesale sf_to_block clobber.

FIX applied `734EAB23`: **epoch never 0** (dlm/dlm.c `dg_grant_ex`: fresh-resource epoch 0→1, epoch_out 0→1) — activates the validated per-block machinery from the first tenure. Result: iters 1-4 PASS, **iter5 FAIL round1 `readdir=799`** — **epoch-never-0 alone did NOT fix round-1**. Kept anyway (correct/harmless, additive). See [[sess35-GPT-consult-round1-epoch0-disables-staleevict-fix]] [[sess35-round1-refutations-and-addname-coherent-experiment]].

## THE DECISIVE ROOT — block→leaf conversion doesn't bump dir_gen (write-side ABA)
sess35 dirwr=1 write-trace (build `4703FA18`, trace saved `tests/tcp/drc_cap/SESS35_daddr120_trace.txt`) NAILED it. iter4-round1, victim `node7_f1`, dir ino131, block0 daddr=120:
- node7 (tenure 4) adds `node7_f1`→daddr120 off3768 @202.764, writes it `xfs_dir3_DATA` (24 ent post-add).
- node6 (buffer stamped tenure 3, BLOCK-fmt) holds an in-AIL block-0 BLI = whole-dir 24-entry image WITHOUT `node7_f1`; xfsaild flushes it @203.08-203.35 as `xfs_dir3_BLOCK` — AFTER node7's add — durably CLOBBERING it. r5/r2/r1 similarly reflush block-fmt block0 @204-205.
- = the sess11 "logged-then-vanish" ABA reflush: a LAGGING-TENURE in-AIL dir-block buffer from before the block→leaf conversion, xfsaild-flushed over a newer-tenure post-conversion add.

WHY every gen-guard missed it: all writes show `bgen=2 dgen=2 lgen=2` (MATCH), `mode=5(EX)`, `would_skip=0 aba=0 tmism=0 staleprt=0`. `xfs_dir2_block_to_leaf` reuses the SAME daddr (block-fmt→data-fmt, in-place `b_ops` change) WITHOUT advancing the cluster-visible dir generation, so pre-conversion buffers stay `bgen==dirgen==2` = "current" to every gen predicate. The ONLY discriminator is `bp->b_ops`: `xfs_dir3_block` (stale pre-conversion) vs `xfs_dir3_data` (current). GPT-5.5 consult #2 confirmed. See [[sess35-ROOT-round1-format-transition-block-vs-data-divergence]] [[sess35-FIX-DIRECTION-gen-bump-on-conversion-and-per-handoff]].

## FIX DIRECTION (GPT-5.5, next session — NOT yet implemented)
1. **`xfs_dir2_block_to_leaf()` (xfs/libxfs/xfs_dir2_leaf.c:445)**: in the SAME transaction as the magic/ops change, bump `dp->i_dlm_dir_gen` and stamp `dbp->b_mxfs_dir_gen = lbp->b_mxfs_dir_gen = new gen`. Do NOT `xfs_buf_stale` the live dbp (valid). Same for `xfs_dir2_sf_to_block`, `xfs_dir2_leaf_to_node`. This feeds the missing signal to already-working evict + write-chokepoint guards — lowest-risk.
2. **Write-submit gen guard**: reject/stale any dir buffer whose `b_mxfs_dir_gen < current i_dlm_dir_gen` (old-incarnation). RELIABLE (unlike blind subset_guard/reflush_skip): only genuine pre-conversion buffers carry the old gen. RISK per option B/C: must not skip a legit block-fmt write when the dir genuinely IS block format — check disk/current fmt, not just b_ops.
3. **Cross-node propagation**: peer learns the bumped gen on next EX acquire (LVB/reload) → its cached pre-conversion block0 detected stale + FUA-refetched; its EX-demotion must drain+invalidate dirty dir buffers so no old-tenure buffer writes after handoff.

**Check FIRST — existing lever `mxfs_dir_gen_per_handoff`** (xfs_mxfs_dlm.c:4488, source shows `=1` but comment says "DEFAULT 0"). Its comment describes THIS EXACT BUG: fast-path epoch-handoff gen-bump CAPPED by `i_dlm_dir_gen <= i_dlm_dir_loaded_gen` → bumps only once per reload cycle, so 2nd+ intra-round fast-path handoff doesn't re-invalidate → cached block aliases peer-superseded image → `readdir=799`. But the trace showed dgen=2 NOT advancing per handoff despite this being =1. Instrument WHY (is it firing? is the handoff epoch advancing? the CAP `<= loaded_gen` may throttle it). Prefer the handoff-independent conversion-site bump (#1). Keeper `4703FA18` == `2EAA0090` 4/5, all exp params off. Repro: `drc_repro_loop.sh 15 "dirwr=1" 2` (~1/4 round-1 HIT; P11-DATALOG + P16-DIRBLK-SUBMIT + P35E show the clobber).

## Refuted param levers — do NOT re-enable (all blind to the gen-not-bumped-on-conversion root)
- `dir_newtenure_evict=1` — KEEP (default-on, the 4/5 baseline).
- epoch-never-0 (dlm.c dg_grant_ex) — KEEP (harmless/additive, does not alone fix round-1).
- `dir_addname_coherent=1` — safe but INSUFFICIENT alone (read at addname is coherent: P28-PLATTER overwhelmingly MATCH, e.g. test1 29 MATCH/0 DIFFER; only 3 DIFFER caught+refreshed).
- `dir_addname_epoch_refresh=1` — **readdir=0 CATASTROPHE** (`mxfs_dir_addname_epoch_refresh`, xfs_dir2_node.c:2057-2079 clears XBF_DONE + brelse + restart WITHOUT retiring the in-AIL BLI → zombie reflush; epoch-never-0 made it fire more). See [[sess35-REFUTED-addname-epoch-refresh-causes-readdir0]].
- `dir_subset_guard=1` — **WEDGE** round-2 create (`734EAB23`+param: iter1 round1 passed, P26-SUBSET-SKIP fired 10× on test1, then test1 wedged >3.5min at round2 create-start; the suppressed write is one the create synchronously depends on; also pathologically slow per-write FUA read). See [[sess35-write-side-subset-guard-test-plan]].
- `dir_reflush_skip=1` — readdir=0/2 catastrophe (skips writes of blocks legitimately DONE=0 during round-1 format churn).
- `dir_release_stale` (release demote-invalidate, sess33) — buffer re-enters next tenure, insufficient.
- `dir_drain_epoch_skip` / `dir_drain_merge` — refuted (see graft section), stay default-0.
LESSON: blind write-skip/suppress + read-refresh + epoch-tracking tweaks ALL fail — during round-1 format churn they can't distinguish a stale zombie reflush from a legit re-write of an evicted-then-refilled block. The discriminator must be b_ops/gen fed from the conversion site, not a blanket predicate. See [[sess35-HEAD-handoff]].

## Refuted root hypotheses (instrumented, RULE 4)
- Read-side KEPT-stale-prior-tenure base: REFUTED, `staleprt=0` (0/60691, caveat: needs cur_mep!=0 which 94% weren't).
- Stale in-core bmap (evict walks too-few extents): REFUTED, P37-STALEBMAP-MODIFY = 0 on all 8 nodes (ran 44-75×/node).
- Addname stale read: REFUTED, P28-PLATTER in-core==platter MATCH.
- use_free live-slot overwrite: `xfs_dir2_data_check_free` guards it, no corruption shutdowns.
These converge (with sess28) on the loss being WRITE-side. The sess97 release fence (xfs_mxfs_dlm.c:8495-8585) already enforces Invariant 1 (loops until all dir-fork blocks bwrite'd + inode out-of-AIL before release), so at a clean release the image IS durable — confirming the ABA is a post-release / conversion-window stale reflush, exactly the block→leaf gen gap. Note `mxfs_dir_data_durable`/flush return-early for LOCAL/shortform fmt (xfs_mxfs_dlm.c:1120), a candidate uncovered transition.

## Test/repro reference
- Repro+trace: `tests/tcp/drc_repro_loop.sh 15 "dirwr=1" 2` (~1/4 round-1 HIT). Steady: `drc_repro_loop.sh 8 "" 24`.
- Criteria runner: `tests/run_criteria_tcp.sh "1 2 4 8"` (clean-reboots each cond, ./run.sh + showstat). Baseline: 1/tcp=16/16, 4/tcp=17/17, 8/tcp=16/17 (dir_reuse sole fail), 2/tcp needs a fresh run.
- RULE-0 budget: `dir_reuse N>4` = 480s in run.sh; iter5 ran slow (~7.5min vs ~5) — watch.
- Run WITHOUT `dirwr=1` for representative results (dirwr perturbs: DABUF_MAP_HOLE storm is a baseline probe artifact, not merge-induced).
