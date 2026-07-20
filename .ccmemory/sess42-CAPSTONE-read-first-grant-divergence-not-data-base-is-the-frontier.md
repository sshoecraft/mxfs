---
name: sess42-CAPSTONE-read-first-grant-divergence-not-data-base-is-the-frontier
description: sess42(ccloop) CAPSTONE (read first) — RETRACTED grant-divergence theory: P42-STALEEX-SERVE=0 → EX IS serialized (held=1 at every serve); storm dir u…
metadata:
  type: project
---

## sess42 (ccloop 4cb2d0a2) CAPSTONE — read FIRST. Build 445B37FF = keeper functionally. Criterion NOT met.

### ⚠️ RETRACTION: the grant-divergence theory (an earlier version of this memory) is REFUTED.
I added an always-on probe `P42-STALEEX-SERVE` (xfs_mxfs_dlm.c ~13925) that, at the dir-EX fast-path serve, queries `mxfs_v5_dlm_inode_held()` and logs if held==0 (serving a cached EX whose grant moved). It fired **0×** across all 8 nodes at a fail. The sibling `P63-FASTEX-HANDOFF` also fired **0×** for ino=131. Conclusion: **the node ALWAYS holds the on-disk/master EX grant when it modifies the storm dir — EX is correctly serialized; there is NO modify-under-lost-grant / divergent concurrent RMW.** (Also: the storm dir is ALWAYS contended → state != CACHED → the dir-strict gate diverts EVERY storm-dir EX modify to the SLOW PATH, so the fast-path handoff machinery never even runs for it. Coherency rests entirely on the slow-path acquire reload + the release drain.)

### What is now SOLID (high-confidence, this run + prior):
1. EX serialized: held=1 at serve, MX-DOUBLEGRANT silent, storm-dir slow-paths every modify.
2. The lost dirent is added in-core under a VALID held EX (P13-NADD/LADD fires; leaf_count increments).
3. It is durably lost on a handoff and absent from disk afterward (LOOKUP_ENOENT, DSCAN-MISS).
4. dland write-completion ring: a block is written by node A up to count N (incl victim era), then by node B to N+k WITHOUT the victim — a count-INCREASING image regression (fools sum=801 + count-regression detectors).
5. EVERY lever REFUTED (each A/B'd ON, still ~33% loss): `dir_wseq_at_completion` (written_seq@completion), `dir_grant_evict` (acquire-side fresh-read base), `dir_release_flush_all_done`, `dir_release_fua_write` (creator→platter FUA), `dir_write_merge` (inert dko=0). Converged default already runs `dir_epoch_adopt=1`+`dir_gen_per_handoff=1` (epoch handoff data-refresh) and still loses.

### Therefore the bug is a release-drain / slow-path-reload-adopt COMPLETENESS gap WITHIN proper serialization — NOT a base/durability/grant bug at the layers already patched. Two concrete candidates the evidence keeps pointing at (next session: trace ONE victim's FULL lifecycle to decide):
- (A) **bmbt/extent-map orphan**: the victim's DATA block is written durable WITH the entry, but the dir dinode's data-fork EXTENT MAP (bmbt) written at the adding node's release does NOT reference that block (or references the pre-grow map) → the next slow-path acquire reloads the dinode and adopts a smaller map → the block is ORPHANED → readdir's bmap walk never visits it. GPT flagged bmbt blocks must be in the release checkpoint; `mxfs_dir_data_durable`/`flush`/`bmbt_scan` exist but may miss the just-grown extent. (My f44 trace this session: P42-RELDUR showed the victim's block daddr present in some releases but the block↔logical-bno↔daddr churns heavily via reuse.)
- (B) **release drain runs on the WRONG/empty extent set**: at the adding node's release the dir reloaded (BTREE/need_iread) or the extent for the just-added block isn't in `for_each_xfs_iext` yet → the drain iterates a map missing the victim's block → never flushes it. (P42-VACUOUS-DURABLE for the pure BTREE-need_iread case fired 0×, but a partial/racing extent map is not covered by that probe.)

### NEXT (RULE 4) — per-victim FULL-LIFECYCLE trace (the decisive experiment not yet run):
Pick the failing run's victim (from drc-RDMISS). On the CREATOR node, trace in order with realns: P13-NADD/LADD (which daddr+bno the entry landed in) → the dinode extent map at that moment (nextents, the bno→daddr mapping, P38-DIRMAP) → the adding tenure's RELEASE: did `mxfs_dir_data_durable`/`flush` ITERATE the victim's daddr (add a per-daddr log in mxfs_dir_flush_data_blocks — extend the existing P42-RELDUR which is in mxfs_dir_data_durable) AND did it flush it? AND was the DINODE (di_nextents + bmbt) durable with that block in the map (P105-REL-DIRINODE nextents vs the count incl the new block)? Then on the NEXT acquirer: P62-RELOAD-FORK-SHRINK incore_nx vs disk_nx — did disk_nx LAG (map missing the block)? If disk_nx < the block's bno → orphan (candidate A); if the block was never flushed → candidate B. Build the fix accordingly (release checkpoint must include the dinode extent-map + bmbt coherent with the just-added block BEFORE handoff — GPT per-tenure checkpoint, tracked via xfs_trans_log_inode not format drains).

### Probes in build 445B37FF (all storm-dir ino<=256, ratelimited, inert/no-behavior-change): P13-LADD, P42-RELDUR, P42-VACUOUS-DURABLE, P42-STALEEX-SERVE (=0, proves EX held at serve). Cross-ref [[sess42-ELIM-fua-write-plus-grantevict-fail-broken-path-bypasses-release-flush]], [[sess42-PROVEN-799-is-stalebase-clobber-not-insert-loss-gpt-tenure-fence-plan]], [[sess41-NEXT-sum-discriminator-bmbt-orphan-vs-insert-loss]] (the bmbt-orphan vs insert-loss discriminator — re-run it per the dland count-trajectory, NOT the ambiguous sum).</body>
