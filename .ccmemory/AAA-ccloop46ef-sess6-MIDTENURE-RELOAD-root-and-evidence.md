---
name: AAA-ccloop46ef-sess6-MIDTENURE-RELOAD-root-and-evidence
description: sess6: i!=1 root = MID-TENURE reload/decode races LIO cache (own unflushed writes); 6 builds of evidence; next fix = skip destructive reload when dir…
metadata:
  type: project
---

# sess6 (46efd8b6) — the i!=1 family: evidence chain across 6 builds

## Where sess5's theory died
- sess5 blamed "P61 skip eats committed bmbt updates". REFUTED: P77 tripwire (both skip sites) showed EVERY differs-from-LUN skip had pre-mark lseq==wseq (mostly 0=never-logged struct-recycled REPUBLISH images). No committed image is eaten by the skips.
- v0.10.24 (P77 bump lseq + scan-undestaged + scan-before-need_iread) made it WORSE: marking republish images undestaged made the next tenure's fence LATE-RE-PUBLISH stale leafs under later EX. REVERTED the bump in 0.10.25 (print-only tripwire P77-SKIP-DIFFERS).

## What was actually proven (run-by-run)
- run 110411Z (v0.10.24, test26 ino=20971652): leaf==LUN=[11,5] vs iext=[12,4] — iext BEHIND by one left-merge grow. P-RELOAD-IDENTICAL fired at crash (cc=863 equal).
- run 112803Z (v0.10.25 = +completion barrier: bmbt in counted+defer lists, P3B barrier poll, dir_wr_barrier=1, FUA-arm manual wseq stamp, chokepoint uncount): test12 iext=[12,5] vs leaf==LUN=[13,4] (iext AHEAD = its own grow never platter-visible at its decode). P63-LEAFWR timeline: test2 wrote leaf ~20x through .488, test12 tenure 36 crashed at .54. P-RELOAD-IDENTICAL cc=810 fired right after P63-HANDOFF grant_gen=68 acted_gen=59 — cc equality VACUOUS.
- di_changecount was FROZEN (cc=1124 while nx went 13→28): upstream bumps iversion only on log-item clean→dirty TRANSITION; under storm the item never leaves AIL ⇒ cc never moves ⇒ all cc-based reload gates vacuous. FIXED v0.10.26: xfs_trans_log_inode forces one inode_inc_iversion per CORE-logging tx on mxfs multi-node mounts (gate: ili_dirty_flags first-CORE-this-tx). VERIFIED: cc now climbs (649→810→1860).
- run 114157Z (v0.10.26): still i!=1 ×2 (test3/test12 ino=35651716). Theory: P3B loop re-drain writes AFTER last flush (H26 @12857) → cache-resident at unlock. FIXED v0.10.27 (P3B-REFLUSH after late work).
- run 120345Z (v0.10.27): P3B-REFLUSH fired 0 (refuted as THE path), still i!=1 ×2 (test18/test26 ino=39846020). Shapes: leaf [16,2] vs iext [17,1]; leaf [7,2] vs iext [8,1] — iext BEHIND by exactly one left-merge grow, LEAF fresh. = P34B decode-time REGRESS signature: victim's own grow completed into LIO cache; mid-tenure reload's iread FUA-read the platter (pre-grow), judged cached-leaf "clean stale" (BLI retired ⇒ has_uncheckpointed_mods false), memcpy-REGRESSED the leaf, decoded pre-grow iext; leaf buffer later refreshed to fresh; mv shrink → i!=1.
- v0.10.28: P34B ahead |= (b_tenure_id == ip->i_mxfs_ex_grant_seq) — skip regress for this-tenure content. Run 121411Z: P34B-AHEAD fired 4, i!=1 STILL ×3 (test6/9/13) + NEW ir.loaded!=if_nextents ×4 (decode kept our leaf but adopt had taken a PLATTER dinode behind our unflushed state). fails 169, 3 dead. NET WORSE.

## THE UNIFYING ROOT (next fix)
All windows = MID-TENURE reload/decode racing the LIO write cache: while we hold EX and have modified the dir this tenure, our dinode+leaf writes are cache-resident (LIO drops FUA); any reload path that FUA-reads the platter (cluster buffer pierce, P34B leaf compare) sees PRE-write state and adopts/regresses one side of (dinode,leaf,iext) → divergence → i!=1 or ir.loaded mismatch. At genuine tenure START the platter is coherent (prior holder's release flushed). sess36 self-skip was the right instinct; sess49/58 scoped it off for post-release paths (which ARE tenure starts — fine).
**FIX SHAPE: in mxfs_dlm_reload_inode: if i_dlm_mode==EX (mode 5) && i_mxfs_dirty_seq == i_mxfs_ex_grant_seq (dirtied THIS tenure) → skip the destructive adopt (keep fork+dinode; freshness stamps still run). Tenure start: grant_seq just bumped ⇒ dirty_seq != grant_seq ⇒ full adopt proceeds.** Then re-measure; consider REVERTING Edit B (bmbt_scan undestaged arm, xfs_mxfs_dlm.c ~581/612) if late fence writes still manufacture; keep completion barrier (E2/E3/E5, sound) + iversion fix (sound) + P3B-REFLUSH (inert but correct).

## Build/infra state
- v0.10.28 = build 576B1092. Tree has: P77 print-only tripwire both skip sites (pal/linux/xfs_buf.c ~3195 helper), bmbt in counted list (~3520) + defer list (~5430), FUA-success manual stamp (~7390), chokepoint uncount arm, bmbt_scan undestaged needs (xfs_mxfs_dlm.c ~581+612), bmbt_scan-before-need_iread in flush_data_blocks+relsafe, P3B barrier poll + p3b_reflush + P3B-REFLUSH print, dir_wr_barrier=1 default, forced iversion (libxfs/xfs_trans_inode.c), P34B tenure-AHEAD + un-gated capped P34B/P68 prints (libxfs/xfs_bmap.c ~1194).
- Baselines: sess5-end v0.10.23 = 54-56 fails, 1 dead node/run. Current 0.10.28 = 169 fails, 3 dead. If mid-tenure-skip doesn't collapse it, consider bisecting my six changes back toward 0.10.23.
- 16/caw suite: user status board shows 16 PASS / 1 PENDING (dir_reuse_coherency) — only 32/caw cache_coherency (+dir_reuse) block the ladder.
- Test cmd: MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="caw_fair_handoff=1" timeout 1400 ./run.sh 32 caw cache_coherency. VM flake: power-cycle then `tools/mxfs_sshpass.sh <host> /tmp/.mxfs_pass '<cmd>'` (host, passfile, cmd — 3 args!).
- The rv-fail arithmetic: each dead node ⇒ ~55-70 rv fails on every OTHER node; nodes_pass=0/32 with failed≈57×k ⇒ k dead nodes; kill i!=1 and the whole face collapses.
