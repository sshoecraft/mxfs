---
name: sess18-ROOT-NARROWED-shortform-to-block-transition
description: sess18 DECISIVE: 2/tcp durable dir loss is the shortform→block FORMAT-TRANSITION window, NOT steady-state block. Pre-growing the dir to block format…
metadata:
  type: project
---

## sess18 (ccloop 8ddb16a2) — DECISIVE root narrowing for the 2/tcp crash_consistency durable dirent lost-update.

## EXPERIMENT (tests/cc_pregrown_probe.sh, baseline build dir_merge=0): each iter test1 PRE-GROWS a fresh dir to BLOCK format single-node (40 files, sync, dirsize=4096) BEFORE any concurrent access, THEN both nodes concurrently create 50 files each into it, then drop_caches + recount.
## RESULT: 0/15 iters lost (first run) — every iter all=140/140, dirsize=4096. (30-iter confirmation running.) CONTRAST: the standard probe (tests/cc_blockdir_probe.sh — dir starts SHORTFORM, both nodes create concurrently from the empty dir) loses entries every ~4-16 iters on the SAME build (today: iter4 199/200, iter14 196/200, iter16 196/200, all durable-unrecoverable).

## CONCLUSION: the durable lost-update is the **shortform→block FORMAT-TRANSITION window**, NOT steady-state block-format concurrent create. When the dir is already block-format + durable before concurrent access, there is NO loss. Mechanism (matches the P62-RELOAD-FORK-SHRINK adjacent-gen format divergence seen on failing iters: test2 incore fmt=2/gen433 vs disk fmt=1/gen434, and the reverse): two nodes concurrently create into a FRESH shortform dir; one converts it to block format on disk; the other still holds a stale SHORTFORM in-core base, RMWs it, and durably writes shortform — clobbering the peer's block conversion (or block entries) → entries lost.

## FIX LOCUS (cold-path, RULE-0-safe — does NOT burden the per-create hot path, unlike the doomed merge [[sess18-merge-perf-doomed-pivot-to-format-transition]]): the ACQUIRE/modify-side reload must adopt a peer's sf→block conversion before RMWing. Candidate site: mxfs_dlm_dir_modify_reload_prelock (xfs_mxfs_dlm.c ~2233) → mxfs_dlm_reload_inode(dp, ..., post_release=false). The post_release=false path "keeps our own in-flight mods authoritative unless the peer genuinely advanced the gen" — SUSPECT: when a peer converts sf→block, if that conversion is not seen as a gen-advance (or the reload keeps our shortform fork because it has in-flight mods), we retain a stale shortform base. Also the reload only fires when MXFS_IF_DIR_RELOAD flag is set (xfs_iflags_test_and_clear) — if the flag isn't set on the node that missed the peer's conversion, no reload happens. Investigate: does the format-mismatch (incore sf, disk block) force a reload+format-adopt? The sess14 shortform 3-way merge (mxfs_dir_sf_3way_merge) handles sf-vs-sf but likely NOT the sf→block transition.

## NEXT STEPS: (1) develop on 4/8-node deterministic repro (user's guidance: bigger node count = race fires iter-1; tests/reset4.sh takes node count), validate on 2-node (the criterion). (2) Instrument the sf→block conversion: on a modify, if incore fmt==LOCAL_FMT_SHORTFORM but disk dinode fmt==block (peer converted), the node must reload to block + replay its pending entry onto the block image, NOT write shortform. (3) Likely fix = force a reload + format-adopt when a peer's gen advanced AND a format upgrade is detected, before the modify RMWs. Validate: cc_blockdir_probe (sf-start) clean >25 iters AND ./run.sh 2 tcp 16/16 x>=5.

## STATE: cluster HEALTHY baseline (dir_merge=0). New script tests/cc_pregrown_probe.sh (in tree per RULE 3). Marker NOT written. [[sess18-readside-ruled-out-writeside-clobber-confirmed]] [[sess17-CONFIRMED-staleflush-clobber-P17]] [[sess14-cc-root-blockdir-concurrent-create-dirent-loss]]
