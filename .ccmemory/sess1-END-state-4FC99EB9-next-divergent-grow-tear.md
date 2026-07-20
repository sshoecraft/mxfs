---
name: sess1-END-state-4FC99EB9-next-divergent-grow-tear
description: sess1(a16ec5f2) END: build 4FC99EB9 = 3 root fixes (FACE-1 leak, grant-epoch order, AG-trylock). 8/tcp drc: 1 PASS (first!), 1 FAIL r20 = divergent-g…
metadata:
  type: project
---

# sess1 (run a16ec5f2) END STATE — build 4FC99EB9 deployed, criteria NOT met, marker NOT written

## Current build 4FC99EB94193AC30E9937D1 (= /src/mxfs/mxfs.ko, tree consistent) carries, in order:
1. FACE-2 reload imap retry (inherited C10470A6) — 4/tcp drc 6/6 (verified on C10470A6 only).
2. AG-trylock for exact_bno/near_bno single-AG allocs (args->mxfs_ag_trylock) — killed the -110 P36 retry storms (73-85/node → 1-19).
3. Attribution instr: P36 ag=/comm=, P67-AG-BAST-STALL ungated, P1-AGWAIT (nb-probe+stack ≤5/boot), P1-AGCONFLICT (master-side holder naming).
4. drain_evict raw down_read → mxfs_drain_ilock_read (P132 forensics, still blocking).
5. **FACE-1 ROOT FIX**: P-RELOAD-TORN-DISK-SKIP bail leaked down_write(i_lock)+snap → kfree+up_write added (see [[sess1-FACE1-ROOT-FIX-torn-disk-skip-leaked-ilock]]).
6. P-DBLALLOC detector gate fix (mxfs_diag_owner — was dead for bmap data allocs).
7. **grant-epoch ordering ROOT FIX** in mxfs_dlm_process_remote_grant (mirror w/ dir_epoch reconciled BEFORE pending_signal; provisional-insert+unwind for unsolicited) (see [[sess1-ROOT-FIX-grant-epoch-visibility-order]]).

## 8/tcp drc_reliability status on 4FC99EB9: 1 PASS (8/8, ALL 24 rounds — first ever in this run), then 1 FAIL:
### run7 FAIL r20 = DIVERGENT-GROW TORN MAP face (now the top blocker)
- test1 (rank1, EX holder at rm): **in-core dir fork = nx=4 WITH data-region HOLE** (P-IFLUSH-GAP-DETECT ino=131 nextents=4 comm=rm, t=2568) while ALL 7 peers held the true nx=9/24576 map (their P62-RELOAD-FORK-SHRINK show disk_nx=4 < incore 9, shrink=1, same gen).
- test1's dinode flush PUBLISHED the holey nx=4 map (disk_nx=4, leaf daddr 6279744 content ZERO — P54 magic=0x0 rc=-117 on test4).
- Verify does drop_caches → COLD reload from the TORN disk → readdir=101-103/800 (only node1's names, all lookup-ENOENT), test4 spun in verifier-EIO retry on the zero leaf (never finished verify) → barriers timed out → 0/8. No shutdown, no leak-wedge (fixes hold).
- **The fence exists but is DETECTOR-ONLY**: xfs_inode.c:5402 (sess49b comment): skipping the flush defers the tear → gapped in-core fork later OOPSes in xfs_dir2_leaf_addname; "real fix is upstream — prevent the divergent grow / heal the gapped fork BEFORE addname uses it". P65-IFLUSH-FENCE (block0-lowest-wins) IS enforced above it (5351). Params dir_iflush_fence=0 (sess65, different purpose), dir_iflush_owner_fence=0 (sess67 inert).

## NEXT SESSION (RULE 4 order):
1. Diagnose WHY test1's in-core map became holey-nx=4 while peers reached 9: walk test1's r20 timeline (scratchpad run7_8n/test1.dmesg, mount@line~grep, r20≈t2405-2568; watch P65-EPOCH-ADOPT/P63-HANDOFF/TORN-DISK-SKIP/FORK-SHRINK on test1 + its adopt decisions). Hypothesis: test1 kept refusing adoption (TORN-DISK-SKIP fired on test1 at dlm_mode=3 in run7 t=361 — it refused a disk map as torn while peers grew past it; its own map froze at 4 and later WON the flush race).
   NOTE: TORN-DISK-SKIP leaves i_dlm_stale=true + MXFS_IF_DIR_RELOAD armed — but test1 held/reacquired EX all round (MHT batching) — does the EX fast path ever re-run the reload? If not, its map never heals → holey forever → flush publishes it. Likely THE mechanism: **refused-adopt + never-retried-reload on the EX-batching node**.
2. Fix direction (pick after 1 proves): (a) on gap-detect at iflush: don't publish AND schedule a forced disk-superset merge/reload (union adopt, like P63-HANDOFF "forcing disk-superset adopt") so the in-core heals instead of OOPS-deferring; (b) make TORN-DISK-SKIP's armed reload actually re-run on the next EX-holder op (check MXFS_IF_DIR_RELOAD consumption path); (c) prevent the divergence: the grower's release must land leaf+data BEFORE dinode extent-count grows visible (ordering in release drain: currently dinode can publish nx ahead of leaf content? run7: leaf daddr zero ON DISK while SOME dinode... actually disk nx=4 didn't reference... test4's P54 says bno=8388608 (leaf) → daddr 6279744 zero: the TORN 4-extent map DID reference a leaf whose write never landed. test1's leaf write never destaged before its dinode flush → intra-node ordering bug on test1's own flush path too).
3. Then: drc 8 xN until ≥5-6 consecutive clean; drc 4 regression (~4 runs); FULL suites `./run.sh N tcp` for N=1,2,4,8 (criterion = full ~17-test suite per column, sess49 memory); marker ONLY on all-100%.

## Env/infra notes this session
- drc faces-grep shows STALE dmesg lines (nodes not always rebooted between runs) — always cut at last 'Ending clean mount'; run5's "identical faces" confusion documented.
- run.sh run_coord already gives dir_reuse@8 tt=480s ✓ (not 300).
- 8-node round pace: r1-6 ~10s, r7+ ~15s (phase change unexplained; log-fill suspect; fits 480s — RULE-0 item, not the blocker).
- rm -rf of 800 files ≈ 4s (per-file AG-EX inactivation sweeps; perf item).
- Node dumps: scratchpad run1..run7_8n; run5 r23 snapshots t4_create_r23.dmesg/t1_failverify_r23.dmesg (grant-epoch clobber evidence).
- Tasks: #4 full-suite (pending), #5 epoch-fix verify (in_progress), #6 stability batch (in_progress).
- User said all test1-32 VMs available for parallel testing — single shared LUN limits true parallel clusters (would need 2nd backing file + MQTT namespace separation); deferred.
