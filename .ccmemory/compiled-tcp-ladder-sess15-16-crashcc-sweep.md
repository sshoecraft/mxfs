---
name: compiled-tcp-ladder-sess15-16-crashcc-sweep
description: TCP DLM ladder sess15-16: crash_consistency roots (FIX-H/I), single-node perf (J/K), lock-set ABBA (L3) → clean 1/2/4/8 sweep B48AC2C8.
metadata:
  type: project
tags: [compiled, tcp-dlm, crash-consistency, validation-ladder, lock-ordering, single-node-perf]
---

# TCP DLM ladder sess15–16: crash_consistency, single-node perf, lock-set ABBA → clean 1/2/4/8 sweep

Central thread: driving the ship criterion **"1/2/4/8 node tcp dlm test working 100%"** to met. sess15 fixed the crash_consistency correctness faces (FIX-H family, FIX-I) and closed most of the single-node perf gap (FIX-J); sess16 killed the last single-node CPU residual (FIX-K) and the multi-node lock-set ABBA (FIX-L3), then accumulated the streak. Final build **B48AC2C8629294ADF396154** = 3 consecutive fresh-boot sweeps, 12 runs, 0 FAIL. [[sess16run-CRITERIA-MET-three-clean-sweeps-B48AC2C8]]

## Build progression (hashes)
- **CBD34F20** — FIX-H (orphan_live abort + P135 GRANTWIN-PARK). [[sess15run-FIXH-orphan-release-eats-fresh-grant-ROOT]]
- **7C321E23** — FIX-H2 (strike escalation) — REGRESSED, do not revisit its shape. [[sess15run-FIXH3-final-shape-and-validation-ladder]]
- **3C674F70** — FIX-H3 (+ `!p_self_demote` exemption). First 8/tcp 17/17 (r14).
- **3AD15DA9** — 3C674F70 + P15I sector-CRC probe. [[sess15run-STATE-ladder-tally-and-crashcc-face]]
- **61FE57FD** — + FIX-I (durable-before-visible). [[sess15run-FIXI-evicted-unpub-child-durable-before-handoff]]
- **0F1666F1** — + FIX-J1/J2 (single-node log-force gates). [[sess15run-FIXJ-single-node-logforce-and-paired-bench-state]] [[sess15run-HANDOFF-state-and-next-steps]]
- **F7A60942 → (FIX-K)** — lockless is_single_node. [[sess16run-FIXK-lockless-single-node-gate-PROVEN]]
- **CC3B3372** — FIX-L2 (dirs-first Phase-A) — REGRESSED (convoy), do not revisit. [[sess16run-FIXL2-dir-dlm-phaseA-before-rwsems]]
- **B48AC2C8** — 0F1666F1 + FIX-K + P16-ILOCKED probe + **FIX-L3** (ascending-all Phase-A). Final. [[sess16run-FIXL3-ascending-all-phaseA-CLEAN-SWEEP]]

## Root cause 1 — orphan release eats a fresh grant (double-EX / dirent swallow) → FIX-H3
sess14's tenure-order reading was INVERTED: it compared fractional realns clocks across nodes (N6 realns ~1.03s offset from its mono vs N4) and mis-assigned order. True sequence: the TCP receive kworker links the local mirror **before** the blocked acquirer thread resumes and bumps holders; `mxfs_v5_dlm_inode_held` reads that same local mirror, so a queued P135 orphan-release BAST running in the `[mirror-link → holders++]` gap saw held/pin==0, gen unmoved, and wire-released the node's OWN just-granted live tenure → master re-granted the peer 0.7ms later → true DOUBLE-EX → both nodes wrote `f9@off=1800`, later writeback swallowed the peer's dirent (799/800). Coin-flip ~1-in-2 iter failure. [[sess15run-FIXH-orphan-release-eats-fresh-grant-ROOT]]

FIX-H (CBD34F20), xfs_mxfs_dlm.c: (1) bast_process P15-recheck backstop aborts when `p_held_mode==MXFS_LOCK_NL && p_rel_gen!=0` (cleanup-flavor vs live-gen); abort state = CACHED + bast_pending. (2) bast_notify queue-time gate: query grant_gen; `held==1 && gg!=0` → P135-GRANTWIN-PARK (arm MHT dwork, don't queue orphan release). `gg==0` keeps the old path — CAW disk-slot semantics unchanged (grant_gen always 0 on CAW).

FIX-H2 (7C321E23) added strike escalation + blocked the P109 EDEADLK self-demote — this WEDGED the cluster (r13 12/17). Lesson: the self-demote at xfs_mxfs_dlm.c ~18181 (bastq_src=6) is THE resolver for a grant our own retry loop stranded; it presents the exact orphan_live signature (in-core NL + live mirror gen). Blocking it makes each master re-grant a fresh gen so strikes reset to 1 forever → LKTIMEOUT rc=-110 shutdown cascade. FIX-H3 (3C674F70) added `!p_self_demote` exemption to orphan_live → r14 8/tcp 17/17. [[sess15run-FIXH3-final-shape-and-validation-ladder]]

## Root cause 2 — crash_consistency evicted unpublished child not durable → FIX-I
crash_consistency is a cold-reload durability test (umount/mount, no crash). Decoded on 2/tcp r6, ino 0x883400: creator makes the last md5 sidecar → child inode unpublished (local EX, icreate+dinode in log only); the test's drop_caches EVICTS the child on the creator, unpub entry later popped by dir-handoff publish drain → **P78-PUB-SKIP** (sess9 FIX-28) correctly skips the master claim but NOTHING made the child's dinode-cluster durable, yet the dir handoff made the dirent peer-visible. Reader PR-acquires by number, grants cleanly (empty resource, no BAST/mirror), FUA-reads the PRE-icreate platter (prior-mkfs dinodes) → `xfs_dinode_verify` UUID reject (xfs_inode_buf.c:891 uuid_equal) → EFSCORRUPTED; iget retry ladder re-reads the same platter ×8 → EIO → FAIL. Platter self-repairs later when creator's async delwri lands — **do NOT trust late raw-disk reads to refute this face.** [[sess15run-FIXI-evicted-unpub-child-durable-before-handoff]]

FIX-I (61FE57FD), xfs_mxfs_dlm.c P78-PUB-SKIP arm in `mxfs_dlm_publish_drain_loop`: on skip, `xfs_imap` → `xfs_buf_incore(TRYLOCK)` the child cluster buf; if dirty (DELWRI_Q|pinned|LI_DIRTY|LI_IN_AIL|li_list non-empty): `xfs_log_force(SYNC)` + `xfs_ail_push_all` + bounded poll ≤250ms until clean/off-AIL; peer stays blocked on the dir BAST until return = durable-before-visible. Validated 2/tcp r7 17/17, P15J fired 126× waited_ms=0 settled=1 (log force alone settles — cheap).

Related open face at the time: 8/tcp r3 inobt CRC flavor (daddr 0x7fc2b8 / 8372920 after P126 staling) — same eviction-family suspect for AG-meta. P126-XFSAILD-SKIP-AGMETA staled a DIRTY IN-AIL inobt (discarded committed metadata — tension with sess43 invariant BB54A138). Post-mortem raw disk was VALID (CRC calc==stored d12f8902); failure was in the tail 3.9KB (torn in-core page mix or durable-then-repaired). Suspect #1 = P126 staling `in_ail=1 dirty=1`; fix direction (sess43) = refuse discard when buffer carries this node's committed-undrained mods, but beware sess23 (suppression misfires themselves corrupt) and log-tail-pinning tension. Did not recur in the final sweeps. [[sess15run-STATE-ladder-tally-and-crashcc-face]]

## Single-node perf — FIX-J then FIX-K
single_node_paired failing 114–144% (mxfs leg ~3.4–3.6s vs native 2.8–2.9s). Geometry EXONERATED (native `mkfs.xfs -d agcount=50 -i size=512` = 2830ms). Read-count theory DEAD (native-50AG does the same 7-reads-per-AG walk). Real gap = ~550 extra barrier round-trips: 211 of 213 `xfs_log_force` calls came from `mxfs_ag_dlm_unlock.part.0` (the v0.3.136 throttled async force, every-128th unlock). **FIX-J2**: gate that force on `!is_single_node` (single-node CIL pushing is native XFS's job) → 213 forces→3, FLUSH 378→12, WFSM 215→6, leg 3.4s→2.9–3.1s. Gap 17%→~5%. Both J gates are is_single_node-only; multi-node semantics untouched. Also rewrote the bench (`tests/tooling/single_node_paired.sh`): old single-leg X-then-M was a host-cache coin flip (disk.img writeback ~700MB/leg gives xfs pole position); now 4 position-balanced rounds (XM MX MX XM), trimmed mean, threshold 105%, legs echo "ms files" (subshell var-loss bug fixed). [[sess15run-FIXJ-single-node-logforce-and-paired-bench-state]]

The remaining ~5% floor was the sess15 handoff blocker (plus fio_vs single-shot host-cache swings). [[sess15run-HANDOFF-state-and-next-steps]] **FIX-K** (sess16) closed it: RULE-4 chain via new in-tree `tests/tooling/paired_perf_diag.sh` (ftrace function profiler) measured **2,276,687 calls to `mxfs_dlm_is_single_node` in ONE paired rsync leg** — its internal mutex (dlm/dlm.c) was the +2% CPU / ~5% wall residual; called from every buf lookup/submit/release site in pal/linux/xfs_buf.c. Patch: bare `count <= 1` read (int, written only under mutex at init/update_active_nodes; precedent dlm_membership_settling reads it bare; CAW arm already lockless). Dead leads ruled out same run: xlog_grant_head_wait 49 native vs 0 mxfs (log size fine), P78/P15J 0× single-node, mxfs buf ops fewer than native. Result: paired ratios 106/107→97–103, 4 consecutive PASS; **1/tcp column 16/16** (first fully-clean 1-node column). Not-yet-done micro-opts: cache a bool in mxfs_v5_dlm; batch the 63 sync 512B heartbeat reads (disklock_hb_fn) into one 32KB (<1%). [[sess16run-FIXK-lockless-single-node-gate-PROVEN]]

## Root cause 3 — lock-set ABBA (dir↔AG cross-node) → FIX-L3
k1 wedge (2/tcp, F7A60942, tds 0/2): test2 blocked on AG-4 EX held by test1 for 312s (`P-LKTIMEOUT-HOLDER ... held_ms=312065`, cached by design); test1 blocked on dir 8530875 PR→EX conversion denied by test2 (`P-CONVBLK-DENY ... deny→EDEADLK`, DLM rc=-35 retry storm). Root: `xfs_lock_inodes` sorts ascending → child ILOCKed before dir; the sess58 arm then did **blocking** `mxfs_dlm_ilock_begin(dir,EX)` with the child rwsem held; `xfs_iflush_cluster` REQUIRES `xfs_ilock_nowait(SHARED)` → child unflushable → AG-4 drain stalls (`P67-AG-BAST-STALL`, `stuck_ino ... sess118-neverflushed`) → peer starves → cross-node ABBA. [[sess16run-FIXL2-dir-dlm-phaseA-before-rwsems]]

Fix evolution (do not regress the reverted shapes):
- **L1 (399BEA9F, REVERTED)**: DLM-try + bare begin/end + goto-retry → grant ping-pong livelock (ilock_end at 0 holders fires peer BAST inline, forfeits instantly). 2/tcp: rm 184s rc=-110 shutdown cascade. **Lesson: a dir grant can only be kept across a retry by HOLDING it (ex_holders≥1).**
- **L2 (CC3B3372, REVERTED)**: Phase A for EX-DIRS only before rwsems (GFS2 pattern). Fixed the k1 ABBA but created a CONVOY — removes held the shared dir EX across cross-node CHILD acquires → 8/tcp drc round-12 create phase 200s+ → 0/8 timeout (drc readdir=197 exp=200 undercount, lookups fine).
- **L3 (B48AC2C8, KEEP)**: Phase A = EVERY set member, ascending ino, mode from `mxfs_setlock_dlm_mode` (EXCL→EX else PR; 0 when no m_mxfs_dlm) — reproduces the historical per-`xfs_ilock` DLM acquisition order (child grant settles before dir when child<dir) minus the rwsem-held-across-DLM-wait hazard. Phase B: pre-held members take rwsems `xfs_ilock_nowait`-only; backoff releases rwsems RAW via new `mxfs_iunlock_rwsems_raw` (keeps the DLM hold + `mxfs_ilk_note_unlock`). Applied to BOTH `xfs_lock_inodes` and `xfs_lock_two_inodes`. Helpers `mxfs_setlock_dlm_mode` / `mxfs_iunlock_rwsems_raw` above xfs_lock_inodes in xfs/xfs_inode.c. Global order now: dir grants (ascending) before ANY rwsem before child DLM → acyclic. [[sess16run-FIXL3-ascending-all-phaseA-CLEAN-SWEEP]]

## Criteria met — evidence
Final B48AC2C8 = 0F1666F1 + FIX-K + P16-ILOCKED probe + FIX-L3. 12 consecutive suite_iter runs (each = full VM recycle + fresh mkfs + full battery incl. fencing/netpartition/crash/soak/tds), ALL zero FAIL: 1/tcp 16/16 ×3, 2/tcp 17/17 ×3, 4/tcp 17/17 ×3, 8/tcp 17/17 ×3. criteria.json 1/2/4/8 tcp columns 100% PASS, 0 pending/skipped. Logs preserved in `tests/results_sess16_streak/`; marker `.ccloop/runs/a9a03929-.../criteria-met = YES`. [[sess16run-CRITERIA-MET-three-clean-sweeps-B48AC2C8]]

## Armed probes for any future flake (zero-cost, attribute in one grep)
- **P16-ILOCKED** `ilocked=` field inside P67-INSTR `AG-AIL-STALL` (xfs_trans_ail.c) — held-ILOCK flush block.
- **P129-CLSKIP** `why=ILOCK_NOWAIT_FAIL` — prints rwsem owner comm (iflush skip).
- **P15I-CRCFAIL** sector-CRC fingerprint (pal/linux/xfs_buf.c `__xfs_buf_ioend`) for the inobt read-fail flavor.
- **P15J-PUBSKIP-FLUSH** (settled=0 would mean 250ms wait too short).
- **P135-GRANTWIN-PARK** same-ino streaks = stranded-grant ping-pong.

## Open / watchlist (not blocking criteria)
- tds long-tail has two distinct mechanisms: r21 (0F1666F1 8/tcp) = REL-ABORT starvation flavor (distinct from the k1 ABBA, theoretically possible under extreme same-ino churn); k1 = the ABBA (fixed by L3).
- fence_during_write "own data intact" own-data face (r11 node7, r12 node4, got-file exactly 4096, healed=0 durable) — probabilistic, PASSed since FIX-H3, best theory = FIX-H/H2 collateral; forensics in tests/suite/fence_during_write.sh.
- drc readdir-undercount signature (197/200, missing=[]) — if it recurs on longer Phase-A dir-EX holds, start at xfs_dir2_readdir.c coherency gates.
- Unaddressed-on-purpose (one fix at a time): P6Z reconcile flavor `mxfs_v5_dlm_inode_release_unconditional` stranded-sample window (xfs_mxfs_dlm.c ~12064-12083); candidate = refuse under table_rwlock if a local-owner GRANTED/CONVERTING entry exists. Needs evidence before landing.

## Harness notes
`tests/cc_loop.sh` = targeted crash_consistency reproducer (N, dlm, laps, optional pre-test). `suite_iter.sh` destroys test1-8 regardless of N (fixes r4a leftover-LUN-holder abort). `tests/tooling/single_node_paired.sh` = 4 balanced rounds, leaves node mounted on fresh mxfs. `tests/tooling/paired_perf_diag.sh` = ftrace/perf/stats per-leg profiler.
