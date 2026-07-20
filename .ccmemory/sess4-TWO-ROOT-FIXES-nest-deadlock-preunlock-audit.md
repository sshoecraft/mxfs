---
name: sess4-TWO-ROOT-FIXES-nest-deadlock-preunlock-audit
description: sess4(a9a03929) build 75F70CA40: FIX-1 nested-IOLOCK/ILOCK DLM self-deadlock (admit/escape at state=BAST) + FIX-2 enforcing pre-unlock dir audit. run…
metadata:
  type: project
---

# sess4 (ccloop a9a03929) — two root fixes; run72 = drc 8/tcp PASS on build `75F70CA401646F3BE5327AF`

READ WITH [[sess3-END-first-8tcp-drc-PASS-four-root-fixes]].

## ROOT 1 (runs 68/69/71 — the 0/8 480s cluster-kill wedge): nested-hold DLM self-deadlock

`xfs_ilock` maps IOLOCK **and** ILOCK onto the ONE per-inode DLM lock (xfs_inode.c:173-200, single holder counts). Every buffered write nests: IOLOCK_EXCL (DLM EX, ex_holders++) → `xfs_file_write_checks` → `file_remove_privs` getxattr (ILOCK_SHARED → DLM PR) / `file_update_time` (ILOCK_EXCL → EX). If a BAST/demote window opens between outer and inner acquire, the inner waits in ilock_begin's DEMOTING/BAST wait_event for a release that itself requires holders==0 — i.e. the waiter's own outer hold. Permanent: P15-REL-ABORT re-arms BAST, ilock_end re-fire needs exact-zero counts, bast_notify's DEMOTING arm ("already processing") swallows every master re-BAST with **no liveness check** (work_busy==0 = swallowed forever). Blast radius: the reused-inum convoy — every node's next create in that AG queues behind the phantom EX (master's LKTIMEOUT-HOLDER dump shows the stuck node GRANTED-EX + 7 PR waiters retrying 1s×60). Proven twice live: run68 test8 ino=6293428, run69 test3 ino=8388765 (P73-WAITSTALL state=2 ex=1 work_busy=0 + /proc stack in remove_privs; master dump held_ms=127822).

**FIX-1** (xfs_mxfs_dlm.c, two arms: pre-wait + in-loop-post-wake): at `state==BAST && (ex||pr)>0 && demoter!=current`, consult the v5 mirror (`mxfs_v5_dlm_inode_granted_mode`, new accessor in dlm.c/v5_mount.c):
- mirror mode ≥ request → ADMIT (restore i_dlm_mode from mirror — abort paths leave it NL which trips non-EX authority guards); P79-NESTADMIT.
- mirror < request (incl. empty; run71 found the PR-held/EX-wanted upgrade variant, test4 ino=6291589) → `state=NONE` + wake → waiter takes the REAL slow path (convert to master; peers' BAST re-delivered by their 1s retries); P79-STALEBAST-CLEAR.
Safety: at state==BAST no drain is in flight (release deferred until holders==0); local task-vs-task exclusion is the rwsems' job — the DLM layer only answers node-level "do we hold ≥ mode". Last ilock_end still re-fires a FULL fresh drain. run72: 4× P79-STALEBAST-CLEAR (t2/6/7/8), each a formerly-fatal wedge, self-recovered; PASS.

## ROOT 2 (run70 — round-1 readdir=799, node7_f45.md5 durably lost cluster-wide): unlock before land

test7's dir-EX tenure gen=213: bash's create fast-path-admitted DURING a queued self-demote release; its P13-NADD (wall .690) landed AFTER the release fence's durability pass but BEFORE the unlock (P6U .6907); the block write went out at .6996. test3 acquired EX in the gap (concurrent epoch 49), cold-read the pre-add platter, placed node3_f44.md5 at the SAME aoff=1376, and its later xfsaild image (+test7's own next cold-read adopting it) durably dropped f45.md5. Contributors: `mxfs_dir_data_durable` returns VACUOUS-TRUE for BTREE forks with unread extents (P42-VACUOUS-DURABLE, known gap-B); P43-OWNERSCAN flush=0 saw cand=3 but was advisory; P3B audit was PRINT-ONLY; clean_skip/self-demote trusted `xfs_inode_clean` which is blind to dirty dir DATA buffers (a node-format add doesn't dirty the dir inode item).

**FIX-2** (xfs_mxfs_dlm.c P3B site): the pre-unlock audit is now ENFORCING — loop {mxfs_dir_data_durable + !in_AIL + pin==0 else xfs_log_force(SYNC) + xfs_ail_push_ag_sync + mxfs_dir_flush_data_blocks_relsafe + msleep(2)}, bounded 5000 tries (~10s) then SHUTDOWN (never release stale — Invariant #1 at the last gate).

## Probes added (all capped, not ratelimited — ratelimiting cost the decisive datum TWICE)
P70-BP (bast_process ENTRY/EXIT=unmount|full; P15/P6G/P6Z tag the other exits — P15+P6Z converted ratelimit→cap), P71-HOLD (holder transitions while state∈{DEMOTING,BAST}) + P71-UNDERFLOW (guarded-skip mispairs; bash create path has a real unbumped-EX-end — benign, guard eats it), P72-SWALLOW-DEAD (notify DEMOTING arm w/ work_busy==0), P73-WAITSTALL (demote-wait self-reports every 30s w/ full state — replaces naked wait_event), P74-GRANT (dlm.c ALL inode grants: matched/have_mirror/prov — the re-affirm ABSORB arm at dlm.c:3683 updates an existing GRANTED mirror on matched=0 WITHOUT reject — known desync hole, not yet fixed), P76-QW-FALSE (queue_work false w/ DEMOTING set), P77-GRANTNEW-CLOBBER (grant_local_new overwrites live state), P78-PUB-PHANTOM (publish drain claims master EX while FS-layer not EX — fired in every wedge run; publish_drain_loop at 17091 has NO FS-state reconciliation — future fix candidate), P79 (FIX-1 actions), P19-B3DEC ratelimit→cap.

## Infra traps (new)
- `/root/drc_failrounds.txt` on nodes is CUMULATIVE ACROSS RUNS (never truncated) — only the last section is the current run.
- drc saves per-round ring snapshots `/root/drc_create_rN_rankR.dmesg` — the round-1 evidence survives ring rotation there (main ring rotates in ~5s under probe load).
- Cross-node dmesg comparison: per-node monotonic clocks differ by boot stagger (~0.6s/node); align via btime (1s granular) or the probes' realns= fields.
- P70 cap 6000 exhausted in ~85s of drc storm — for bast-level tracing rely on realns-stamped P3W/P71 or raise caps.

## Ladder state
run72 = consecutive PASS #1 on build 75F70CA40 (target 5), then full `./run.sh N tcp` N∈{8,4,2,1} (ALL recorded criteria.json results for non-drc tests predate sess3-4 fixes = must re-run). Marker NOT written.
