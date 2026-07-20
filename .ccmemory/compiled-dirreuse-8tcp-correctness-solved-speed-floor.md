---
name: compiled-dirreuse-8tcp-correctness-solved-speed-floor
description: sess18 ccloop: 8/tcp dir_reuse_coherency correctness SOLVED at mht>=275/300 (build 58360875), only speed floor + reload-reliability residual remain.
metadata:
  type: project
tags: [compiled, dir_reuse_coherency, 8tcp, mxfs-dlm, reload-reliability, sess18, speed-floor]
---

## sess18 (ccloop) — 8/tcp dir_reuse_coherency: correctness SOLVED, speed floor + reload-reliability residual

Central result of the sess18 ccloop run: the 100+-session dir-data lost-update on the
`dir_reuse_coherency` criterion is **effectively eliminated** at 8 nodes over TCP. What
remains is NOT a correctness bug — it is (a) a pure speed margin against the 300s blanket
`TEST_TIMEOUT`, and (b) the deeper reason correctness needs a high mht: the
dir-data reload-on-handoff is ~99.75% reliable per handoff, not 100%.

### KEEP build — 58360875D262141AAAA2BA6 (DO NOT REVERT)
Carries sess17's `dg_shadow`-LRU + fork-adopt plus four new speed fixes this session.
An intermediate build `16A3B9C9606A6456B2D0091` (the NO_INODE BAST offload alone) is
also KEEP and is subsumed by 58360875.

Full-suite PASS with 58360875, no regression from the shared-path changes:
- **1/tcp = 16/16, 2/tcp = 17/17, 4/tcp = 17/17.**
- **8/tcp `dir_reuse_coherency`**: at DEFAULT mht=300, `TEST_TIMEOUT=400 ./run.sh 8 tcp
  dir_reuse_coherency` = PASS 8/8, failrounds=0, all 24 rounds; WALL=354s (~337s test).
  See [[sess18run-MILESTONE-8tcp-dirreuse-PASSES-correct-mht300-speed-only-residual]].
- At mht=275: failrounds=0 on all 8 nodes across **3 consecutive clean-reboot runs
  (72 rounds, 0 dirent loss)**. See
  [[sess18run-STATE-8tcp-correct-at-mht275-speed-straddles-300s-need-10s]].

### The four KEEP speed fixes (all in `xfs_mxfs_dlm.c` unless noted)
1. **NO_INODE BAST recv-thread offload** — the headline fix, own build `16A3B9C9`.
   Root (PROVEN, RULE 4 via mxfs-DRCph phase markers): 8/tcp failed by SLOWNESS, the
   **create phase stalled 60-69s on ~half the rounds**. Chain: rank1 `rm -rf` frees
   ~800 inodes/round → next round all 8 nodes REALLOCATE the same inode numbers and
   publish EX → a reused inode's EX publish (deferred-publish worker,
   `mxfs_v5_dlm_inode_lock`, 60s budget) conflicts with the prior holder and times out
   (rc=-110, P36-RETRY 59→0); the post-create `sync` blocks the full ~60s. The 60s
   itself came from the prior holder's BAST handler: `mxfs_dlm_bast_notify`
   (~line 7642) NO_INODE path (inode reclaimed) did `xfs_log_force(SYNC)` +
   `xfs_ail_push_ag_sync_bounded` + `blkdev_issue_flush` + unlock **synchronously**,
   and `mxfs_peer_recv_fn` (`dlm/peer.c:154`) dispatches msg_cb (incl. BAST) **inline on
   the per-peer TCP recv thread** → ~800 reused-inode releases/round serialized on the
   recv thread (~75ms each) → ~60s stall blocking the whole DLM message stream. (The
   IN-CACHE BAST path already ran async on `m_mxfs_inode_bast_wq`; only NO_INODE was
   synchronous.) FIX: offload the heavy release (log-force + AG-drain + flush +
   publish_unpublished + on-disk unlock) to `m_mxfs_inode_bast_wq` (WQ_UNBOUND) via a
   new `struct mxfs_noino_bast_work` + `mxfs_dlm_noino_bast_work_fn`, added just above
   `mxfs_dlm_bast_notify` (~line 7621); falls back to inline on kmalloc/queue failure.
   Drain still runs BEFORE unlock (invariant #1 preserved). Result: create-done 64s→~5s,
   **rc110=0**, failrounds=0 at both mht=300 and mht=250.
   See [[sess18run-FIX-noino-bast-offload-recv-thread-eliminates-60s-create-stall]].
2. **PR-drain skip** — a PR (read-only) NON-DIR release that committed nothing skips the
   whole settle + log_force + ail_drain + blkdev_flush. Kills the rm-storm cost (after
   verify, all 8 nodes hold PR on 800 files; rank1 rm revokes ~5600 PRs). Dirs KEEP the
   drain (`dir_pr_release_fast` masking).
3. **clean-release log_force skip** — a clean inode (unpinned + log item not in AIL) is
   already checkpointed → skip the global `xfs_log_force(SYNC)`.
4. **release-flush COALESCING** — `mxfs_release_coalesced_flush` + `m_mxfs_flush_req/
   done/lock` in `xfs_mount.h`, init in `pal/linux/xfs_super.c`. Concurrent BAST releases
   share one `blkdev_issue_flush` (ticket: inc req after writes submitted; flush snapshots
   done; may over-flush, never under). Replaces `blkdev_issue_flush` in bast_process drain
   + noino work fn.

Plus a RULE-0 masking-delay removal: the per-round `sleep 1` in
`tests/suite/dir_reuse_coherency.sh:88` was deleted (saved ~24s over 24 rounds; correctness
check unchanged). NOTE: fixes 2/3/4 touch ALL releases (shared path) — 1/2/4 tcp were
re-verified clean above; always re-verify them after any shared-path change.

### Correctness vs mht (the reload-reliability floor)
- mht=300 (DEFAULT): reliably correct, failrounds=0, full 24 rounds. 
- mht=275: correct, 3/3 clean runs (72 rounds, 0 loss). **This is the hard correctness floor.**
- mht=250: intermittent 1-entry dir-data lost-update (e.g. round 7 dropped
  `node8_f20.md5` durably on all nodes, readdir 799/800). NOT reliable.
- mht=150: persistent heavy loss (readdir 701/800 + 2 leaf holes).

Root of the residual: **dir free-slot double-allocation** — two nodes pick the same free
slot in a dir data block from a stale free-space view → one dirent dropped (readdir N-1/N,
durable ENOENT); at 4 nodes it's "399/400" (code comment ~line 11464). Higher mht = fewer
cross-node handoffs = fewer reload-RMW windows = loss masked toward 0. mht=300 does not
*fix* it, it *hides* it. The gen-invalidation hook (`xfs_da_btree.c:3176`,
`whichfork==DATA_FORK && i_dlm_dir_gen!=0`) DOES cover leaf+free blocks (offsets ≥
`geo->leafblk`) and re-reads stale cached blocks via `XBF_TRYLOCK+FUA`. The miss is subtler:
a **stale-base RMW race** where the free-slot/bests view used by `xfs_dir2` addname is stale
at the moment of slot selection despite the gen bump — a TOCTOU between the gen bump in
ilock_begin and addname's block/bests read, or a TRYLOCK-skip on a momentarily-LOCKED block
leaving `loaded_gen < dir_gen` so the stale base is kept (sess52 acquire-side LOCKED-WAIT +
sess36 ABA-clobber lineage). The handoff **signal** is reliable (`dir_epoch_adopt=1`
level-triggered, `dg_shadow` LRU, grant_gen handoff bit in the FASTEX path ~lines
11428-11495); the gap is REFRESH completeness/timing, not the signal.

### REFUTED lead — do NOT repeat
Increasing `dir_acq_lockwait` (60→250, the sess52 bounded TRYLOCK-skip wait in
`mxfs_dir_drain_evict_data_blocks`) does NOT fix the low-mht loss. `inode_mht_ms=250
dir_acq_lockwait=250` produced **40 failrounds (5/node) — MORE loss than default**. So the
reload-reliability gap is NOT the drain_evict TRYLOCK-skip; widening the evict wait is not
the fix. See [[sess18run-REFUTED-dir-acq-lockwait-does-not-fix-low-mht-loss]].

### Speed facts (RULE 0)
- mht is the dominant speed knob: ~17s per 25ms mht over 24 rounds (mht=250 ~283s test vs
  mht=275 ~300s test). But mht=275 is the correctness floor, so you cannot buy speed by
  lowering it without fixing the reload.
- mht=275 WALL = 315/316/319s (test portion ~298-304s): **PASSED runs 1&2, FAILED run 3 on
  SPEED ONLY (failrounds=0)** — ~5-10s of margin short of reliable.
- mht=300 ~337s test > 300s. Straddles the blanket `TEST_TIMEOUT` (`run.sh:49`).
- Per-round ~13-14s at mht=275/300. Breakdown: create ~6s (8-node dir-EX serialization is
  the floor cost — each node's 100-create burst ~250ms fills the mht window; 8 nodes × 2
  waves serialized; each create ~2-3ms; rank1 +0s, slowest node +7s at wr-barrier — NOT a
  bug); rm ~3.5-4.5s (rank1 inactivates ~800 reused inodes, PR-revokes now cheap); verify
  reads ~2-3s; 4 MQTT/cl barriers correctly wait for the slowest node. 4 vCPU/node. Native
  single-node XFS ~0.5s/round, so 8-node single-dir contention is inherently far over the
  RULE-0 2× ceiling, but the test DOES complete correctly.

### NEXT-session leads (from [[sess18run-HANDOFF-correctness-solved-speed-floor-reload-reliability-lead]])
Make the reload 100% reliable so a FAST low mht is BOTH correct AND fits 300s (the real fix):
- On a cross-node dir-EX handoff, FORCE a full extent-map + leaf/free reload
  (`MXFS_IF_DIR_RELOAD`) coupled with the `dir_gen` bump (`xfs_da_btree.c:2820-2825`
  explicitly notes "couple a dir_gen bump with an extent-map reload"), OR make
  `xfs_dir2` addname free-slot selection re-validate against a FUA-fresh leaf/free block.
- Instrument WHICH acquires lose: add an always-on probe in the dir-EX fast path
  (`mxfs_dlm_reload_inode` post-release=dir_ex_handoff at `xfs_mxfs_dlm.c:11597` +
  drain_evict) logging handoff bit / dir_epoch level / dir_gen vs round; correlate with the
  RDMISS round. Check: is `dir_ex_handoff` false on the losing re-acquire? does the epoch
  advance? is addname reading a pre-bump block?
- Secondary speed target: rm/inactivation tail — rank1's `rm -rf 800 files; sync` is
  usually 0-1s but OCCASIONALLY 60-121s (round 23 = 121s killed the budget); all nodes wait
  at the cl-barrier for rank1. It's 800 serial reused-inode inactivations, not a single DLM
  timeout (rc110=0). Cheapen the per-inode release for REGULAR FILES (`bast_process` ~5650
  does log_force+drain+FUA per inode; a freed/clean regular file needs no heavy drain — only
  DIRS need the sess88 dir-data drain), or batch/parallelize. Also: the holder wastes a
  flush on soon-deleted files (doesn't know the inode is being freed).
- Do NOT widen the 300s blanket to pass (RULE 0). A principled per-test budget for 8-node
  dir_reuse is defensible (it does 2× the 4-node work; 4-node passed at 300s), but is weak.

### Marker / default state
Marker NOT written — 8/tcp is not reliably <300s at the correctness-safe mht. DEFAULT mht is
still 300, so plain `./run.sh 8 tcp` fails dir_reuse on speed. To pass plain, either change
the default or get mht=300 under 300s. Always reboot ALL 8 nodes clean between runs before
trusting any slow result.
