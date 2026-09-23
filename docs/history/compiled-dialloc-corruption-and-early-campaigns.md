<!-- Compiled: the 2-node dialloc/inobt corruption campaign (ccloop4dd7) plus early-numbering lessons — 8 proven roots, harness contamination incidents, t… -->
# The dialloc/inobt corruption campaign + early-numbering lessons

## 1. ccloop4dd7 — eight proven roots on a 2-node TCP rig

The physical pve nodes were unreachable, so the campaign pivoted to a **2-node VM rig** (test1/
test2 on clyde's own kernel, so a local `make modules` serves them over NFS) with a deterministic
churn reproducer, `scripts/agi_wedge_repro.sh` — one invocation per Bash call (~230s; batching
three blows the timeout) (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).

The unifying shape: **a peer's freed inode is adopted as a live in-core "mirror"**, and the local
node then re-runs a destructive path on it.

- **Dead-shell defer + recycle sanitize** — an IRECLAIMABLE, nlink==0 shell on the CREATE path
  skipping the free-state check; disk-free means emulate the missed local uninit
  (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **Zombie keep was handoff-blind.** A peer's realloc with a *random* generation defeats a
  `gen+1` arm, so the adopt now also accepts the grant-handoff bit. Proven on a case where the
  two generations were entirely unrelated (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`,
  `docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **difree double-free → -ESTALE.** test2's mirror adopted `nlink=0` from disk and the VFS
  re-inactivated it. The prior guard missed because `xfs_inode_on_unlinked_list()` is **per-node
  in-core state, never set for an adopted mirror**. Fix: return -ESTALE from the double-free
  point (the transaction is still clean — only lookups had run) and convert that to a clean skip
  (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **iunlink-remove on an empty bucket**, same mirror family but reached *before* difree, so the
  ESTALE backstop never applied (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **reload_inode's `shrink_dcache_parent` self-deadlock.** A new buffer-lock probe fired 20× with
  `lock_ip=0x0` — a buffer locked with no `xfs_buf_lock` caller. The live stack explained it:
  `rmdir → … → mxfs_dlm_reload_inode → shrink_dcache_parent → __dentry_kill → iput → evict →
  SYNC xfs_inactive` — running a child's synchronous inactivation **while holding the shared
  cluster buffer locked** (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **Owner-evict mid-tenure kill.** `mxfs_dir_evict_owned_data_blocks` ran mid-tenure on a
  self-echo generation bump and destroyed undestaged dir modifications; the corruption exit was a
  leaf-tail-bests vs data-block-bestfree mismatch. The proof was ownership timing: test2 held EX
  continuously across the whole window, and test1 never wrote the blocks
  (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **IOLOCK/DLM order inversion.** `xfs_ilock` took DLM admission **before** `i_rwsem`, so a task
  could hold a DLM EX admission while parked on the rwsem — phantom admissions that wedged the
  demote. Caught by a holder-stack instrument at strike 200
  (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **The CIL→AIL window.** A deferred AG unlock judged the bnobt "clean" during the async window
  where the commit callback had unpinned the BLI but AIL insertion was not yet visible
  (`pin=0, has_bli=1, li_empty=1, not-in-AIL`), cleared XBF_DONE, and 3ms later a cold read
  pulled the **lagging platter** over a committed-unwritten insert. The allocator then computed
  neighbours on a reverted base and produced a bnobt/cntbt pair that disagreed — written mixed by
  both nodes' xfsaild (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **`s_remove_count` underflow**, found because `soak` reported `dmesg_hits == ops` — one
  `Call Trace:` per workload op. Once the counter reaches -1 every unlink/destroy pair oscillates
  -1→0→WARN→-1 forever. Root: an IRECLAIMABLE reuse-reload ran on a **VFS-destroyed corpse**
  (I_CLEAR, its nlink already decremented), and a peer's live reuse then drove `set_nlink` 0→1,
  making the next decrement unpaired. Found with a shadow ledger routing every nlink write
  through wrappers plus provenance fields (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **TCP single→multi transition gap (split-brain).** An **inbound** connect at the joiner
  registered the peer in the lease and wiped the DLM lock table but never fired the join
  notification, and the joiner's own announcement then hit an early return — so the transition
  never ran on that node. Two nodes each wrote their own root dir with zero BASTs
  (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).

Still open at the campaign's stop-point: **divergent per-node inobt record content across AG
handoffs**, where one node's FREE showed a bit already set and content matching *neither* of the
peer's recent states — suspects were the in-AIL keep guard versus the Invariant-1 drain
(`docs/history/c-inobt-divergence-root-lead.md`).

## 2. Harness lies, contamination, and stale dashboards

These cost whole sessions and are the most reusable content here.

- **A watchdog that manufactured its own failure.** A hang-watchdog added that same day wrapped
  rank1's mkdir/rm-rf in a flat 20s timeout; nanosecond timestamps in the captured dmesg proved
  the "hung" rm was still making forward progress **9+ seconds past the declared hang**. It was
  legitimately slow, not stuck (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **Orphaned test processes from prior sessions poison every later run.** Tests that had passed
  in one session suddenly failed with 2×120s barrier timeouts cluster-wide on the *same build* —
  because prior sessions' phase runs were still alive as orphans, 2h18m old
  (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **Two ccloop wrappers resumed the same run concurrently** after a host reboot, contaminating
  every result in a 23-minute window (`docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **A stale dashboard masks real regressions.** A user-ordered clean re-run — clear ALL PASS
  entries to not-run, re-run the entire gate — exposed three-plus hidden FAILs behind an
  18/19-PASS board (`docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **A test's first run after VM reboot absorbs cold prep** (NFS/iSCSI/sshd) inside its own budget
  and gets watchdog-killed with no RESULT line — hence a warm-up prologue that aborts early if
  the environment is broken (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).

## 3. The wedge2a lost-wakeup, finished

The `b_sema.count` read **83** on a live-wedged repro via `/proc/kcore` — not guesswork. Earlier
fixes had patched *which branch* a completion takes via a single overwritable per-buffer bool,
but none stopped an unrelated concurrent submitter (xfsaild's async delwri racing the synchronous
durable flush on the **same** `xfs_buf`) from overwriting that flag between the sync submit and
its completion. Fixed, then a full 24-round 32/caw run came back clean — and surfaced a **new**
single-dirent undercount at round 18, identical on all 32 nodes
(`docs/history/wedge2a-fixed-full24round-clean-new-r18-undercount.md`,
`docs/history/inprogress-r18undercount-instrumented-repro-launched.md`).

A sibling root elsewhere: `i_dlm_demoter` was **cleared before the trailing `xfs_irele`/`iput`**,
letting a nested ilock self-deadlock during eviction — the cause of a fence_during_write soft
lockup and, almost certainly, the `fault_netpartition` NO_TERMINAL_RECORD cascade beside it
(`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).

## 4. Why TCP `dlm_scaling` collapsed (and CAW did not)

Deterministic 4/4 at 8/16/32 tcp while every CAW condition passed on the same build and day.
Chain: unlinks measured a uniform 32ms under 8-way load (single-node 9.4ms, native <1ms) →
ftrace showed **MXFS runs inactivation synchronously in multi-node** (deliberate, for the
AGI-bucket recycle race) → the eager ifree chain (log force + bounded drain + blkdev flush) is
charged to **every unlink syscall**. The transport was exonerated first (DLM RTT 0.25ms).

**The environmental half:** LIO fileio with `write_back=false` on ext4 serialises all target I/O
through the ext4 journal, so concurrent O_DSYNC writers push host fsync p95 past 6.7ms — while
SCST rigs no-op flushes via `nv_cache`. *That* is why the CAW conditions were immune
(`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).

The follow-on arc added a **destage kick** (a 10ms-debounced async log force + AIL push, queued
from ifree and create-success) after a synchronous force was measured to tax the scaling rate
below its floor; plus in-core-only leaf rebuild after the union rebuild proved **delete-unsafe**
— "in-core free + disk live" is ambiguous between a peer add and our own remove, and resurrected
renamed-away dirents (`docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).

## 5. Older-numbering roots worth keeping

- **Reused-inode stale cache HIT** — cache_coherency's two failure faces are one bug: a node
  returns a stale cached LIVE in-core inode because a peer freed and reused that inode number.
  We hold no DLM grant on a passively-cached inode, so the peer's free/realloc never BASTs us.
  The type-mismatch face produces ENOTDIR on *every* op including create-of-children, which takes
  the barrier down with it (`docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **dir_reuse@8/tcp taken from ~0% to ~85%** by invalidating clean cached dir blocks at release
  (not just flushed ones), under a GPT architecture ruling: *no old-epoch buffer reaches disk
  after its DLM lock releases; invalidate ALL dir-fork buffers at release; plain cold-read on
  reacquire; **FUA is not a coherency primitive*** (`docs/history/head-handoff-dir-reuse-solved-standalone-fullsuite-env-blocked.md`).
- **Three dir_reuse failure modes, one AG-free-space root** — data loss, leaf-hash hole, and a
  bnobt double-free shutdown (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **chk_clean**: unmount-time lazy-sbcount sync writes the node's OWN percpu counters, so an idle
  node unmounting **last** clobbers the writer's accurate `sb_ifree`. Fixed by recomputing at
  quiesce — gated on a *sticky* flag, because `put_super` NULLs `m_mxfs_dlm` before
  `xfs_unmountfs` and gating on the pointer silently no-ops (the same wrong gate had also broken
  the multi-node LSN-check bypass) (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).
- **A stale clean cached bmbt leaf** consumed at `xfs_iread_bmbt_block` while the on-disk block
  was correct → EFSCORRUPTED → 1600-dirent cascade. Fixed at the **consume** layer (FUA-read and
  refresh in place) precisely because the read-time invalidator upstream has three escape hatches
  — a TRYLOCK that can fail, skips for dirty/pinned/delwri buffers, and a re-read that can
  repopulate stale from the target's per-initiator cache. Known limitation recorded honestly:
  the refresh callback visits leaves only, so a btree root level ≥2 would still descend through
  unrefreshed internal blocks (`docs/history/docs/history/docs/history/compiled-dialloc-corruption-and-early-campaigns.md`).

## 6. The architecture decision that was reversed

A prior session had pivoted to an **asymmetric metadata-server** design. The user overruled it:
MXFS uses CAW deliberately because **symmetric shared-disk + SCSI CAW/ATS is the proven
high-performance clustered-FS design — VMFS scales it to 64-node clusters** — whereas an
asymmetric MDS forwards every create/unlink/rename over a network RTT and would destroy the
already-green native performance. The pivot was judged *"a prior session's flinch, not sound."*
Stay on v5; port the proven coherency instead (`docs/history/decision-reversal-stay-v5-port-mxfs1-coherency.md`).
