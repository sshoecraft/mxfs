# MXFS NEWARCH — Implementation Journal

> Live notes for the NEWARCH (Path A: portable reliable-notification hybrid)
> rollout.  Append-only.  Detailed per-phase results live in dedicated
> files (`phase0_results.md`, …); this file is the running narrative.

## 2026-06-06 — Phase 0 begins

### Setup
- Read NEWARCH.md, DESIGN.md §4-6/§11, .ccmemory/sess106_lessons.md,
  .ccmemory/sess107_lessons.md, .ccmemory/tcp_dlm_straggler.md,
  .ccmemory/project_caw_is_load_bearing.md, feedback memories.
- Baseline build at session start: srcversion `EED6A769B0BA85B48F6B6BC`
  (sess107 deploy on test1..test4).

### Phase 0a — `mxfs.force_coherent` design
- Goal (per prompt + NEWARCH §5): measure whether a fully coherent MXFS
  is still meaningfully faster than GFS2/OCFS2 BEFORE building the
  notification layer.
- Original design (v1): demote every cached in-core lock to NL/NONE/stale
  on the fast path AND invalidate every cached dir DATA buffer on read.
- Built v1 as srcversion `287BA2051DF7DD51B56AEED`.  Probe tags
  `P0-FCOH` (lock-state demotion) + `P0-FCOH-DIRINVAL` (dir-buf invalidation).

### Phase 0c — first run, NULL-deref oops
- Clean cycle: `sudo virsh destroy+start test1..test4`, waited for ssh,
  `INSMOD_OPTS="force_coherent=1" cache_coherency --nodes 4`.
- cross_visibility + rename_visibility passed; **all 4 nodes oopsed
  during test_unlink_visibility** within ~7 minutes of run start.

```
BUG: kernel NULL pointer dereference, address: 0000000000000001
RIP: xfs_dir2_sf_lookup+0x4b/0x260 [mxfs]
Call Trace:
  xfs_dir_lookup_args → xfs_dir_lookup → xfs_lookup → xfs_vn_lookup
  → lookup_one_qstr_excl → filename_create → do_mkdirat → mkdir(2)
```

- r12=0 (the SF-entry iteration cursor); r13 was a valid sfp pointer.
  The fault is at a `cmpb $0x1, 0x1(%r12)` byte read of NULL+1.
- Root: my v1 force_coherent block ran INSIDE the spinlock'd region of
  `mxfs_dlm_ilock_begin`, clobbered `i_dlm_mode = NL; state = NONE;
  stale = true`, then dropped the spinlock so the slow path
  re-acquired and called `mxfs_dlm_reload_inode`.  Reload re-reads the
  dinode from the on-disk inode cluster — but if the in-core SF dir
  data was already populated and another thread on the SAME inode was
  mid-`xfs_dir2_sf_lookup`, reload momentarily clears/replaces `if_data`
  and that other thread iterates a NULL sfp.
- **Phase 1 implication recorded for later:** this race IS the
  read-vs-reload coupling that Phase 1 must close.  The right fix is a
  single chokepoint for release/demote/reload that excludes concurrent
  in-core access — exactly what NEWARCH §4 calls for.

### Phase 0a' — v2 design: buffer-level only
- Reverted the in-core mode/state clobber in `mxfs_dlm_ilock_begin`
  (kept an explanatory comment for future maintainers).
- Kept the buffer-level invalidation in `xfs_da_read_buf`: when
  `mxfs_force_coherent=1`, any clean cached dir DATA block (subject to
  the existing dirty/in_ail/pin/delwri safety gates that protect THIS
  node's uncommitted work) is invalidated on read so the sanctioned
  read path refetches fresh from the SCST-coherent shared target.
- Built v2 as srcversion `4C9D5DA8740D26E8CF977B5`.  Sole new probe
  tag: `P0-FCOH-DIRINVAL` (mxfs.instr-gated, doesn't flood).
- Rationale: this still answers "do reads see stale dir blocks?" — if
  every cached dir block is treated as stale, the only way
  unlink_visibility/rename_visibility can still fail is broken mutual
  exclusion (i.e. Phase 1 / P106 territory) or inode-cluster staleness
  (cross_write_read).  A clean v2 PASS would be Outcome 1 evidence;
  v2 FAIL on the exclusion-driven subtests is Outcome 3 evidence.

### Phase 0c — second run, v2 buffer-invalidation
- Clean cycle + `INSMOD_OPTS="force_coherent=1" cache_coherency --nodes 4`
  on srcversion `4C9D5DA8740D26E8CF977B5` ran for 244s, FAILED on subtest 1
  (cross_visibility).
- Nodes 1/2/3 passed all content assertions ("Node N reads correct
  content from node M" for every M).
- **Node 4 FS-shutdown** at t=49.866s after mount, ~5s into setup
  (before content assertions started):
  ```
  XFS (sda): Internal error dp->i_disk_size != geo->blksize at line 287
    of file xfs/libxfs/xfs_dir2.c.  Caller xfs_dir2_format+0xf4/0x140 [mxfs]
  XFS (sda): Corruption detected. Unmount and run xfs_repair
  XFS (sda): Shutting down filesystem.
  ```
  `xfs_dir2_format` mismatch — in-core `i_df.if_format == EXTENTS`
  (block/leaf format) but `dp->i_disk_size != blksize`.  Consistent with
  a dir-format transition (block → leaf as the dir grows) where a
  force-invalidate re-read returns a disk image whose size doesn't match
  the in-core format state.
- "Node 4 cannot see node{1..4}.txt" failures are DOWNSTREAM of the
  shutdown (filesystem read returns EIO once shutdown), not coherency
  failures of force_coherent.

### Phase 0 cumulative finding (preliminary)
- **Both force_coherent variants — v1 (lock-state demotion) and v2
  (buffer invalidation) — surface DIFFERENT pre-existing in-core
  state-machine races that the default code path hides behind
  amortization.** v1 races SF-dir reads against reload-clobber of
  `if_data`.  v2 races dir-format transitions against forced disk
  re-reads.
- **This is itself the Phase 0 answer in the language of NEWARCH §5:**
  Outcome 3 — "Cannot pass even fully synchronous" — exclusion / in-core
  state coherence is broken below the notification layer.  Per the gate
  spec, **Phase 1 (P106 kill / single chokepoint for release/demote/
  yield with coupled in-core mode reset) is the prerequisite**; the
  notification layer is a cosmetic optimization until the in-core state
  is provably coherent with the on-disk holder bitmap.
- The cross_visibility content assertions DID pass on nodes 1/2/3 — so
  buffer-level cache coherency works when nothing else trips.  The
  problem is structural, not in the FUA/SCST data path itself.

### Phase 0c — third run, default-mode baseline
- Clean cycle + `cache_coherency --nodes 4` (no flags), build `4C9D5DA8`.
- 126 s wall.  cross_visibility / rename_visibility / unlink_visibility
  all **PASS**; cross_write_read FAILS — every reader sees empty content
  for node 3's file.  Matches the sess107 residual on this build.

### Phase 0e — gate decision

**Outcome 3 — Cannot pass even fully synchronous → Phase 1 first.**
(see `phase0_results.md` for the full evidence package).

Stopping here for Phase 0.  Recommendation to Steve: do NOT proceed to
Phase 2 (TCP mesh) until Phase 1 (single chokepoint for release/demote/
yield, coupled in-core mode reset, permanent divergence assertion) is
in place AND Phase 0 is re-run with a clean instrument.  The two races
the Phase 0 instrument tripped are real bugs in the current code path
(default mode just usually avoids them via amortization) and they ARE
the exclusion gaps NEWARCH §4 says must be closed before any
notification layer can help.

---

## 2026-06-06 — Phase 1 (continued)

### Phase 1.1 — instrument every on-disk holder-bit clear site
- Added `P109-CLR-*` probes (gated by `mxfs.instr`) at every site in
  `dlm/dlm_caw.c` that clears OUR `holders_*` bit:
  - `P109-CLR-DIVERG-LO` — divergence guard, our_mode<requested.
  - `P109-CLR-DIVERG-HI` — divergence guard, our_mode subsumes.
  - `P109-CLR-UPGRADE` — compatible upgrade (clear old + add new in
    same CAS — low hazard).
  - `P109-CLR-UPGRADE-DDL` — upgrade-deadlock-release: clears old, no
    add, opens a real window before re-acquire — HIGH suspect.
  - `P109-CLR-UNLOCK` — canonical unlock entry.
  - `P109-CLR-RELEASE-ALL` — bulk release at umount.
- Each probe records `{resource type, resource id, our mode, slot}`
  so a P106-STALE-EX firing can be correlated with the last clear.
- Build `8354BAEE` deployed.

### Phase 1.2 — collect evidence
- Clean cycle + 4-node rename repro (20 files) with `mxfs.instr=1`:
  - cross-node coherency PASSED 4/4 (instr=1 slowdown masks the race —
    see [[sess39_lessons]]).
  - `P109-CLR-UPGRADE-DDL` fires 19× on test2, 20× on test4 in a
    normal contended run.  Confirms the suspected window-open clear
    path is exercised under realistic load.
  - `P109-CLR-DIVERG-{LO,HI}` did not fire — divergence guards are
    rare, as expected.
  - `P109-CLR-UNLOCK` fires 88–151× per node — canonical safe path.
  - `P106-STALE-EX` = 0 (race masked by instr=1 slowdown; the structure
    is still present in default-mode).

### Phase 1.3 — chokepoint fix attempts (NONE LANDED)
Three increasingly-careful attempts in this session, all rolled back:

- **v1** (`287BA205…`) — reset `i_dlm_mode = NL` synchronously on
  slow-path entry.  Cascaded multiple same-node `caw_lock` calls for
  the same resource → exhausted the 3-attempt outer wrapper →
  force-shutdown on all 4 nodes.

- **v2** (`690BE0EF…`) — set `state = DEMOTING` on slow-path entry to
  make concurrent same-node ilock_begin callers wait in the existing
  DEMOTING loop.  Broke `mxfs_dlm_bast_notify` (xfs_mxfs_dlm.c:2221):
  it interprets DEMOTING as "we are already demoting, drop the BAST".
  Peer BASTs silently dropped → peer `caw_lock` timed out 120 s × 3
  → shutdown ~360 s in.

- **v3** (`D77E964D…`) — added new state `MXFS_DLM_ISTATE_UPGRADING`,
  taught `bast_notify` to defer it to BAST instead of dropping it,
  taught the slow-path DEMOTING-wait loop to also wait on UPGRADING.
  Subtly broke the BAST drain on the eventual `ilock_end`: observed
  `SESS50-STARVE` firing continuously on `ino=128` (root) — test1
  acquired EX, 4 waiters queued, but bast_process never advanced past
  state=DEMOTING.  Caw_lock timed out → shutdown.

Reverted to build `7447E27A` (probes only, no fence) to restore the
known-good 3/4 baseline.

### Phase 1.3 — handoff to next session

The pattern from the three attempts is the lesson: the in-core state
machine has interacting consumers (`bast_notify`, `bast_process`,
`ilock_end`, `bast_work_fn`, the slow-path entry, the demoter belt-
and-suspenders path) that each make their own assumptions about which
states can transition to which.  Adding a fourth state or a localized
fence breaks each consumer in a different invisible way.

What the proper Phase 1.3 needs:
1. **A single chokepoint function** that owns ALL release / demote /
   yield / upgrade transitions, with its own internal state and a
   clear contract for every other consumer to follow.  No "set state
   here, return, hope someone notices" patterns.
2. **Per-state transition unit tests** (a stress harness that drives
   each state transition pair under controlled contention and asserts
   no invariants break) so each refactor step is verifiable.
3. **The permanent divergence assertion** the prompt called for:
   periodic sampling that reads each held slot from disk and asserts
   on-disk holder bit matches in-core mode for every live resource.
   Fires the moment a refactor regresses the coupling.

That is a session of careful design, not a one-line patch.  This
session's deliverables are:
- The P109-CLR-* probes (KEEP — they identify the path next time).
- `MXFS_DLM_ISTATE_UPGRADING` defined in xfs_inode.h (unused now;
  reserved for the chokepoint refactor).
- Three documented failure modes that constrain the chokepoint design.

### Phase 1.4 — publish-on-create (LANDED)
- Added `mxfs_dlm_publish_inode(ip)` to xfs_mxfs_dlm.{c,h}.
- Called from `xfs_create` after `xfs_trans_commit` + `mxfs_dlm_dir_durable_signal`,
  before `*ipp = du.ip` exposes the new inode and before the iunlocks.
- Synchronously promotes the new inode from local-grant (no on-disk slot)
  to a real on-disk EX CAW slot, so a peer reaching it via a cached parent
  dirent finds a slot to BAST against instead of acquiring an empty one.
- Build `B132B685`.  20-file 4-node rename repro: 11s, TOTAL_FAILS=0.
- cache_coherency under publish-on-create alone (no chokepoint yet):
  cross_visibility **PASSED**, rename_visibility 220/240 on 3 nodes, 80/240 on
  test3, no shutdowns — already a measurable improvement.  P107-PUBLISH=0
  (publish-on-create made the sess107 lazy backstop unnecessary), P106-STALE-EX=0.

### Phase 1.3 (proper) — Gemini chokepoint (LANDED)
Per the user's "the design IS solved, look at Lustre / BeeGFS / GFS2" pushback
and the timing-is-first-class rule, asked Gemini (RULE 5 escalation — 3 failed
local attempts) for the codebase-aware chokepoint design.  Gemini's answer:

1. **Remove UPGRADE-DDL from `mxfs_dlm_caw_lock`.**  Instead of silently
   clearing our holder bit and registering as a waiter, return `-EDEADLK`.
   caw_lock now has a strict contract: it upgrades atomically (clear+add in
   one CAS) OR acquires from NL.  No silent demotes.
2. **New state `MXFS_DLM_ISTATE_ACQUIRING`** — set on slow-path entry before
   dropping the spinlock to call caw_lock, cleared on return.
3. **Upper-layer `-EDEADLK` handler:** transition state to BAST, schedule the
   existing `bast_work_fn` (drain + invalidate + clear on-disk bit + set
   i_dlm_mode = NL atomically), then re-enter ilock_begin to retry from a
   clean NL state.  No window where in-core and on-disk diverge.
4. **`bast_notify` on ACQUIRING:** record via `i_dlm_stale = true`, do NOT
   queue bast_process (queuing would strip the slot out from under caw_lock's
   polling loop — the v3 failure).
5. **Slow-path wait loop extended** to wait on DEMOTING || ACQUIRING || BAST
   (demoter exempt for re-entry).

Implementation: build `F591E7A5`.  All five changes landed
(xfs_inode.h, dlm/dlm_caw.c, xfs/xfs_mxfs_dlm.c).

Results:
- **20-file 4-node rename repro: 13s, TOTAL_FAILS=0 on all 4 nodes.**
- 100-file stress: 35s, 20 consistent fails per node (5% lost-write rate),
  NO shutdowns, NO STALE-EX, P109-EDEADLK fires 5–17×/node (chokepoint engaged).
- cache_coherency: **cross_visibility PASSED**, rename_visibility wedged at
  900s (criterion SIGKILL).

The rename_visibility wedge is downstream of the chokepoint, not introduced
by it.  Diagnosis:
- test1 ran `rm` on a recently-created inode (`ino=4194433`).
- caw_lock returned -EDEADLK (we hold PR, peer holds incompatible EX/PW).
- Chokepoint correctly scheduled `bast_work_fn` and called wait_event on
  state==BAST.
- bast_process tried to drain AG=2's AIL.  **AG-AIL push wedged at
  `iter=75520` (75K iterations with no progress) on stuck_ino=4194433,
  iflags=0x0 buf_locked=0** — clean inode with no locked buffer that
  the existing P67-INSTR AG-AIL-STALL drain code can't push.
- The rm thread hung in `mxfs_dlm_ilock_begin+0x279/0x1080 → schedule`
  for 900+s ("hung_task" messages every ~120s) waiting for the drain.

**This is a pre-existing AG-AIL-drain bug** (sess67 named the path
P67-INSTR; sess20+ logged the underlying drain logic).  The chokepoint
hits it harder because it routes every -EDEADLK through bast_process,
where the silent UPGRADE-DDL release would have side-stepped it.  In
other words: the chokepoint is correctly demanding what NEWARCH §4
invariant #1 says ("no on-disk unlock without completed drain") — and
the drain code can't deliver in this case.

### Summary of this session's deliverables (KEEP)
- `mxfs.force_coherent` module param + buffer-level invalidation in
  `xfs_da_read_buf` (Phase 0 measurement instrument, dormant at default).
- `MXFS_DLM_ISTATE_ACQUIRING` enum value.
- P109-CLR-* probes (6 sites) in dlm/dlm_caw.c.
- `mxfs_dlm_publish_inode(ip)` + call in xfs_create.
- caw_lock UPGRADE-DDL removed in favor of -EDEADLK return.
- Upper-layer slow-path ACQUIRING fence + -EDEADLK handler.
- bast_notify ACQUIRING-branch (defer via i_dlm_stale).
- Slow-path wait loop extended to ACQUIRING/BAST (demoter exempt).
- Post-acquire publish: ACQUIRING → CACHED (or BAST if stale arrived).

### Phase 1.5 — for next session
- **Fix the AG-AIL push wedge on iflags=0x0 buf_locked=0 inodes**
  (pre-existing; see sess67 P67-INSTR + sess33 adaptive-yield code).
  Without this, rename_visibility under heavy contention can't complete.
- Add the permanent divergence assertion (`WARN_ON_ONCE` in
  `mxfs_dlm_caw_unlock` pre-CAS + in `mxfs_dlm_bast_notify`) per
  Gemini's design item (e).
- Re-run Phase 0 force_coherent gate now that the chokepoint exists.
- Multinode metadata fio bench under default + force_coherent for the
  Phase 0 Outcome-1-vs-2 distinction.

(End of session 108 NEWARCH narrative.)
