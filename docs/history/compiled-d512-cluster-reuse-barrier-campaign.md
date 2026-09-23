<!-- sess414-416: D-512 cluster-reuse-barrier build+verify (cycle1 gates, cycle2 barrier ruling, T2/T8 ladder), D-0285 unlock-clobber found+fixed, D-0286… -->
## D-INCARN-STALE-SHELL-UNGATED-FILE-READS-512: cluster-reuse-barrier build+verify, sess414-416

Continuation of the sess413 GPT ruling (fix shape (c): DONTCACHE + never-fall-through-to-poisoned-
shell + full data-path gate set + poison-time revocation + dirty-G1 hazard + recycle-only clear +
cluster reuse barrier — banked in `docs/history/docs/history/compiled-sess413-defect-closure-campaign.md` via
`docs/rulings/d512-incarn-stale-full-gate-design.md`). This article covers cycle 1
(build), cycle 2 (GPT ruling on the reuse barrier + T-ladder verification), and the T8 injector work
that found a second critical defect (D-0285) plus a related TCP-transport ruling (D-0286) surfaced
while scoping the T9 TCP-lap leg of the same ladder.

### Cycle 1 — poison/revocation gates landed and verified (0.28.0)

sess414: landed in tree as 0.28.0 (unbuilt at write time, per
`trap-never-rebuild-mxfs-ko-while-rig-run-in-flight` — mxfs.ko deliberately not relinked while
another board ran).
`docs/history/docs/history/docs/history/compiled-d512-cluster-reuse-barrier-campaign.md`

- `mxfs_incarn_poison()` + `mxfs_incarn_revoke_work_fn` (`xfs/xfs_mxfs_dlm.c`): all 3 poison sites
  route through the helper; worker takes `IOLOCK_EXCL|MMAPLOCK_EXCL` in one `xfs_ilock`, re-asserts
  the flag, `unmap_mapping_range` + `truncate_inode_pages` (discard dirty G1, never flush), unlock,
  `d_mark_dontcache` + `d_prune_aliases`.
- fsync gates ahead of `file_write_and_wait_range` (never flush through a dead bmap); writepages
  short-circuit to 0 under `INCARN_STALE` (dirty-G1 sanitation, worker discards); -ESTALE rechecks at
  direct/buffered/read/seek/xattr iomap_begin (the under-the-op's-own-lock recheck the sync model
  requires).
- ioctl gate added but dead code — `xfs_ioctl.c` isn't in Kbuild; live ioctl surface is a
  GOINGDOWN-only stub, so component coverage there is N/A-by-exclusion, not a gap.
- Flag lifecycle audited clean: set only via `mxfs_incarn_poison` (3 sites + debug knob), cleared
  only via `XFS_IRECLAIM_RESET_FLAGS`.
- New verification rig: `tests/d512_ref_matrix.c` (on-node C helper: rw fd + O_DIRECT fd + dirtied
  mmap across a knob-forced poison; asserts -ESTALE everywhere, SIGBUS on deref within the zap
  window, reopen serves the fsync'd baseline not flushed dirty G1) + `tests/d512_incarn_gate_verify.sh`.

Board result (sess415): 0.28.0 D-512 cycle-1 closed green (ndr 322s; crash_consistency warm 21s
confirms the D-401 budget-edge face, not a regression).
`docs/history/docs/history/docs/history/compiled-d512-cluster-reuse-barrier-campaign.md`

### Cycle 2 GPT ruling — the reuse barrier is the real gap (sess415)

Tree facts brought to GPT: dialloc reuse is a per-ino DLM CAS with sticky DEMAND revoke; holder-side
BAST release drain already does `filemap_write_and_wait` + `invalidate_inode_pages2` +
`i_dlm_stale=true` before on-disk unlock; re-acquire does protective reload → di_gen mismatch →
cycle-1 poison; the eviction ring is lossy-only; and `P52-RELOAD-FREEDREUSE-DIR-SKIP` was silently
*keeping* a dirty dir shell backed by a different-gen free slot — flagged as unsound.
`docs/rulings/d512-cycle2-reuse-barrier.md`

Ruling: the barrier is structurally mostly present but component 7 closure needs five more pieces —
(a) extent-publication proof (the ino-reserve interlock does NOT cover reuse of the *freed file's
extents*; every extent-free publisher — unlink/ifree/truncate/punch/reflink-cancel/orphan/replay/
repair — must drain old holders before the extent reaches free space); (b) drain-error fail-stop
(nonzero return from invalidate/writeback-wait/flush during release drain must block the unlock and
escalate to withdraw/fence, never best-effort); (c) dirty-different-gen is an invariant violation
type-independently — replace the unsound P52 REG+DIR keep with freeze+retain-grant+poison+withdraw;
(d) replay/recovery must participate in the same barrier and never overwrite an already-reused
dinode/extent; (e) fencing must be confirmed before grant reassignment on both transports. Mandated
unlock publication order: stop new ops → wait local holders → zap+TLB → drain writeback/DIO/ioends/
COW/DAX → invalidate → handle GUP/RDMA/DAX pins → blkdev_flush → mark stale → publish unlock. Defined
a T1-T9 verification matrix (clean lazy-shell reuse, drain pausepoint ladder, DEMAND escalation,
fenced-holder-with-dirty, crash/replay phase matrix, extent-only reuse, async-path drain, synthetic
impossible-state injection, transport/failover cross product) and a 13-step build order, closing
D-512 only after all of it passes.

### T-ladder execution (sess415-416)

- 0.28.2: `P-D512` containment arms + `mxfs_inode_wedge` — board 27/27 zero fires.
- Armed board (enforce=1+tcp=1): 27/27 including node_death_replay under enforcement — zero
  refused/quarantine/EIO.
- 0.28.3: race windows; write+writeback race legs PASS 7/7 via `tests/d512_race_verify.sh` (trigger
  must be on-node event-driven, never fixed-sleep — a lesson repeated across this whole campaign).
- T1 (`tests/d512_t1_reuse.sh`): both arms PASS — fd-open blocks exact-ino reuse entirely via
  open-unlink deferral; fd-closed allows real reuse and the stale shell never serves old bytes.
- 0.28.4: T2/T6 drain pausepoints (`dbg_rel_pause_{ino,stage,ms}`, 5 sites in `bast_process`
  including both unlock arms). First pass: stages 1,2,4 held (publication blocked ≥2s); stages 3,5
  looked like leaks but were a HARNESS bug (RULE-4 proven from dmesg: a recycled ino carried pending
  BAST state, create-churn released the grant ~10ms after create — *before* the second-ssh arm — so
  the pause never engaged and a free slot was found; not an ICLUS bypass). Fixed by arming in the
  same ssh as create and re-dirtying after arming. Rerun (sess416) closed T2 5/5 + T6 riders clean,
  29s wall.
  `docs/history/docs/history/docs/history/compiled-d512-cluster-reuse-barrier-campaign.md`
- New unrelated defect logged in passing: D-CLUSTERWIDE-CONVOY-STALL-SELFCLEARING-0281 (high,
  unrooted, no recurrence x3 — tracked separately, not part of this campaign's closure).

### T8 synthetic injectors find D-0285 (sess416, 0.28.5)

`dbg_rel_fail_{ino,kind}` one-shot injectors (kind1=site-1 writeback→-EIO, kind2=site-1
invalidate→-EBUSY, kind3=site-2 flush→-EIO, kind4=reload dirty-mismatch) via
`tests/d512_t8_inject.sh`.
`docs/history/docs/history/docs/history/compiled-d512-cluster-reuse-barrier-campaign.md`

Results: kind2 benign (6/6 PASS, no wedge). kind1 correctly contained (INJECT+WBFAIL+WEDGE+mount
dead; waiter blocked 68s then served correct data via fence+recovery — the designed disposal path).
**kind3 found D-WEDGED-RELSTATE-CLOBBER-UNLOCK-PUBLISHED-0285 (critical, ledger #141)**: code-proven
root cause — unlock arms call `mxfs_relbar_close_or_defer` *before* their pre-CAS WEDGED re-check, so
the proof body's `WRITE_ONCE`s clobber a terminal WEDGED back to DRAINING→PROVED and the unlock CAS
publishes over a failed drain; the on-disk pin only guards `release_all`, not the direct unlock CAS.
kind4 never fired — the armed re-read short-circuits at `P-RELOAD-IDENTICAL` before reaching the real
dirty-mismatch arm in the freshsrc-adopt chain.

Fix landed 0.28.6: `mxfs_rel_state_set()` made a sticky, WEDGED-enter-only setter; all 7 lockless
writers converted (5 in the proof body + both arms' RELEASING path); kind-4 injection point moved to
reload entry (before the `P-RELOAD-IDENTICAL` compare) so it's deterministically reached. Rerun
pending at end of sess416 (expected: kind3 blocks + recovers like kind1, kind4 fires, kinds 1/2
unchanged).

Harness bug fixed en route: `rpid=$(trigger_read ...)` command substitution waits for the backgrounded
subshell's inherited pipe EOF, so an "+8s still blocked" check ran only after the read had already
completed — false negative. Fixed by capturing rc from `timeout`/`ssh` directly instead of the
filter's tail, with `TRPID` made global.

### D-0286 TCP dirty-departure ruling (sess416, scoped while planning the T9 TCP leg)

Separate defect, same campaign's transport-generality requirement (T9 needs both CAW and TCP to
enforce the same barrier): D-TCP-WEDGE-PIN-NOOP-REPORTS-SUCCESS-0286.
`docs/rulings/tcp-wedge-dirty-departure.md`

GPT ruling: Shape B strengthened — no per-resource TCP pins (would need a second durable-lock
replication/failover mechanism). Instead WEDGED poisons the entire TCP session/mount incarnation:
no NODE_LEAVE, no release_all, no reconnect, no unlock for the wedged resource once poisoned;
connection loss is classified as dirty death; grants aren't reassigned until fence + slice replay +
cert. State machine: ACTIVE → QUIESCING → CLEAN_LEAVE, with any path divertable to
POISONED/WEDGED → DISCONNECTED → DEATH_RECOVERY (terminal per incarnation). Six invariants: wedge
publication precedes cleanup; no clean protocol action after poison; NODE_LEAVE needs a real
linearization point (a concurrent wedge wins over an already-queued goodbye); connection death never
implies immediate reassignment (tombstone + fence + replay + cert first, scoped to the exact session
incarnation for ABA safety); master failover preserves the obligation (no "no lock record ⇒ free"
inference); death dominates a delayed clean leave. Named hazards to design against: goodbye already
in flight when wedge lands, concurrent release_all not rechecking poison per-unlock, poison published
after socket close, master granting a fresh request for a resource still owned by a dead session
(new-request bypass), master failover at each of 7 phases.

Interim containment landed 0.28.7: `-EOPNOTSUPP`, safe *only if* force-shutdown already guarantees
dirty death through the whole TCP teardown stack — explicitly flagged as needing an audit (generic
shutdown still running release_all/NODE_LEAVE, wedge marked per-inode but no session-wide poison,
shutdown racing before sticky-state publish, a non-rechecking release worker, a pre-wedge-queued
goodbye, auto-reconnect after master failover, master granting a recreated resource pre-recovery,
error-unwind releasing the grant on pin failure, a missed wedge call site) before full Shape-B design
is built.

### Standing lessons this cluster reinforces

- Trigger events for race/pause harnesses must be on-node and event-driven; a fixed sleep raced a
  10ms grant-release window and produced a false "leak" that cost a full T2 rerun cycle.
- A recycled-then-BAST-pending inode can release its grant within ~10ms of create — any harness that
  arms a pause in a *separate* ssh call from the create step is racing that window.
- Debug-only synthetic injectors (T8) are what actually found D-0285 — normal race legs (T1-T2,
  0.28.0-0.28.4) all passed clean; the invariant-violation class of bug only surfaces under forced
  fault injection at the exact drain-failure sites.
- `P141-UNLK-EXCLR` (`dlm_caw.c`) is a reusable "unlock actually published" oracle for any future
  release-path defect in this family.
