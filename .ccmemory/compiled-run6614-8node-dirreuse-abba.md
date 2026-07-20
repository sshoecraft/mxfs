---
name: compiled-run6614-8node-dirreuse-abba
description: run6614 ccloop sess6-7: 8-node dir_reuse ABBA drain_evict deadlock, leaked i_lock(rm), reused-dir EIO shutdown, refuted barrier levers.
metadata:
  type: project
tags: [compiled, dir_reuse, ccloop, run6614, abba-deadlock, i_lock-leak, durability-gap, 8node]
---

## run6614 ccloop — 8-node dir_reuse coherence investigation (sess6→sess7)

Ship gate: `drc_reliability` / `dir_reuse_coherency` at TCP transport across 1/2/4/8 nodes.
The rm-rf'd+recreated shared dir (ino=131, 800 dirents, 8 nodes × 100) drives a deep
reused-inode/reused-dir-block coherence bug that gets worse with node count. As of
sess7 END the marker is NOT written; 4/tcp and 8/tcp are both flaky. Fallback shippable
baseline = **9AA569A0** (== behavior of D7A9A25E baseline; gg_refresh=1 + leaf_flush=1),
but that baseline HANGS at 8 so it is not truly shippable.

### Build progression (chronological)
- **9AA569A0** — gg_refresh=1 + dir_release_flush_leaf=1 (both KEEP, proven). 1/2/4 tcp=100%,
  8/tcp ~16/17 (~1/3 fail). The best default; baseline for sess6 work. [[sess6-ccloop-8node-dirreuse-undercount-refuted-levers]]
- **97E09EE8** — adds behavior-neutral P6-DIRPATH / P6-DIRPHANTOM atomic counters + `dirphantom_dump` param. Measurement build. [[sess6-ccloop-8node-DECISIVE-not-stalebase-release-durability-gap]]
- **414432A9** — GPT-5.5 "must-complete invalidation barrier" (log_force+drain_evict-until-left==0). REFUTED (1/5), reverted. [[sess6-ccloop-8node-barrier-refuted-release-or-bypass-next]]
- **900BB963** — sess6 HEAD, UNTESTED at relay boundary: candidate-A (arm gg_refresh on hgg==0 && !self_created). Later REFUTED in sess7. [[sess6-ccloop-HEAD-untested-candidateA-hgg0-refresh]]
- **D7A9A25E** — pristine N=8 baseline re-measured in sess7; HANGS at 8. [[sess7-ccloop-DECISIVE-8node-ABBA-deadlock-drain-evict-ilock]]
- **638E582919B7D49E** — drain_evict ABBA fix (blocking down_read → bounded trylock). KEEP; cut mass-loss 700→797/800. [[sess7-ccloop-8node-progress-ABBA-fixed-now-leaked-ilock-rm]]
- **F5A90E91C5841F8B** — sess7 END HEAD = pristine baseline behavior + behavior-neutral leak-attribution instrumentation only; ALL sess7 workarounds REVERTED. (== 9AA569A0-equivalent minus instr.) [[sess7-ccloop-END-state-F5A90E91-safe-baseline-4tcp-confirmed]]

### sess6 — narrowing the residual (before the ABBA hang was seen)
Under 9AA569A0 the 8-node failure was framed as a **readdir undercount**: a few SCATTERED
dirents durably lost (lookup_fail=0, all nodes agree, REREAD_MISS). Losses skew to LATE
creates by HIGH-numbered nodes (node8's `.md5` second wave), spread across rounds. E.g.
round1 796/800 missing=[node5_f5, node8_f44/46/47.md5]; other runs 793/800; a transient
0/800. No shutdown in the default build — the undercount itself fails the test.
[[sess6-ccloop-8node-dirreuse-undercount-refuted-levers]]

**Refuted sess6 levers (do NOT retry — all regress with shutdowns):**
- `dir_release_flush_all_done=1` → in-memory corruption at `xfs_trans_cancel` (xfs_trans.c:1061) shutdown (release bwrite hits an in-flight trans).
- `dir_tenure_evict=1` → DABUF_MAP_HOLE leaf-flood shutdown.
- GPT-5.5 must-complete acquire barrier (414432A9) → 1/5, no help; DECISIVE: the loss SURVIVES a fully-evicted cold base (left==0) ⇒ NOT acquire-side pin/undestaged skip.
[[sess6-ccloop-8node-barrier-refuted-release-or-bypass-next]]

**Decisive counters (P6-DIRPATH, build 97E09EE8, at a real 0/8 fail):** ALL 8 nodes showed
`fastret_stale=0` + `demoter_bypass=0` + `phantom_total=0`. This REFUTES stale-base-RMW at
the serve (gen==loaded every dir-EX serve) and refutes the gg_refresh-bypass path.
Conclusion: **base is gen-FRESH but content-STALE** — loaded_gen advances on reload/evict
bookkeeping, not on proof-of-durable-disk-content, so a gen-fresh cold-read of a not-yet-
durable dir block RMWs a content-stale base and drops the peer's late dirent =
**RELEASE-SIDE / PUBLISH DURABILITY GAP**. Prime suspect: `mxfs_dlm_dir_durable_signal`
(xfs_mxfs_dlm.c:18481/18593) is synchronous xfs_bwrite+blkdev_issue_flush BUT gated
`i_dlm_dir_gen>0 && fmt EXTENTS/BTREE` → early/round-1 creates at gen==0 skip the fence and
reach the LUN only via lazy xfsaild. Proposed fix: drop the gen>0 gate for peer-reachable
(!self_created) multinode dirs, scoped to preserve RULE-0 solo-rsync perf.
[[sess6-ccloop-8node-DECISIVE-not-stalebase-release-durability-gap]]

**Nuance (amends the above):** `fastret_stale=0` does NOT rule out a MISSED HANDOFF — if
grant_gen (hgg) fails to change on a real handoff, gg_refresh never arms yet gen==loaded.
Two live candidates split by counting hgg!=cached vs hgg==cached at serve (~14815), and by
checking whether `mxfs_v5_dlm_inode_grant_gen` ever returns 0/stale at N=8:
A = missed handoff (unreliable grant_gen query — fix like sess5 dir_epoch max-across-mirrors),
B = release-durability gap. [[sess6-ccloop-8node-NEXT-diagnostic-missed-handoff-vs-durability]]

**candidate-A (build 900BB963, UNTESTED at sess6 boundary):** arm gg_refresh also when
`hgg==0 && !self_created`. Motivated by test7 `gg_hgg0=87` (grant_gen query returned 0 —
stale/absent local grant mirror — 87×), where the old `hgg!=0` condition never armed →
undetected handoff → stale-base RMW. [[sess6-ccloop-HEAD-untested-candidateA-hgg0-refresh]]

### sess7 — the real N=8 root: ABBA deadlock, then a leaked i_lock
Re-measuring baseline D7A9A25E at N=8 reframed the DOMINANT failure: not sess6's scattered
1-3 dirent loss but a **hard node HANG**. One node's `dd` goes D-state 368s+, `ls` hangs,
NO shutdown/corruption. Stack:
`xfs_lookup → mxfs_dlm_dir_consumer_refresh → xfs_ilock(SHARED,5309) → mxfs_dlm_ilock_begin
→ mxfs_dir_drain_evict_data_blocks → down_read(&ip->i_lock)` blocked forever. The wedged
node's 100-entry batch never publishes → every peer's readdir = **700/800** consistently +
barrier never completes → whole test 0/8. (`node8_f*` names are exactly the lookup_fail
entries.) The `imap_to_bp failed rc=-5` face is a RED HERRING here — that path
(xfs_mxfs_dlm.c:11799) only logs, sets i_dlm_stale=false, returns; no shutdown.

**ROOT (ABBA, proven by stack):** `mxfs_dir_drain_evict_data_blocks` (xfs_mxfs_dlm.c:7856)
took a blocking `down_read(&i_lock)` to snapshot the dir extent map, but runs INSIDE
`mxfs_dlm_ilock_begin` (serialized per-inode DLM acquire). A concurrent writer
(xfs_create/remove on the same shared dir) holds i_lock(WRITE) while waiting for that same
DLM grant. Cycle: acquire needs i_lock(read) ⟂ writer holds i_lock(write) & needs grant ⟂
grant handoff needs this acquire to finish. 4-node passes because contention rarely lines up.
**FIX (638E5829):** replace the blocking down_read at 7856 with bounded trylock —
50 × (down_read_trylock else msleep(2)), on exhaustion `return 1` (="skipped", the existing
loss-safe path also used for BTREE-not-read at 7850). Mirrors the ABBA-safe idiom in
`mxfs_dir_flush_data_blocks_relsafe`. Result: mass-loss gone (700→797/800). KEEP.
[[sess7-ccloop-DECISIVE-8node-ABBA-deadlock-drain-evict-ilock]] [[sess7-ccloop-8node-progress-ABBA-fixed-now-leaked-ilock-rm]]

**candidate-A and candidate-B both REVERTED (do NOT retry):**
- candidate-A (hgg==0 gg_refresh arm) → caused the SAME drain_evict hang much more often.
- candidate-B (loosen durable_signal gen>0 gate to publish per-create) → per-create synchronous
  log_force(SYNC)+bwrite under dir ILOCK_EXCL → peers' EX acquires time out rc=-110 → mass
  shutdown at xfs_mxfs_dlm.c:15570. **Durability must be at RELEASE, not per-create.**

**Residual after the ABBA fix — a genuinely LEAKED i_lock(write) (FACE 1):** dd now gets past
drain_evict but wedges at the plain `xfs_ilock(SHARED)` in `mxfs_dlm_dir_consumer_refresh`
(5309); the BAST release worker wedges at `mxfs_dlm_bast_process → mxfs_drain_ilock_read →
msleep` (waits forever, bails only on FS shutdown) — both on dir ino=131. DECISIVE forensic
(P132-ILOCK-STUCK, always-on): `ino=131 waited_ms=270000 rd_held=0 cnt=3
wr_last=xfs_lock_two_inodes+0x14e pid=17267 comm=rm`. rwsem count=3 = WRITER_LOCKED|WAITERS;
the recorded writer pid (rm, the rank1 rm-rf) is GONE from ps ⇒ rm exited/was-killed while
holding dir ILOCK_EXCL taken via `xfs_lock_two_inodes` (xfs_inode.c:643, from
xfs_trans_alloc_dir in xfs_remove). Leak is PRE-EXISTING; the drain_evict fix only unmasked
it. Once i_lock leaks, release-drain can't complete → DLM grant never hands off → peers cascade.

**Leak not yet pinned** — static reads of xfs_remove / xfs_lock_two_inodes show balanced
unlock paths. Hypotheses to test (RULE 4): (1) rm SIGKILLed mid-xfs_remove during an FS
shutdown race → an mxfs error/shutdown path skips xfs_iunlock(dp); rc!=0 DLM-acquire
shutdowns (xfs_mxfs_dlm.c:15597) were seen same runs. (2) double-down_write on dp from an
mxfs hook (mxfs_dlm_dir_modify_refresh@xfs_inode.c:3866, or mxfs_dlm_ilock_begin(ip1) at
xfs_lock_two_inodes:698) unbalanced vs a single up_write → write bit stays set.
**Attribution fix applied (behavior-neutral):** `mxfs_ilk_note_lock` was previously only on
the xfs_ilock path; sess7 ADDED it to the 3 raw `down_write(&ip->i_lock)` sites — reload@~12471,
reset_inode@~13667, sf_merge@~13985 — so the NEXT P132 names the true leaker. The instrumented
runs did not hit FACE 1; re-run drc_reliability 8 until P132 fires, read wr_last.
[[sess7-ccloop-8node-multiface-leak-plus-imapEIO-state]]

**HARD CONSTRAINT (proven):** do NOT fix by SKIPPING the acquire-side dir evict/refresh under
contention. The `consumer_refresh(5309)` and `drain_evict(7856)` trylock-then-SKIP workarounds
REGRESS 4-node from 12/12 (2/3) to 0/4 — a false-skip of transient-writer contention does a
stale-base RMW → dirent loss. The blocking down_read only wedges because of FACE-1's leaked
lock; fix the leak, not the drain. [[sess7-ccloop-END-state-F5A90E91-safe-baseline-4tcp-confirmed]]

**FACE 2 — reused-dir EIO → shutdown (dominant in the F5A90E91 runs; all 8 nodes shut down,
readdir 0/800):** `DLM inode reload imap_to_bp failed ino=131 rc=-5` (the dir itself,
freed+realloc'd each round) then `P-CREATE-ERR2 dir_create_child err=-5 t_dfops_empty=1
dp_ino=131` → `XFS Metadata I/O Error (0x1) at xfs_trans_read_buf_map (xfs_trans_buf.c:313)
Shutting down`. Root: the reload (xfs_mxfs_dlm.c:11799) stales the dir's inode-cluster buffer,
then `xfs_imap_to_bp` re-reads DURING the free/realloc window → transient EIO. The reload only
logs+returns, but the CREATE path (xfs_create/dir_create_child) hits the SAME EIO reading dp's
cluster on a dirtying transaction → dirty-cancel → shutdown. FIX IDEA (untested): bounded RETRY
of xfs_imap_to_bp on -EIO in BOTH the reload and the create's dp cluster read (reuse window is
sub-ms; sess9@3439 already retries a "transient xfs_imap_to_bp failure" in the durable path —
mirror it). A transient reuse-window EIO must NOT dirty-cancel→shutdown. Note: this is distinct
from the sess7 benign `imap_to_bp failed rc=-5` red herring (which only logs and returns; it
appears in PASSING 4-node runs).

### sess7 END state & correction
Corrects sess6's "4/tcp = 12/12": with F5A90E91, **4/tcp drc_reliability = 2 PASS / 1 FAIL (2/3)**
— dir_reuse is INHERENTLY FLAKY at 4-node too (RUN3 FAIL = test2 shut down via FACE 2), just
rarer than 8. Instrumentation is behavior-neutral (mxfs_ilk_note_lock already runs on the
xfs_ilock path) so it cannot cause the flake. Both hard faces (FACE 1 leaked i_lock hang;
FACE 2 reused-dir EIO shutdown) are the SAME deep reused-dir coherence bug and both hit 4 and 8.

**NEXT (RULE 4):** (1) pin FACE 1 via new P132 attribution → fix the leaking down_write path;
(2) fix FACE 2 — make the reused-dir-block read coherent (cold-read current incarnation) OR make
a torn/stale reuse-window read non-fatal (retry/degrade to ENOENT, no dirty-cancel→shutdown).
Re-verify 1/2/4 after EACH change with N≥6 (4-node is only ~2/3 so needs samples for stable
signal). Write the marker ONLY when 1/2/4/8 tcp are all 100% AND stable.
[[sess7-ccloop-END-state-F5A90E91-safe-baseline-4tcp-confirmed]]

### Standing infra notes
- rsyslog must stay masked on all 8 nodes + clean /root/drc_*.dmesg first, else disks refill and mask results.
- P6-DIRPHANTOM / P6-DIRPATH atomic64 counters (dump via `echo 1 > /sys/module/mxfs/parameters/dirphantom_dump`) are the proven no-heisenbug instrumentation pattern; P132-ILOCK-STUCK is always-on.
