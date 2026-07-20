---
name: compiled-dirreuse-8tcp-tenure-epoch-ex-handoff-lostupdate
description: sess16 ccloop: dir_reuse 8/tcp loss = mid-transaction dir-EX-handoff lost-update; tenure-epoch fix design + refuted acquire-side levers.
metadata:
  type: project
tags: [compiled, dir_reuse, cache_coherency, dlm, ex-handoff, tenure-epoch, sess16, tcp_dlm]
---

# dir_reuse 8/tcp — mid-transaction dir-EX-handoff lost-update + tenure-epoch fix

sess16 (ccloop `4cb2d0a2`) investigation of the last ship blocker: the
`dir_reuse_coherency` sub-test of the 8-node TCP `cache_coherency` criterion
loses directory entries. All 19 source memories describe ONE bug: a cross-node,
cross-tenure RMW lost-update on the hottest shared dir block. Criterion NEVER
met this session — marker not written. Every build here keeps new logic gated
OFF at default, so default-config behavior == the `48C6A95E` baseline.

## The proven root — mid-transaction grant handoff

[[sess16run-BREAKTHROUGH-dir-EX-handoff-midtransaction-lostupdate]] is the
decisive evidence (P-DIRWR count timeline, dirwr=2, 8 nodes, daddr=120
block-format dir block, ino=131). Round 1 sorted by realns: test4 grew block0
to cnt=126 (dd), then 225µs later test2 durably wrote cnt=77 — a **126→77
revert dropping ~49 of test4's entries** — then grew from its stale 77 base.
Two nodes RMW'd the same shared dir block from divergent bases.

Mechanism: a dir-modify (`xfs_dir2` addname) holds the dir **ILOCK** for the
whole transaction, reads block0 into the txn (base=77), then commits. mxfs's
DLM **EX grant is separate from the ILOCK**: on a peer BAST the grant is
released to the peer while the local txn still holds the dir buffer joined and
dirty. The peer modifies (→126); when this node re-acquires and commits, its
buffer is still based on the stale 77 and was never re-read → durable clobber.
Not a read-cache staleness, not a literal double-grant — serialization broken
by mid-transaction grant handoff.

`inode_mht_ms` (EX min-hold-time) is the speed/correctness knob and a CRUTCH:
mht=300 holds the grant long enough that the txn commits before handoff →
dir_reuse PASS but tcp_dlm_scaling FAIL (slow); mht=50 releases mid-txn →
dir_reuse FAIL but tcp_dlm PASS (fast). The window between "long enough to be
correct" and "short enough to be fast" is EMPTY. Committed direction: hold the
EX grant until the dir-modify transaction commits (dir inode unpins / dirty
BLIs clear), frequency-independent — a transaction-scoped grant hold, not a
timed defer. Candidate signal: `ip->i_pincount>0` or an in-core "dir modify in
progress" marker across `xfs_dir2` addname/removename, checked in
`mxfs_dlm_mht_defer_bast` / `mxfs_dlm_bast_process` (~5719).

### The victims are deterministic (and why)
[[sess16run-RESOLVED-f1-written-then-clobbered-on-hot-block0]]: the lost names
are ALWAYS `node1_f1` (rank1's FIRST file) and `node5_f40`. A dirwr=2 trace
proved node1_f1 is durably WRITTEN many times (test1×286, test3×129, test4×81,
etc.) then CLOBBERED — NOT never-written, NOT a structural format-transition
drop. It is deterministic because node1_f1 lives in block0 (daddr=120), the
HOTTEST block that every node's early creates RMW — the block carrying the
proven 126→77 regression. Not a special-case bug, just the most-contended
block. [[sess16run-mht50-dirreuse-loss-durable-survives-forcecoherent]]: the
loss is DURABLE on disk — on the owner test1, `P21H-LEAFHOLE` (leaf hash hole
for a name still in the data block) + `P33-DSCAN-ONDISK incore==disk`; peers
report round 1 readdir=751/800, lookup_fail=2, missing=[node1_f1.md5
node5_f40.md5]. A separate SECONDARY `P32-NXSHRINK` shutdown hits only test1
(`P32-IFLUSH-NXSHRINK`, stale smaller dir extent map flushed under EX,
comm=rm); it is downstream of the leaf-hash loss — fix the loss first.

## Refuted levers — the loss is NEITHER read-staleness NOR write-durability

Every buffer-coherency mechanism was tested at mht=50 dirwr=0 (the config where
the race manifests) and FAILED with the identical node1_f1/node5_f40 loss:

| Lever | Layer | Result |
|---|---|---|
| `force_coherent=1` (FUA re-read every dir block, no cache hit) | read | FAIL |
| `dir_postread_reread=1` (FIX3 grant-gen re-read) | read | FAIL |
| `b_mxfs_dir_epoch` tenure-epoch trigger | read | FAIL |
| `dir_release_fua_write=1` (release block to platter via SCSI FUA) | write | FAIL |
| `dir_release_invalidate=1` (drain-then-invalidate, cold-read next) | release | FAIL |
| P16 leaf-refresh (crc-differ) | acquire refresh | REVERTED (regressed) |
| prior-tenure evict override (`dir_evict_prior_tenure`) | acquire evict | FAIL (too sparse) |

- [[sess16run-mht50-dirreuse-loss-durable-survives-forcecoherent]]: force_coherent
  + postread both fail → not a cache-hit stale read.
- [[sess16run-epoch-readside-trigger-REFUTED-loss-is-not-readside]]: build
  `42178C17` added `b_mxfs_dir_epoch` (xfs_buf.h), stamped =
  `dp->i_dlm_dir_valid_epoch`, postread-reread trigger overriding the payload-LSN
  undestaged keep-guard. Epoch machinery was LIVE (P65-EPOCH-ADOPT, P63-HANDOFF,
  grant_epoch 771→792) yet `P67-POSTREAD-REREAD` fired only 2× — the stale block
  is not being re-read. Proves the loss is not read-side; re-reading by ANY
  trigger doesn't prevent it.
- [[sess16run-release-fua-write-REFUTED-loss-is-DETERMINISTIC]]: FUA write to
  platter bypassing the LIO write-back cache — same loss → not a LIO
  write/read cache gap.
- [[sess16run-release-invalidate-REFUTED-points-to-DLM-grant-drain-ordering]]:
  `dir_release_invalidate=1` (GPT part-1 "publish-durable-then-discard": after
  the synchronous release bwrite lands, `xfs_buf_stale` + clear XBF_DONE so the
  next acquirer COLD-READS) STILL fails → the writer is not using a stale cached
  buffer that better invalidation would fix.

## Double-grant RULED OUT — the DLM serializes EX correctly

The P106 lead evolved and collapsed:
- [[sess16run-PIVOTAL-P106-overlapping-EX-grants-and-timing-race]]: two
  corrections — (1) the loss is a TIMING RACE, not deterministic-in-frequency: a
  `dirwr=2` run PASSED 8/8 because heavy per-IO tracing adds latency that
  serializes handoffs and closes the window (classic instr-masks-races). NEVER
  trust a dirwr=2/instr=1 PASS; validate only at dirwr=0/instr=0. (2) P106-EXGRANT
  appeared to show pervasive overlapping EX on ino=131 (420×).
- [[sess16run-P106-overlap-INCONCLUSIVE-instr-incomplete]]: that overlap is an
  ARTIFACT — P106-EXGRANT fires ONLY on the slow-path fresh acquire
  (xfs_mxfs_dlm.c:11774); fast-path cached-EX serve and PR→EX upgrade grant
  without logging, so single-holder pairing over logged grants is meaningless.
- [[sess16run-DECISIVE-double-grant-RULED-OUT-bug-is-buffer-layer]]: DECISIVE.
  Added an always-on, clock-free master-side auditor
  `mxfs_dlm_audit_double_grant()` (dlm/dlm.c, build `C1469F1E`, KEEP as a
  permanent cheap invariant check) wired at all 3 grant-commit points
  (new-grant ~1226, PR→EX upgrade ~1123, promote_waiters regrant ~626). On a
  failing dir_reuse 8/tcp mht=50 run, `MX-DOUBLEGRANT fired 0×` on all 8 nodes.
  The master table NEVER holds two incompatible EX/PR grants for ino=131. EX is
  granted SERIALLY, yet the acquirer's in-core base is stale → the bug is the
  buffer/reload layer, not DLM mutual exclusion.

## Acquire-side refresh structurally cannot work

[[sess16run-acquire-side-refresh-cannot-work-must-be-release-side]] (build
`247E2BCB`): the acquire/modify-path evict `mxfs_dir_evict_data_blocks` runs
heavily — P68-EVDECIDE=6000 (capped), 3720 blocks KEPT undurable — but
P-DIRREFRESH-EVICT (data) and P16-LEAFREFRESH-EVICT (leaf) each fired 0×. To
refresh a kept block it plain-reads disk and asks "is disk newer?", but at that
instant the PEER's newer write often is not yet on the LUN (peer mid-tenure /
drain not landed) → disk == our stale incore → refresh declines → we RMW the
stale base → clobber materializes later when writes interleave. An acquire-side
"is disk newer?" check is racing the peer and structurally cannot be reliable.
Conclusion: the only sound place to enforce coherence is the RELEASING node,
before it drops the grant.

[[sess16run-SYNTHESIS-next-target-PRtoEX-upgrade-grant-bypasses-drain]]
sharpens this: `mxfs_dlm_bast_process` (xfs_mxfs_dlm.c:5592) orders correctly
per Invariant-1 (drain — log_force + AIL/alloc drain + `mxfs_dir_data_durable`
— BEFORE the final `mxfs_v5_dlm_inode_unlock`). So the release-BAST handoff
serializes correctly; the unrefuted root is the DIRECT GRANT path:
dlm/dlm.c:512-527 documents a PR→EX UPGRADE / remote REAFFIRM that keeps the
grantee holding, decided only against conflicting GRANTED holders, firing NO
BAST and NOT routing through bast_process. bash `open(O_CREAT)` does
lookup(dir PR) then create(dir EX); mxfs CACHES the PR, so create is a PR→EX
upgrade on the hot shared dir — the node held ≥PR continuously, no handoff
transition is detected, the reload-on-acquire never runs, and the stale PR-era
buffer is carried into the EX tenure and RMW'd. This unifies WHY every
read-side and release-path lever failed (none touch the upgrade path). Fix
candidates: (a) on PR→EX upgrade of a dir inode, force the full reload+evict
pipeline before granting; (b) route the upgrade PR→NL→EX (clean reacquire) for
dir inodes; (c) route contended-dir upgrades through the BAST/drain path.

## The tenure-epoch fix design (GPT-5.5) and its implementation arc

[[sess16run-GPT-design-tenure-scoped-dirbuf-coherency-FIX]] — the convergent
design. Core invariant: **a dir DATA/LEAF/NODE/FREE buffer is valid only while
the node has CONTINUOUSLY held ≥PR since the buffer was loaded**; dropping below
PR ends the tenure and invalidates the cached RMW base. Non-resurrection
predicate (the ~90-session knot): at demote/release AFTER Invariant-1's
synchronous drain the buffer is DURABLE on the LUN, so clearing XBF_DONE is NOT
resurrection. The payload-LSN "undestaged" heuristic gives FALSE POSITIVES and
must not decide cross-node coherence — DLM tenure/epoch state dominates. Three
parts, do all: (1) PRIMARY — drain-then-invalidate at RELEASE under a **REVOKING
writer-fence** that blocks NEW local dir ops from starting the txn (not just DLM
acquire), waits active_dir_ops==0, drains, invalidates ALL dir metadata buffers
(DATA+LEAF+NODE+FREE, not just daddr=120), then drops grant; the fence closes
the "redirty-after-drain, before grant-drop" window that sank sess96's naive
force-evict. (2) BACKSTOP — epoch-invalidate at REACQUIRE, keyed on the EPOCH
(level-triggered, reliable) not grant_gen (overfires). (3) ENFORCE at USE —
stamp each buf with (tenure_gen, epoch); before RMW require
`XBF_DONE && buf.tenure==ip.tenure && buf.epoch==ip.epoch && grant≥PR/EX` else
FUA-reread+restamp.

The session then tried to build the acquire-side pieces (parts 2+3) and hit a
density/lag chain that ultimately REFUTED the pure acquire-side epoch approach:

1. [[sess16run-epoch-stamp-too-sparse-cachehit-blocks-unstamped]] (build
   `EA41172C`): the prior-tenure evict override (`dir_evict_prior_tenure`)
   ENGAGED but fired only 10-20× vs ~6000 evict decisions (3720 kept-stale) —
   `b_mxfs_dir_epoch` is stamped ONLY on a genuine fresh disk read; block0 is
   served as a CACHE HIT forever so its epoch stays 0 and the `epoch != 0`
   safety guard SKIPS it. You cannot safely stamp a cache-hit with the current
   epoch (that is the lossy dir_gen bug). Only robust models: GPT tenure-CHECK
   at use, or release-side invalidate.
2. [[sess16run-FINAL-fix-recipe-stamp-epoch-on-dirblock-create-and-read]]: the
   proposed density fix — stamp `b_mxfs_dir_epoch = i_dlm_dir_valid_epoch` at
   dir-block CREATE/INIT (`xfs_dir3_data_init`, `xfs_dir3_leaf_init`,
   `xfs_dir3_free_init`) AND at every coherent cache-hit pass-through in
   `xfs_da_read_buf`, THEN drop the `epoch != 0` guard.
3. [[sess16run-HANDOFF-tenure-epoch-fix-remaining-implementation]] (build
   `8524552B`): plumbing done, gated OFF. Identified that stamping only on
   create leaves a block created at tenure 0 then modified in the current tenure
   still at epoch 0 → falsely evicted. So MODIFY-stamp is also required
   (`xfs_dir2_data_log_entry/header`, `xfs_dir3_leaf_log_header`).
4. [[sess16run-FINAL-epoch-check-must-be-in-PREread-not-evict]] (build
   `7FC04802`, create+modify stamp + dropped guard + `dir_evict_prior_tenure=1`):
   STILL FAILS 0/8. P16-PRIORTENURE fired 28×/10× vs ~3600 kept blocks carrying
   epoch==valid. Precise gap: a modify READS a stale block0 (cache-hit,
   pre-peer-image), adds its entry, and the MODIFY-STAMP then marks it epoch ==
   current → the clobbered block looks like legitimate current-tenure work, so
   no evict flags it. The staleness lives in the READ before the modify. FIX:
   move the epoch-staleness CHECK to the ALWAYS-ON pre-read invalidation block
   in `xfs_da_read_buf` (~3176-3352, the incore+clear-DONE path that runs for
   EVERY dir DATA-fork read), clearing XBF_DONE before the read returns.
   CAUTION: runs under ILOCK with XBF_TRYLOCK — verify no deadlock (use the
   existing dir_gen invalidate as the template).
5. [[sess16run-ROOT-valid-epoch-lags-use-master-authoritative-epoch]] (build
   `4509825F`): the ROOT of why acquire-side epoch fails —
   `i_dlm_dir_valid_epoch` LAGS real handoffs. It is set only at
   xfs_mxfs_dlm.c:~9389, near the END of the reload, AFTER the P43/P43B/P62
   keep-stale guards that frequently `return` early → line 9389 not reached →
   valid_epoch does not advance even though a handoff occurred. Measured
   (mht=50): valid_epoch climbs 0→66/0→58 while master grant_epoch reaches
   70/67. So a stale block0 stamped at epoch 66 vs stuck valid_epoch 66 →
   66<66 false → not flagged → stale read proceeds. FIX: use the master's
   AUTHORITATIVE per-inode epoch `mxfs_v5_dlm_inode_dir_epoch(mp->m_mxfs_dlm,
   ino)` (bumped on EVERY cross-node handoff, NOT gated by keep-guards) as BOTH
   stamp and compare value everywhere. Watch RULE-0 cost (one hash lookup per
   dir create/modify/read; cache per-op if hot).
6. [[sess16run-INPROGRESS-master-epoch-check-done-stamps-remain]] (build
   `E3CDB9F1`, COMPILES, all gated → INERT/safe baseline): master-epoch swap
   PARTIALLY done — the pre-read CHECK in xfs_da_btree.c now computes
   `cur_ep = mxfs_v5_dlm_inode_dir_epoch(...)` and flags
   `cbp->b_mxfs_dir_epoch < cur_ep`. REMAINING: swap all STAMP sites
   (xfs_da_btree.c dir_stamp_fresh + postread + create-init; xfs_dir2_data.c
   `xfs_dir3_data_init`/`xfs_dir2_data_log_entry`/`_log_header`; xfs_dir2_leaf.c
   `xfs_dir3_leaf_init`/`_log_header`) and the evict-override from
   `i_dlm_dir_valid_epoch` to the master epoch, then enable
   `dir_evict_prior_tenure=1` and validate.

## Corrected framing — no mht reliably passes

[[sess16run-CORRECTION-dirreuse-fails-at-mht300-too-no-reliable-mht]]: build
`72C02C21` at DEFAULT mht=300 FAILED 0/8 with the SAME content-loss signature
(round 1 readdir=751/800, node1_f1/node5_f40 missing) + shutdown at round 7-8
of 24 — NOT a timeout. So the earlier "mht=300 PASS" (sess15's
MHT-tradeoff framing, and the handoff's "16/17") were LUCKY runs: the
lost-update is a timing race present at ALL mht; higher mht only makes it less
frequent (fewer handoffs → smaller window). The criterion needs 100%, so the
race must be ELIMINATED — tuning mht cannot achieve it. Both 8/tcp tests fail
(dir_reuse = lost-update; tcp_dlm_scaling = too slow at mht=300); the only fix
path is to make the dir modify correct at LOW mht.

## Build progression & KEEP items

`BAB5566E` (baseline + inert P32F-NXSHRINK fence) → `42178C17` (+ inert
`b_mxfs_dir_epoch` read-trigger) → `C1469F1E` (+ MX-DOUBLEGRANT auditor, KEEP)
→ `247E2BCB` (+ gated P16 leaf-refresh, later removed) → `EA41172C` (prior-tenure
evict override + sparse stamps, gated) → `8524552B` (+ create-stamp) →
`7FC04802` (+ modify-stamp, dropped epoch!=0 guard) → `4509825F` (P65-EPOCH-ADOPT
always-on measurement) → `E3CDB9F1` (master-epoch swap, in-progress). Every
build is a safe baseline: all session params default OFF
(`dir_evict_prior_tenure=0`, `dir_postread_reread=0`, `dir_nxshrink_fence=0`,
`force_coherent=0`, `dir_epoch_adopt=1`), default-config behavior == `48C6A95E`.
Permanent KEEP: the **MX-DOUBLEGRANT auditor** (dlm/dlm.c) — cheap always-on
master-table scan proving EX serialization.

## Validation protocol (for whoever finishes this)
Validate ONLY at mht=50 dirwr=0/instr=0 (dirwr=2 and instrumentation MASK the
race — a dirwr=2 run PASSED spuriously). Require: P16-PREREAD/PRIORTENURE fire
MANY× (covering block0); P-DIRWR daddr=120 count MONOTONIC (no 126→77);
dir_reuse 8/tcp PASS across ≥5 clean-reboot runs (virsh destroy+start test1-8 —
a FAIL wedges the LUN, must reboot before re-prep). Then tcp_dlm_scaling ≤60s,
full 8/tcp 17/17, then 1/2/4. Resurrection canaries unlink_visibility,
rename_visibility, crash_consistency MUST stay PASS. Watch RULE-0 timing from
extra re-reads. Repro:
`MXFS_EXTRA_MODARGS='inode_mht_ms=50 dirwr=2' MXFS_TEST_ENV='DRC_ROUNDS=2'
./run.sh 8 tcp dir_reuse_coherency`; merge P-DIRWR owner=131 across nodes, sort
by realns, grep daddr=120 count regressions. If the master-epoch acquire-side
CHECK also fails, the staleness is not handoff-detectable at the acquirer at all
→ fall back to the GPT RELEASE-side REVOKING fence (parts 1+2), the direction
that is over-determined by the double-grant ruling and the acquire-side
structural refutation.
