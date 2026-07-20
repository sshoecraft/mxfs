---
name: compiled-cc-dir-block-lost-update
description: Compiled sess68-100: durable write-side dir-block/shortform lost-update behind unlink/cross/rename coherency + GPT/Gemini fix designs.
metadata:
  type: project
tags: [compiled, cache-coherency, dir-block-lost-update, unlink-visibility, publish-before-notify, xfs-buf-stale]
---

# Compiled: durable dir-block / shortform-dir lost-update (cache_coherency ship blocker)

Central topic: for sess68→sess100 the sole remaining ship-gate failure is the
`cache_coherency` criterion (11/12 other criteria PASS — rsync_paired 103%,
single_node 104%, all robustness/tooling green per [[sess84_lessons]]). Its four
subtests — `cross_visibility`, `rename_visibility`, `unlink_visibility`,
`cross_write_read` — fail on a **durable WRITE-side lost-update on a shared
directory** under 4-node concurrent create/rename/unlink. A node RMWs a shared dir
block/dinode off a stale base and durably clobbers a peer's committed dirent(s).
Test cluster = test1-4 (`MXFS_HOST_OFFSET=0`; cache_coherency.sh sets
`MXFS_NODE_OFFSET=16`). `fua_disable=1` is the correct module default throughout.

## Two on-disk formats, two surfaces of the same bug
- **SHORTFORM/LOCAL dir** (dirents inline in the dinode): `cross_visibility` (4
  entries, one per node). Loss = last committer's dinode revert.
- **BLOCK/LEAF dir** (dirents in separate DATA blocks): `rename_visibility` (80
  entries), `unlink_visibility` (120 entries). Loss = dir DATA block RMW off stale
  base. `cross_visibility` passed early precisely because shortform rides inode
  coherency; rename/unlink grow the dir to block format where per-block staleness
  bites ([[sess80_lessons]]).

## HARD on-disk proof it is write-side, not transport ([[sess69-ondisk-proof-durable-lostupdate]])
`tests/uv_disktruth.sh` reproduces the divergence, then reads the dir DATA block
RAW via `dd iflag=direct` on multiple initiators (device skip = xfs_data_offset/512
+ XFS daddr; xfs_data_offset @ byte 88 of mxfs_ondisk_super). Findings:
1. Raw O_DIRECT bytes are **BYTE-IDENTICAL across initiators** → SCST/transport is
   coherent; per-initiator stale-read hypothesis REFUTED.
2. On-disk block (magic XDB3, bs=4096) leaf tail `count=122 stale=101 active=21` =
   19 files durably retained that should be deleted. Nodes showing 0 hold correct
   but NON-durable in-core; nodes showing 19 read the wrong durable disk.
So with proper EX serialization (`ex_pop=1` everywhere; concurrent-EX REFUTED,
matches sess52), working acquire-evict, and coherent transport, a stale-based image
still got durably written. Gemini's `xfs_dir2_leaf_to_block` reshape hypothesis
REFUTED — probe **P69-L2B** (xfs_dir2_block.c) fired 0× (dir stays leaf format at
45 entries; loss is in the NORMAL leaf-format removename path). Sharpened root: a
SILENT stale block — `b_mxfs_dir_gen == i_dlm_dir_gen` (passes the lazy
`xfs_da_read_buf` hook) but content stale, because gen-bump+evict run ONLY on the
slow-path acquire (xfs_mxfs_dlm.c ~L3122-3167); a FAST-PATH dir EX re-acquire does
no gen-bump/evict → stale served as fresh, RMW'd, flushed = durable clobber.

## Release path is NOT early-unlock ([[sess68-check5-result-unlink-base-staleness]])
GPT "Check-5" (does unlock publish before the fence worker completes?) REFUTED by
reading `mxfs_dlm_bast_process` (xfs_mxfs_dlm.c L743-1744). For a dir inode the
order is: set i_dlm_mode=NL (local gate) → release durability fence
(log_force(SYNC)+ail_push+`mxfs_dir_flush_data_blocks` xfs_bwrite each DATA block
until `mxfs_dir_data_durable`, 15000-iter backstop→shutdown) →
`mxfs_dir_evict_data_blocks` → inode-cluster quiesce → blkdev_issue_flush →
`mxfs_v5_dlm_inode_unlock` (genuine on-disk publish, AFTER all flushing). The
releasing node DOES land its own blocks first. Sharpened hypothesis: ACQUIRE-side
base staleness under fua_disable=1 — the re-acquiring node's cached dir DATA block
is not refreshed to the peer's latest committed state before it applies its own rm,
so it flushes a stale-base image that resurrects the peer's removed entry. mxfs.1
passes because its dir_cache re-parses under EX from a DLM-coherent block_cache
dropped on BAST and re-read fresh; v5's evict+reread does NOT reliably pull a peer's
just-committed block off SCST under fua_disable=1.

## Chronology of fixes and refutations

### sess80 ([[sess80_lessons]]) — HB evict-ring generalized to DIR_MODIFY
Build **71FD67B0** (KEEP): generalized the heartbeat eviction-ring (was INODE_FREE
only) to carry DIR_MODIFY entries. Producer = xfs_dir_createname/removename/replace
call `mxfs_dlm_note_dir_modified(mp, dp->i_ino)`; consumer =
`mxfs_dlm_evict_inode_cb` branches on type, bumps peer `i_dlm_dir_gen++`; the
existing xfs_da_read_buf invalidation then re-reads stale-but-CLEAN cached blocks.
RESULT: cache_coherency 1/3→2/4, rename_visibility PASSES. Rename root nailed: `mv:
cannot stat node3_before_9` = node3 can't stat its OWN just-created file = write-side
lost-update. bnobt double-free SHUTDOWN still open; Gemini: local `pag_dlm_meta_gen`
STUCK at 1 → move AG versioning to a SHARED ON-DISK AGF epoch.

### sess82 ([[sess82_lessons]]) — evict-ring was DEAD cross-node in CAW
Build **B5C1FA0F** (KEEP). PROVEN via P-EVICT-STAGE (producer, 37-80/node) vs
P-EVICT-DISPATCH (consumer, **0 on every node**): `disklock_hb_fn` gated peer slots
on `if(!ctx->monitored[slot])`, and `mxfs_disklock_monitor_node` was ONLY called on
the TCP path — the CAW path never called it → all-false → 0 dispatch. So sess55/80
coherency signals were dead on the real (CAW) cluster the whole time. FIX =
self-healing auto-monitor in disklock_hb_fn (auto-monitor any ACTIVE peer HB).
DISPATCH → ~200/node; unlink soft failures 10→2. **Auto-monitor EXPOSES the durable
lost-update**: gen-bump now works → node1 invalidates its own CLEAN cached dir block
→ re-reads a DISK image missing node1's own creates → 31 fails / "node1 lost its own
30 files". Confirms the disk dir blocks are durably corrupt. Also unified the
`unlink_visibility` shutdown: `xfs_dir_removename rc=-2 (ENOENT)` on a node's OWN
just-created dirent → xfs_trans_cancel(dirty) → SHUTDOWN. **Defensive
REMOVE-REVALIDATE** (KEEP): xfs_dir_lookup_locked before remove_child, ENOENT→cancel
CLEAN txn → converts catastrophic shutdown to benign "rm: No such file", 0 shutdowns.
FAILED/REVERTED: per-unlink durable-on-release in xfs_remove — whole-AG
ail_push_ag_sync WEDGED 3 nodes (holds dp ILOCK across whole-AG drain); targeted
bwrite without log_force WEDGED (wait_unpin on pinned buf); +log_force REGRESSED
2→31 (per-unlink flush desyncs + peers FUA-read a TORN txn = new dir block/old inode
→ "sees 90/120"). Dormant helpers `mxfs_dlm_dir_durable_signal` +
`mxfs_dir_flush_data_blocks` left exported/unused for a future correct call site.

### sess83 ([[sess83_lessons]]) — noino-BAST root for BLOCK-format dirs
Build **F08CE615** (KEEP). PROVEN (P-DIRREL-DIFFERS=0 → bast_process handoff release
IS durable; but `bast: noino=2..12`/node). **noino** = `mxfs_dlm_bast_notify` gets a
BAST for an inode NOT in-core (reclaimed mid-run) → does a DIRECT
`mxfs_v5_dlm_inode_unlock` with NO dir-data drain. The shared 120-entry dir hits
noino. Gemini confirmed: xfs_reclaim_inode→mxfs_dlm_evict once the inode CORE is
clean, but a directory's data-fork xfs_buf's are independent AIL items reclaim's
iflush doesn't write → evict releases DLM with dir blocks dirty → peer FUA-reads
stale → clobbers = Invariant #1 violation. FIX in `mxfs_dlm_evict` for multi-node
S_ISDIR EXTENTS dirs, before unlock: `xfs_log_force(SYNC)` +
`mxfs_dir_flush_data_blocks(ip)` (targeted per-block, NOT whole-AG) +
`blkdev_issue_flush`. MUST NOT re-take i_lock (XFS_ILOCK IS the i_lock rwsem, already
held by reclaim). Remaining: shortform LOCAL barrier dirs still lose entries; slowness
from bast_process per-handoff whole-AG push.

### sess84 ([[sess84_lessons]]) — shortform loss = LAST committer reverts its own dinode
Build on nodes **83522A1B**; local **564A41EF** (P-SFDIR-REVERT). PROVEN via
cross-node P-SFDIR-RELOAD/FASTEX timeline: nodes form a clean RMW chain and node1
(test1, always adds LAST/lowest-id finishes) reloads count=3 correctly, adds node1 →
count=4 in-core, commits — but **disk stays count=3**; a later test1 reload re-reads
stale count=3 and reverts its OWN count=4 → node1 loses its own file. Concurrent-EX
REFUTED (CAW-EXCL-VIOLATION=0, CAW-DUP-SLOT for INODE=0 after extending the detector
from AG-only). Mechanism = CIL-window early-break: shortform add commits into CIL,
brief window where the log item is not-yet-in-AIL and not-pinned yet the on-disk
dinode is STALE; two sites assume `!in_ail && !pin ⇒ durable` and skip flushing.
Fix attempts (extend L1378 inode-cluster flush to S_ISDIR; gate early-out to S_ISREG)
did NOT fix — because the LAST committer is never BAST'd (holds dir EX sticky-cached;
test ends before a peer BASTs it) so the release-side flush never runs for it.

### sess85 ([[sess85_lessons]]) — cross_visibility shortform loss FIXED (provisional)
Build **7C44AF11** (KEEP, no regression, cross_vis ~0/5→4/5). PROVEN via
P-DIRFLUSH: test4 (LAST) adds node4.txt → `count=4 own=1` (own iflush writes cnt=4),
then `count=3 own=0` (a CO-RESIDENT child inode flush re-writes the SAME cluster
buffer but the dir slot is back to cnt=3) → disk reverts → node4.txt durably lost.
`own` = flushing-mask (1=this node iflushing the dir; 0=dir is a foreign co-resident
slot). Revert path is NOT `mxfs_iflush_cluster_merge_dirs` — both new guards
(P-CLMERGE-SKIP-HELD, P-CLMERGE-DIRAHEAD) fire 0× in failing AND passing runs. So the
buffer's dir slot becomes cnt=3 via buffer invalidation (XBF_DONE cleared) then
FUA-re-read from stale platter (test4's cnt=4 in SCST write cache, not destaged), and
a later co-resident child flush writes cnt=3 back. Changes: `mxfs_inode_cluster_durable`
in mxfs_dlm_evict for FMT_LOCAL dirs (fires 0×, harmless). Criterion still 1/4
(rename 28 misses fast; unlink 1-21+140s; cwr 1+244s). **CRITICAL INFRA**:
`/mnt/mxfs-src` NFS mount drops off test1 after reboot → node1 rc=127 → node1 never
runs test → FALSE-POSITIVE loss; ALWAYS remount on all nodes before runs.

### sess88 ([[sess88_lessons]]) — dir-block durable lost-update FIXED (noino-BAST AG drain)
Build **73B57CCD** (KEEP). One-line change in `mxfs_dlm_bast_notify` NO_INODE branch
(~L1719) before unlock: `xfs_log_force(SYNC)` +
`xfs_ail_push_ag_sync_bounded(m_ail, XFS_INO_TO_AGNO(ino), 50, 8)` +
`blkdev_issue_flush`. Root = the P-NOINO-BAST path released the DLM slot with no
dir-data drain (reclaim flushes only inode CLUSTER; dir-data xfs_buf's are
independent AIL items); DIR-STALE-SKIP fired 20-40× with disk_differs=1 buf_gen=0.
RESULT: DIR-STALE-SKIP 20-40→0; rename_visibility PASSES 0/240 in ISOLATION; unlink
shutdown eliminated; cwr now runs. REVERTED (RULE-4 disproven): adding
`mxfs_dir_evict_data_blocks` after flush in mxfs_dlm_evict — clearing XBF_DONE on a
buffer whose bli is still in the AIL makes it UN-PUSHABLE → xfsaild stuck 39000+ iters
→ near-hang + SB-LSN shutdowns (confirms sess39/64: NEVER clear XBF_DONE on a
dirty/pinned/in_ail buffer). Eviction is unnecessary once release-side flush makes the
buffer clean. NEXT blocker isolated = bnobt AG-meta in-core corruption (P88-INSTR:
in-core numrecs=2 rec0=[32777,7] vs disk numrecs=3 rec0=[32777,1], buf_gen=1 pag_gen=1
MATCH, sole EX holder) — `pag_dlm_meta_gen` frozen at 1; Gemini: shared on-disk AGF
epoch.

### sess95 ([[sess95_lessons]]) — inode-reload fixes, cache_coherency 1/4→3/4
Two in-place `mxfs_dlm_reload_inode` fixes for REFERENCED inodes eviction can't fix
(xfs_irele won't reclaim referenced; retry_iget cache-HITs same stale inode):
P95-SAMETYPE-RELOAD (build **6B77CE94**, rename PASS) and P95-TYPEFLIP-RELOAD (build
**66A40A3D**, uv_delete PASS). Gemini: reloading the dinode alone is insufficient —
OLD dir DATA blocks must also be XBF_DONE-cleared under fua_disable=1 (reload already
does this). Last blocker = uv_verify typeflip RELOAD THRASH: sess90 typeflip-stale
guard (~L2013) rejects a genuine file→dir flip because XFS gens are RANDOM
(disk_gen<incore_gen is NOT a reliable stale signal); the DIRENT ftype (ground truth)
AGREES with the disk inode.

### sess96 ([[sess96_lessons]]) — typeflip-ftype fix + FUA disproven
Build **FB9573F7** (KEEP). Threaded authoritative `dirent_ftype` into
`mxfs_dlm_reload_inode(ip, expect_ftype)`; bypass the typeflip-stale skip when
disk di_mode ftype == dirent ftype. RESULT: unlink thrash 146s→28s. Remaining
lost-update small under fua_disable=1: rename 2/240, unlink 2/122, cwr 1/6. PROVEN
root of the 2-fail: **local pinned-stale dir-buffer reuse** — `DIR-STALE-SKIP ino=136
pin=1 disk_differs=1 dirty=0 bli_flags=0x2` fires; the read-time invalidation
(xfs_da_btree.c ~L3001) takes the SKIP branch when the cached buf is pinned/dirty/in-AIL
(can't re-read a pinned buf — sess64: races writeback → corruption + shutdown). So the
node keeps its stale buffer, RMWs, durably clobbers a peer. **fua_disable=0 DISPROVEN**:
rename alone with FUA on = 370s (45x slower, timing FAIL) AND 40 fails (WORSE) — FUA
reads the STALE PLATTER (writes sit in SCST write-back cache; the normal dir BAST
path has no blkdev_issue_flush to destage). Do NOT re-enable FUA. REVERTED:
deterministic flush+evict on release (build FB8842FD) — made rename 2→24; xfs_bwrite of
a dir block on release WRITES the local (stale) buffer to the target = clobbers.

### sess96 GPT design ([[sess96_gpt_fix_design]]) — invariant set
GPT-5.5 (after 2 Gemini consults, RULE 5). **Inv 1**: DLM EX demote/release MUST be a
real XFS metadata CHECKPOINT FENCE — every protected buf not pinned/dirty/no
uncheckpointed AIL obligation AND (if modified this tenure) reached the shared target;
no timeout/best-effort; writeback fail → xfs_force_shutdown. **Inv 2**: slow-path EX
ACQUIRE is an INVALIDATION FENCE — bump gen, mark clean/unpinned bufs stale
(clear-DONE); pinned/dirty/in-AIL prior-tenure buf = protocol violation → shutdown;
NEVER write a stale buf on acquire (Fix A's flaw). **Inv 3**: the DIR-STALE-SKIP
"keep stale and continue" branch must become FATAL (xfs_force_shutdown, no local
merge — XFS has NO semantic merge for metadata buffers). WHY sess96 fixes failed: Fix
A (release xfs_bwrite) published a divergent image because the acquire base was
already stale; Fix B (read-time wait_unpin+reread) forces a pinned stale image out =
clobbers, then reads its own clobber. Implementation: track dirty bufs explicitly per
DLM lock domain; BAST = quiesce+queue (do NOT release in callback); demote worker on a
blocking WQ (NOT the BAST/CAW-poll thread, no ilock/txn/buf locks) does
wait active==0 → log_force(SYNC) → per buf lock+wait_unpin+bwrite → assert clean →
unlock. Caveat: `xfs_buf_wait_unpin` is STATIC in pal/linux/xfs_buf.c:1020 → de-static/export.

### sess97 ([[sess97_lessons]]) — WRITER-SIDE publish-before-notify (rename PASS)
Build **476E164C** = FB9573F7 + writer-side publish-before-notify → rename_visibility
2/240→0 PASS (32s). Wired `mxfs_dlm_dir_durable_signal(dp)`
(log_force(SYNC)+mxfs_dir_flush_data_blocks+note) POST-commit with ILOCK+EX held,
into xfs_remove/xfs_create/xfs_rename (both src_dp+target_dp). Safe at COMMIT (buffer
is this node's own change; EX excludes peers) where sess96's release-time flush
clobbered. Reader half (partial): `mxfs_dlm_dir_consumer_refresh(dp)` at top of
xfs_file_readdir + xfs_lookup — when `i_dlm_dir_gen > i_dlm_dir_evicted_gen` eagerly
evict all CLEAN dir DATA blocks (new field `i_dlm_dir_evicted_gen`). Build
**AF60EC48**: unlink 2→1 survivor. Remaining-1 fix (build **1B611843**, untested):
`mxfs_dir_evict_data_blocks` returns all_evicted; advance evicted_gen ONLY on full
success so a skipped (pinned/in-AIL) block retries once durable.

### sess97 GPT design ([[sess97-gpt-dir-coherency-design]]) — durable per-dir SEQLOCK epoch
GPT verdict (ranked): BEST = (C) shared durable per-directory EPOCH as a SEQLOCK, read
synchronously by readers on every lookup/readdir; make it the AUTHORITATIVE coherency
mechanism and stop relying on heartbeat/EVICT-RING for correctness. seq even = stable
published; odd = writer in progress. Storage v1 = CAW/DLM resource record (LVB) via RAW
plain bio (NOT bread/xfs_buf), NO FUA. Writer: EX → publish ODD (E+1) → txn → commit →
log_force(SYNC) → bwrite ALL modified dir metadata (data+leaf+node+freeindex+dabtree+
inode core if changed, each wait_unpin+bwrite+wait) → publish EVEN (E+2) → release EX.
Reader `mxfs_dir_read_coherency_envelope(dp)` at TOP of lookup/readdir: raw-read epoch;
odd→sleep+retry; if != observed → reload dinode+ifork, mark buffers stale(target=seq).
Buffer hooks stamp `b_mxfs_dir_epoch` ONLY AFTER the reread completes (never before).
(B) restamp fix (reread-before-stamp) REQUIRED but insufficient alone.

### sess98 ([[sess98_lessons]]) — the decisive WRITE-submission trace (P-DIRWR)
Built the long-wanted instrument: in xfs_buf_submit, log every dir block/leaf/data
WRITE on a multi-node mount (fmt, owner-ino, daddr, count, stale, active, pin/in_ail/
dirty/done, comm, realns; capped 8000, realns merges 4 nodes into ONE per-daddr
timeline). Build **8946A0F6**. PROVEN (airtight): in the DELETE phase active must
DECREASE monotonically; instead **active OSCILLATES — stale DECREASES on some writes**
= a node flushes an in-core dir buffer 1-2 deletions BEHIND a peer's already-flushed
version, durably reverting peer deletions. KEY: ALL target writes are comm=xfsaild/sda
(async AIL push, in_ail=1) over 10-21s; ZERO writes by the release path — the block
reaches the shared target ONLY via async xfsaild; reverts are NEAR-CONCURRENT (acquire
base ~1 behind, not seconds-late). Found+fixed a real gap: `mxfs_dir_data_durable`
(xfs_mxfs_dlm.c:85) checked DIRTY/pinned/DELWRI_Q/!DONE but OMITTED XFS_LI_IN_AIL, so a
removename-committed block (DIRTY clear, DONE set, IN_AIL set) reported "durable" and
the fence loop broke without flushing. FIX = add IN_AIL to `bad` (build **1383B52D**).
RESULT: STILL FAILS (2-21 survive) + sometimes 5x slow — P-RELFLUSH fired 0×; the
whole-AG `xfs_ail_push_ag_sync(d_agno)` at L1336 makes xfsaild write+AIL-remove the
block first (so by L1338 needs_flush=false→skip), and it is SLOW (148s vs 26s). Inv1
~satisfied yet lost-update persists ⇒ remaining bug is ACQUIRE-SIDE stale base +
async-xfsaild out-of-tenure-order flush. Build **8AA373A2** (+P-RELFLUSH, all probes
KEEP).

### sess98 GPT design ([[sess98_gpt_fix_design]]) — buffer cache is TENURE-LOCAL
GPT-5.5 with the write-trace proof. Model: for shared dir metadata, treat the xfs_buf
cache as TENURE-LOCAL, not persistent. Minimal fix (release+acquire are a PAIR):
release path, per buf while holding dir EX — DO NOT use whole-AG push, DO NOT call
xfs_trans_ail_delete manually; log_force(SYNC) → wait_unpin if pinned → lock → targeted
xfs_bwrite if dirty/DELWRI/in-AIL → verify clean → **`xfs_buf_stale(bp)`** (THE MISSING
STEP: removes the local copy from cache+future writeback so xfsaild can never flush a
stale image, and forces the next read to cold-fetch) → unlock+rele → THEN release DLM
EX. Current `mxfs_dir_evict_data_blocks` only clears XBF_DONE (a cleared-DONE buffer can
still be re-dirtied/re-flushed; a STALE one cannot). Acquire path: cold-read from target
(plain, non-FUA). Optional cleaner arch = on-disk per-directory coherence EPOCH (3
parts: read-validate, write-suppress, recovery-validate) but do the buffer
write-invalidate handoff FIRST.

### sess99 ([[sess99_lessons]]) — release-side xfs_buf_stale WORKS (block-dir loss FIXED)
Build **D6AD04FE** (KEEP, deployed test1-4). FIX 1 (KEEP, PROVEN): new
`mxfs_dir_stale_data_blocks` wired at bast_process dir-release REPLACING
mxfs_dir_evict_data_blocks — on release, for each DURABLE (clean/!in_ail/!pinned/
!delwri/DONE) dir block: `xfs_buf_stale(dbp)` + force-clear DONE|_XBF_FUA_FRESH
(xfs_buf_stale doesn't clear DONE) + b_mxfs_dir_gen=0. MUST NOT stale in-AIL (discards
committed update). RESULT (build BA0A5E6D): P-DIRWR trace MONOTONIC, **ZERO reverts** —
the block-format dir durable lost-update (the primary sess98 root) is FIXED;
unlink_visibility PASSES in ISOLATION (0 survivors). FIX 2 (AG-meta bnobt/cntbt
release-side stale) is INERT (fires 0× — xfsaild flushes the stale bnobt buf ASYNC
before the release drain; the revert is outside the release window). REGRESSION
(REVERTED, RULE-4 2a): acquire-side xfs_buf_stale made unlink WORSE (aggressive
acquire-side COLD re-read under fua_disable=1 returns stale/racing SCST content) ⇒ GPT
"release+acquire PAIR" is WRONG here: release-side stale correct, acquire-side cold-read
harmful. DO NOT retry acquire-side cold-read/stale for dirs. Remaining: bnobt
P93-REVERT-CLOBBER intermittent run-killer (`ltbno+ltlen>bno` shutdown); can't
write-suppress without a load-epoch (buf_gen/pag_gen frozen at 1).

### sess100 ([[sess100_lessons]]) — cross-visibility root = WRITE-SIDE publish-before-notify (bug generalized)
Baseline known-good **D6AD04FE**: cross PASS, rename PASS, cwr PASS, unlink FAIL 1
survivor = 3/4. ROOT CAUSE (PROVEN + GPT-confirmed): `mxfs_dlm_note_dir_modified(dir_ino)`
is called INSIDE the txn at commit (xfs_dir2.c 411/633/696) and ONLY stages an
evict-ring entry bumping PEERS' `i_dlm_dir_gen` — it does NOT write the modified dir
block to the shared LUN. The block destages only via (a) xfsaild lazy writeback or (b)
the BAST-release fence. In unlink, ALL 4 nodes cache the same dir continuously → NO
node is ever BAST'd → deletes sit in each node's CIL/AIL/WB cache, never promptly on
the LUN. Peer gets "dir changed" gen-bump but the changed block was never published →
cold-read re-reads the OLD block. **The gen bump is a publication event but the data
was never published.** The durable variant `mxfs_dlm_dir_durable_signal(dp)` EXISTS
(~L4766, written sess82) but is NEVER WIRED IN (0 callers). ACQUIRE-SIDE REFRESH = DEAD
END (4 variants reverted): B1 5D795627 (EX-only evict, no barrier) unlink PASS but
rename REGRESSED 0→40; B2 1B206382 (+blkdev_issue_flush) rename self-loss 40→14; B3
02B33DC9 (broaden to PR readers) rename PASS but unlink 3 survivors; B4 84EA79C2 (advance
loaded_gen only if drain left==0) unlink 24s→500s flush storm. Advancing loaded_gen ⇒
serve stale forever; not advancing ⇒ flush storm; acquire side CANNOT fix it because
nothing newer is on the medium. THE FIX (GPT, next): move note_dir_modified OUT of the
txn to POST-COMMIT (dir ILOCK still held): log_force(SYNC) → bwrite modified dir
DATA/leaf/freeindex blocks → blkdev_issue_flush → THEN note_dir_modified (bump peers'
gen) → set loaded_gen=dir_gen. Rename = ONE visibility unit (bwrite all affected parents
+ child ".." blocks, ONE flush, THEN bump gen for all — never half-publish). This is ~
wiring in `mxfs_dlm_dir_durable_signal` at the post-commit sites. Cost: synchronous per
op was ~10x slow historically (sess43); optimize later with a per-dir publish queue that
COALESCES commits → one log_force → one batch bwrite → one flush → one gen bump
(preserve the invariant: gen bump AFTER blocks on LUN). Source at sess100 end reverted to
≈baseline (acquire experiment disabled with `false &&` at ~L3203); build **DB19A553**
(NOT deployed); last DEPLOYED = regressed **84EA79C2**.

## Cross-session lessons / recurring failure modes (deduplicated)
- **NEVER clear XBF_DONE / re-read / xfs_buf_stale a dirty/pinned/in-AIL buffer** —
  races writeback → xfs_inode_buf_verify corruption + SHUTDOWN (sess39/64/88). Only
  stale/reread a buffer proven clean, !in_ail, !pinned.
- **NEVER whole-AG `xfs_ail_push_ag_sync`** in a handoff/release path — wedges under
  peer AG contention (holds ILOCK), and is catastrophically slow (26→148s). Use
  targeted `mxfs_dir_flush_data_blocks` (O(dir size)). ([[sess82_lessons]],
  [[sess83_lessons]], [[sess98_lessons]])
- **Heavy drain MUST be off the BAST/CAW-poll thread** (deadlock vs log force /
  writeback / DLM rx). ([[sess96_gpt_fix_design]])
- **fua_disable=1 is correct**; FUA reads the stale platter (SCST write-back cache),
  45x slower AND worse. Never re-enable. ([[sess96_lessons]])
- **Acquire-side cold-read/refresh for dirs is a DEAD END** under fua_disable=1 — every
  variant regressed (there is nothing fresher on the medium to read until the writer
  publishes). The fix is WRITER-side publish-before-notify. ([[sess99_lessons]],
  [[sess100_lessons]])
- **xfs_log_force(SYNC) does NOT synchronously wait for unpin** — the async
  xlog_cil_committed WQ drops pin_count + AIL-inserts later; a bounded/msleep drain
  gives up before it runs. Use deterministic `xfs_buf_wait_unpin` (static in
  pal/linux/xfs_buf.c:1020 → de-static). ([[sess96_lessons]])
- **CIL window** (`!in_ail && !pin ⇏ durable`): a just-committed change is briefly
  neither pinned nor in-AIL yet the on-disk image is stale — several gates wrongly
  treated this as durable. ([[sess84_lessons]], [[sess98_lessons]])
- **concurrent-EX REFUTED repeatedly** (ex_pop=1, CAW-EXCL-VIOLATION=0, INODE
  CAW-DUP-SLOT=0): the DLM serializes EX holders correctly; the bug is purely
  write-durability ordering across EX handoffs, not lock contention.
- **Detectors must be always-on (instr=0-safe)**; instr=1 is ~100x slower and can't
  reach the create storm. Trust only always-on pr_warn markers + report_stats.
- **Separate open blocker: bnobt AG-meta in-core corruption** (`ltbno+ltlen>bno`
  double-free, P93-REVERT-CLOBBER) — same class (async xfsaild flushes stale bnobt buf
  outside the release window); `pag_dlm_meta_gen` frozen at 1; needs shared on-disk AGF
  epoch. GPT's fence applies to AGF/AGI/AGFL/bnobt bufs too.

## Infra invariants (repeatedly cost time)
- Trustworthy run needs a REAL reboot: `LIBVIRT_DEFAULT_URI=qemu:///system virsh
  destroy+start test1-4` (~65s), THEN `bash tests/reset4.sh 4` (fua_disable=1 default).
  reset4 alone (teardown+remount, no reboot) leaves contaminated state → 141s/37-survivor
  JUNK. ([[sess100_lessons]])
- Remount `/mnt/mxfs-src` (192.168.120.1:/src/mxfs, holds tests/mxfs_test.sh) on ALL
  nodes after every reset — it drops off test1 → node1 rc=127 → FALSE-POSITIVE loss.
  ([[sess85_lessons]])
- After `make clean` ALWAYS `make tools` too (wipes mkfs_mxfs/chk_mxfs → mount fails
  with stale-FS corruption). Fast deploy = `insmod /src/mxfs/mxfs.ko` (all node kernels
  == dev 6.8.0-101-generic; no per-node rebuild).
- Single subtest: `MXFS_TESTS_DIR=/src/mxfs/tests MXFS_NODE_OFFSET=16
  tests/run_tests.sh --nodes 4 --phase cluster --test test_<name> --pass-file
  /tmp/.mxfs_pass --device /dev/sda --mount-point /mnt/shared`. Full criterion:
  `bash tests/criteria/cache_coherency.sh --nodes 4`. EXIT=137 = SIGKILL (blew budget);
  `pkill -9 -f run_tests` + reset4. Recover a wedged node via virsh destroy+start; first
  mount post-shutdown often hits a transient SCSI reservation conflict (-117) → retry 2-4x.
