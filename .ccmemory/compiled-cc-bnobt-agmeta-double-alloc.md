---
name: compiled-cc-bnobt-agmeta-double-alloc
description: Compiled sess21-111: bnobt/AG-meta double-free + free-space double-alloc family; ended as RED HERRING (real root = stale inode/BMAP).
metadata:
  type: project
tags: [compiled, bnobt, agmeta, double-alloc, cache-coherency, xfs_alloc, dlm]
---

# Compiled: bnobt / AG-meta double-free & free-space double-allocation corruption family

Central symptom chased from sess20 through sess111: the `Internal error "ltbno + ltlen > bno"`
shutdown at `xfs/libxfs/xfs_alloc.c:2244` (formerly :2231) in `xfs_free_ag_extent`, reached via
`xfs_inactive_truncate`/`xfs_bunmapi`/`xfs_defer_finish` during `rm`/unlink inactivation. A block is
freed that the bnobt (free-space by-block btree) already lists free → double-free → EFSCORRUPTED →
FS shutdown → cascade FAIL of the `cache_coherency` ship criterion. Sibling symptoms in the same
family: AG free-space **double-allocation** (two inodes/objects handed the same block; two files
share a disk block; a dir data block physically overlaps a file data block), plus stale-behind AGI
unlinked-list and inode-cluster corruption. **The multi-session verdict (sess93/sess111): the bnobt
itself was a RED HERRING — it was doing legitimate forward B-tree math; the true root is a stale
in-core INODE / BMAP extent map that issues a duplicate free.**

## Timeline of root-cause framings (each superseded the last)

### sess21 — disk-level race, not in-core cache staleness (mxfs.1-era, v0.3.5x)
P22-INSTR census proved **bnobt/cntbt are usually NOT in `pag_bcache` at fresh-acquire** (later
corrected: sometimes cached, LRU-dependent). Concluded corruption is disk-level, not in-memory cache
staleness. Ruled out (do not re-chase): `invalidate_ag_meta` skip-rules; Phase-3 defer-to-iodone
firing unlock before durable (v0.3.55 REL-INLINE-V55 inline-wait+flush made no difference — corruption
identical `bno=131080 ltbno=131080 ltlen=131054`). **Real find (v0.3.56 P23-INSTR + cross-node dmesg
correlation): CAW disklock READ cache-coherency bug — both nodes briefly held EX on same slot 10369
because `mxfs_pal_bdev_read_prio` (read_slot) used plain bio without FUA while CAW WRITE used SCSI
COMPARE-AND-WRITE 0x89 w/ FUA.** Fixes: v0.3.57 REQ_FUA on bio → EIO (block layer won't translate FUA
read to SCSI on this iSCSI/LIO stack); v0.3.58 direct SCSI READ(16) CDB 0x88 FUA via `scsi_execute_cmd`
→ pagf_freeblks stopped diverging (pag-cache-staleness closed) but bnobt corruption persisted with a
new RIGHT-FAIL signature. Open Q left for sess22: does LIO honor FUA at all (`emulate_fua_write`,
qemu `cache=none`)? Lessons: REQ_FUA is asymmetric (write via bio OK, read needs SCSI passthrough);
same external symptom (`ltbno+ltlen>bno`) has multiple distinct root causes. See
[[Sess21 MXFS — bnobt is not in pag_bcache at fresh-acquire (KEY FINDING)]].

### sess41-42 — false-fresh gen-stamp → free-space double-alloc FIXED (v5 fork)
[[sess41_lessons]]: btree-block AG read-coherence hook added in `xfs_btree_read_buf_block()`
(~L1419) — `if (cur->bc_ops->type == XFS_BTREE_TYPE_AG) mxfs_ag_meta_invalidate_stale(mp,
to_perag(cur->bc_group), d, xfs_btree_bbsize(cur))`. Correct perag accessor for this kernel =
`to_perag(cur->bc_group)` (NOT `cur->bc_ag.pag`). Build `379A9A25`, built clean but NOT deployed →
UNVALIDATED. Reset4 failed; tool channel injected phantom output (recurring; a false "5 clean runs"
claim was RETRACTED — verify tool output self-consistency).

[[sess42_lessons]]: **FIXED** the false-fresh gen-stamp bug (build `C6970FF9`). Winning RULE-4 method:
fire-only-on-corruption `pr_warn` at the `XFS_IS_CORRUPT` site dumping daddr + `b_mxfs_ag_gen` vs
`pag_dlm_meta_gen` + a live FUA disk-vs-incore memcmp (helper `mxfs_ag_buf_disk_differs()`; LBA =
`bm_bn + bt_sector_offset`) — near-zero overhead, doesn't hide races (unlike `mxfs.instr=1` = 100×
slow). ROOT: `mxfs_ag_meta_invalidate_stale()` stamped `b_mxfs_ag_gen = pag_dlm_meta_gen`
**unconditionally even when it SKIPPED invalidation** (buffer pinned/BLI-dirty/delwri) → a stale
un-refreshable buffer got marked current-gen → never re-read → stale free-space frozen authoritative
→ double-alloc. FIX: only advance gen when genuinely fresh (already gen>=current, or actually cleared
XBF_DONE on a clean/unpinned/!delwri buffer). P70 → 0/8. Also FIXED #2: EX-acquire walk left a
b_hold==0 stale AGI reusable → clear XBF_DONE|_XBF_FUA_FRESH for no-hold AG-meta bufs. Env note:
dev host **IS clyde** (libvirt host); `tests/reset4.sh` arg is a **NODE COUNT**. Pivotal sess42
observation: a SECOND free-space corruption is WRITE-SIDE (both trees match disk yet disagree =
on-disk bnobt/cntbt genuinely inconsistent, non-atomic writeback of the two btree blocks). Unifying
root stated: lazy gen invalidation CANNOT refresh a pinned/locked/dirty buffer (XBF_TRYLOCK-skips).

### sess43 — in-AIL lost-update FIXED; deep dive into release-durability & nlink
[[sess43_lessons]] (the largest source). **PROVEN FIX build `BB54A138`:**
`mxfs_ag_meta_invalidate_stale` discarded any gen-lagging buffer that was
`DONE && !XFS_LI_DIRTY && !pinned && !delwri` — but a buffer committed to the log and sitting in the
AIL awaiting metadata writeback has `XFS_LI_DIRTY` CLEARED and `pin==0` yet its content is AHEAD of
disk (P70: `bno_dirty=0 bno_pin=0` yet `bno_disk_differs=1`). Discarding it re-read the STALE disk
image → lost the committed update → cnt/bno diverge by exactly one block → `i != 1 at
xfs_alloc_fixup_trees` shutdown. FIX: add `XFS_LI_IN_AIL` to the safe-to-discard guard (in-AIL
AG-meta is always this-node-ahead because AG-DLM EX serializes peers). `XFS_LI_IN_AIL` is the ONLY
reliable "in-core may be ahead of disk" signal (DIRTY is txn-private, cleared on commit). Proven via
P76=0 while P70=16 (fixup leaves trees consistent; divergence appears post-commit) + P77 protect-log
fired 21-56×/node after fix. AG free-space double-alloc ELIMINATED. Milestone build `2488245C` /
`E0903CE8` added gen-stamp-on-fresh-read + a second `drain_meta_buffers` (Phase-2b, inode alloc dirties
AGI/AGF/inobt after first drain) → P70=0 all nodes, AGI read-coherency fixed, dlmto=0.

sess43 established the "clean-but-ahead" durability trap that dominated the next 50 sessions: a
committed buffer that LOOKS clean (`DONE && !DIRTY && !pinned && !IN_AIL`) can still be in-core-ahead
because its writeback bio was submitted (bli detached, buffer clean) but NOT completed — release drops
the DLM, a peer FUA-reads the shared LUN and gets the pre-write image → lost update. Confirmed by
P81-INSTR build `EB0CD2A2`: at unlock after double `blkdev_issue_flush`, agf+cntbt still
`disk_differs=1 pin=0 DONE`. **DEEPEST sess43 root: the gen protocol can't distinguish
"this-node-ahead" from "peer-stale"** — a freshly-MODIFIED buffer has `b_mxfs_ag_gen=0`, identical to a
peer's stale cached buffer; the read-hook discards this node's own authoritative buffer → self-revert.
Proposed real fix: **gen-stamp-on-MODIFY** (stamp `b_mxfs_ag_gen=pag_dlm_meta_gen` whenever this node
modifies AG-meta while holding AG EX) — the missing half of sess42's fix.

**DECISIVE sess43 negative results (do not repeat):** all FUA-refresh dir-coherency approaches hit a
TIMING WALL (read-side gen-0 re-read broke `cross_write_read` with EACCES — a node FUA-re-reads the
platter and misses its OWN target-cached-but-not-platter-durable dirent; bast-release gen-bump = wrong
layer; write-acquire gen-bump TIMED OUT rename_visibility >180s; sync_iflush too slow). Cross-node dir
coherency via FUA re-reads is fundamentally too slow at scale — needs a NON-FUA mechanism (dir seqno /
proactive invalidation broadcast). sess43 ALSO reframed the AGI/iunlink shutdown as a **cross-node
nlink coherency bug**: P71 build `E0903CE8` showed `nlink=0 (in-core) disk_dnlink=1` — the inode is
STILL LINKED on disk; this node's stale in-core VFS nlink=0 wrongly inactivates a still-linked inode.
NOT double-free (di_mode=0100644 ≠ 0). The `rm -rf` iunlink shutdown was later ruled a **repro
artifact** (repro's cross-node `rm -rf` vs the real same-node `test_unlink_visibility`) — sess43 end:
cache_coherency = **3/4 PASS, only rename_visibility failing**.

### sess44 — sess43 handoff was over-optimistic; corruption is DURABLY ON DISK
[[sess44_lessons]]: `A0A86F31` was clean only at idle; under real 4-node `cache_coherency` it produced
5 shutdown classes (SB-verify `fdblocks>dblocks`, bnobt overlap [dominant], DLM-lock-unrecoverable,
`xfs_dir2_sf_lookup` NULL-deref, mxfs_buf leak). LANDED SB summary-counter clamp (build `8E87D691`):
in `xfs_log_sb()` multi-node, clamp `sb_fdblocks<=sb_dblocks`, icount into range, ifree<=icount
(benign per-node percpu lazy counters; per-AG AGF authoritative). Removing SB-verify shutdown revealed
the real disease = bnobt overlap. **Root confirmed via P85/P88 (builds `2B938526`/`23F83A35`):
corruption is DURABLY ON DISK** — `disk_differs=0` at the free means the bad bnobt is authoritatively
on the platter; a node committed a bnobt RMW on a STALE base and wrote it to disk. P88b then FLIPPED
the framing (`disk_differs=1`): V1 (allocated) IS durable; the node clobbers it with a stale-pristine
V0 (mkfs whole-AG-free record `[9,260906]`). So NOT a write-durability gap → READ-STALENESS: the node
modified a stale V0 base read at acquire and wrote it over durable V1. CONCLUSIVE rule-outs (all
instrumented 0×): CAW DLM split (P87 post-CAS re-read `holders_ex==our bit`, EXCL-VIOLATION=0);
read-hook skipping a stale buffer (P86); in-AIL preserve path (P77); missing-FUA-coverage (bnobt IS in
`mxfs_buf_is_ag_metadata`). Leading suspect handed forward: the sess43 gen-stamp-on-fresh-read LOCKS IN
a stale V0 if a node FUA-reads at the instant disk is still V0 (read races peer's release-destage).

### sess46 — clobber localized to acquirer stale-pristine buffer + frozen meta_gen
[[sess46_lessons]] (build `9AF61DF2`, later `0FA2CB16`): the ACQUIRER (freeing node) writes a PRISTINE
whole-AG-free bnobt over the peer's V1. `mxfs_ag_meta_invalidate_stale` NO-OPs because
`buf_gen>=pag_dlm_meta_gen` (both stuck at 1). P102 proved `pag_dlm_meta_gen` goes 0→1 once per AG then
FREEZES — only fresh CAW acquire (~L2873) + post-acquire-lock cached path (~L2737) bump it; the early
cached fast-path (~L2658) and NESTED path (~L2648) do NOT, and cross-node free re-enters nested/cached.
RULED OUT (data, don't re-chase): peer write durability (aggressive owner flush → clobber persists 8×,
disk_differs=1 = V1 durable); medium-vs-cache (`dd iflag=direct` byte-identical across initiators);
FUA-reads-stale-medium (`fua_disable=1` cluster-wide → clobber persists, acquirer serves in-core
pristine with NO device read). LATE WINS: `single_node_paired` PASS 104% (138% was multi-node residue).
**Re-enabled sess43's dir-gen-0 bump** in `xfs_da_btree.c` (~L2872 `dp->i_dlm_dir_gen=1` on first
multi-node DATA-fork dir read) → rename_visibility HANG → FAST 1-2/240. Residual di_size=0
empty-content root = inode-number REUSE: peer holds a cached PR grant on reused inode N, never
invalidated on free/reuse (no BAST), cached-PR fast path serves stale di_size=0. FIVE VFS-layer
reload-triggers ALL FAILED+REVERTED (getattr EXCL+reload `40B34C7C`; iomap hole EXCL+reload `53813959`
HUNG on CAW; open-path `F3CA2903`; per-read ILOCK_SHARED `5471F480` perf wall; di0-gated `07B97DAF`).
**LESSON: never take ILOCK_EXCL or call `mxfs_dlm_reload_inode` in the hot read/getattr path.** Trigger
must be EVENT-DRIVEN at the DLM layer (readdir/lookup instantiate GRANT-LESS, so a peer's EX BAST has
no grant-holder to notify → needs a dlm_caw inode-invalidate broadcast or grant-less-cache tracking).

### sess47 — the "AG bnobt double-free" declared FIXED (stale-inode inactivation)
[[sess47_lessons]] (build `29977E5D`): the 7-session `ltbno+ltlen>bno` corruption FIXED. NOT any
DLM-side theory (find_slot claim-race / dup-slot / concurrent-EX all REFUTED via `CAW-DUP-SLOT`=0×,
`ag_held`=1 at every bnobt write, in-AIL skip guards 0×). ROOT via P47-INACT: a node runs DESTRUCTIVE
INACTIVATION on a STALE cached inode and double-frees its blocks. Two sub-cases: **B1** (`di_mode==0`):
peer unlinked+freed the inode; this node instantiated it GRANT-LESS (readdir/lookup/stat) so the free
never BAST'd it, stale in-core extent map kept. **B2** (gen-mismatch): inode number REUSED, disk has a
different incarnation. FIX in `xfs/xfs_inode.c` top of `xfs_inactive`: multi-node + nlink==0 →
FUA-read on-disk dinode; if `di_mode==0` OR `di_gen != i_generation`, SKIP the destructive
truncate/ifree, reclaim in-core only (logs `INACT-SKIP-STALE`). Helper `mxfs_dbg_disk_di_mode`
(dinode offsets di_size=0x38, di_gen=0x5C, di_next_unlinked=0x60). **B2 must be UNGATED** (gating on
grant-less i_dlm_mode==NL → corruption returned; the corrupting reused inode is grant-held). OPEN RISK:
ungated B2 could false-positive on a node's own reused-not-yet-flushed inode (gen is random). This is
the same guard that survives (evolved) into sess93/103/111. Remaining after fix: ENOTDIR dir-visibility
(reused barrier-dir name → stale cached dentry wrong type; d_revalidate DISABLED since sess38).

### sess52 — double-alloc PROVEN; concurrent-EX REFUTED; single-holder read-side staleness
[[sess52_lessons]] (build `BDC9BB93`, `mxfs_dlm_caw_ex_count` detector KEEP). Direct on-disk proof of
double-allocation: `xfs_dir3_data_reada_verify` "corrupt dir block" hex dumps physically contained
regular-FILE data ("hello from node 1\n") = one physical block allocated as BOTH a dir data block AND a
file data block; `INODE-REUSE-EVICT incore_ftype=2 dirent_ftype=1` = inode double-alloc. **CONCURRENT-EX
DEFINITIVELY REFUTED**: every P88 fire on all nodes/AGs = `ex_pop=1 ex_nslots=1` → never 2 nodes EX one
AG, never a dup slot. Mechanism = SINGLE-HOLDER read-side AG-meta staleness: the sole AG-EX holder
writes a stale low-numrecs bnobt whose gen FALSELY == pag_gen → `mxfs_ag_meta_invalidate_stale` skips
re-read → lost update → double-alloc. Open Q: why is the sole holder's bnobt buffer gen-fresh but
content-stale (dirty/in-AIL/pinned/delwri un-refreshable, or gen-stamped fresh without re-read).

### sess68 — bnobt-FUA hypothesis REFUTED; `fua_disable=1` is deliberate
[[sess68-baseline-evidence-bnobt-fua-gap]]: earlier bnobt-FUA hypothesis in that same file is REFUTED.
`fua_disable=1` is the DELIBERATE module default (sess94) — FUA-fresh reads caused 45× slowness + a
class of read corruption. The constant `P88-INSTR bnobt-WRITE-low-numrecs disk_differs=1` is KNOWN
instrumentation NOISE under fua_disable=1, NOT the blocker. Accurate state: symmetric v5 at
cache_coherency **3/4** (lineage `66A40A3D`→`99635EAD`→`EC07F422`); only `unlink_visibility` fails =
WRITE-SIDE dir-block handoff race (a non-releasing node's dirty/in-AIL/delwri/in-flight dir buffer
reaches the shared store after the peer's deletion). Variance warning: trust ONLY `cache_coherency.sh`,
not back-to-back subtests (phantom cwr/cross_vis fails).

### sess81 — full trace: durable on-disk corruption written by a fully-drained release
[[sess81_lessons]] (build `D8F43418`, P81-DEXT probe). Isolated `unlink_visibility` DETERMINISTICALLY
shuts a node down. P15 `agno=3 bno=13 ltbno=10 ltlen=6`; P47 verdict `DISK-LIVE-same-gen=>A-lost-removal`
(inode live on disk, gen matches — NOT sess47's reuse case); **P28 disk_differs=0 = the on-disk bnobt
ALSO lists 13 free = DURABLE corruption on the platter.** AG3 touched by only test1(slot0)+test3(slot3);
`CAW-DUP-SLOT=0` (concurrent-EX refuted again). Timeline: test3 ACQ-FRESH → test3 REL-INLINE-V55 (clean
BAST drain, P75=0) → ~33s later test1 ACQ-FRESH → 4ms later crash → **test3 durably wrote a bnobt where
block 13 is free while a live inode owns it, even though test3's release was FULLY DRAINED.** New helper
`mxfs_dbg_disk_di_first_dext` FUA-decodes the on-disk dinode's data-fork first extent; P81-DEXT verdict
`DISK-INODE-OWNS-FREED=>bnobt-lost-update` vs `DISK-INODE-DIFFERS=>incore-extent-stale` — THE decisive
datum (free-space-tree coherency vs inode-extent coherency). Manifestation STOCHASTIC (alloc:2244 vs
`xfs_trans_cancel:1060`) so P81 hadn't fired yet.

### sess89 — Gemini root: post-release xfsaild CIL→AIL clobber (Probe-A built, unproven)
[[sess89_lessons]] (build `A18B3029`; Probe-A `0BC933EE`). P47 `DISK-LIVE-same-gen=>A-lost-removal` on
`bno=10 len=1 agno=1`, ltbno=10 ltlen=6 → block 10 DOUBLE-ALLOCATED (also owned by 2097282); the bnobt
"remove block 10" update was LOST. `agf_freeblks==pagf_freeblks` → pagf-staleness REFUTED. test1
acquired agno=1 FRESH exactly once, held continuously, `pag_gen=1` = SINGLE-EPOCH (**kills the
sess46/52/80 "frozen pag_dlm_meta_gen" framing** — expected, not a bug). test1 INHERITED already-corrupt
on-disk state at fresh acquire; prior holder test4 released via bast_work_fn (FULL-drain). Deferred-iodone
release path (`mxfs_dlm_ag_meta_iodone`/`ag_release_work_fn`) is DEAD CODE (`pag_dlm_release_pending`
never set true). Gemini RULE-5 diagnosis: **post-release xfsaild clobber via CIL→AIL pipeline race** —
`xfs_log_force(SYNC)` in bast_work_fn can RETURN BEFORE the item lands in the AIL (CIL→AIL insertion runs
on `xc_commit_wq`); drain sees buffer not-in-AIL → skips; after unlock, Node B's background CIL push
inserts into its AIL, xfsaild writes Node B's stale in-core bnobt to home → erases peer's allocation.
Probe-A: `pr_warn` in `xfs_buf_submit` if AG-meta WRITE with `!(cached||holders>0||demoting||
release_pending)` → `comm=="xfsaild/*"` = confirmation. Proposed FIX: `flush_workqueue(...xc_commit_wq)`
after log_force(SYNC) to guarantee CIL→AIL insertion before drain. NOT YET DEPLOYED/PROVEN.

### sess92 — PROVEN: in-core revert before drain; GPT mechanism-F / aliasing
[[sess92_lessons]] (baseline `ECDE1FC5`). PROVED the bnobt double-free is a cross-node alloc/free +
**IN-CORE revert of the bnobt buffer from split→pristine BEFORE the release drain** — NOT a
drain-enumeration gap, NOT a storage-persistence failure. Refutations (RULE 4): (1) FIX1 FUA-skip guard
`P91-FUA-SKIP-LOGGED` fires only on `ops=xfs_inode`, 0× on bnobt/cntbt. (2) P-AILVERIFY walked the AIL
right before unlock → n=0, `xfs_ail_push_ag_sync_bounded` DOES empty AG-meta from the AIL (REFUTES
sess89's drain-enumeration-gap / Gemini's 1st hypothesis). (3) P80-DESTAGE-RETRY 0× → every synchronous
`xfs_bwrite` persists immediately (REFUTES sess44/79 "SCST ACKs-but-doesn't-persist"). CONCLUSION: a
NON-TRANSACTIONAL path reverts the split→pristine before the drain writes the already-reverted block.
GPT consult #2 (gpt-5.5) TOP LEAD = **mechanism F: read-completion TOCTOU** — FIX1 checks logged/pinned
at FUA-read submit; if buffer is clean at submit but a txn logs the split while the read is in-flight,
completion DMAs the stale disk image over `bp->b_addr` (submit-time guard can't fire → why P91 never
fires on bnobt). 2nd lead = buffer ALIASING (two live xfs_buf for one bnobt daddr; pristine alias wins
the home write). GPT's robust FIX: bounce-buffer reread (read into private kmalloc, re-validate under
bp lock via a new `b_mxfs_content_seq`, memcpy only if unchanged else discard). Corruption is
VARIABLE/multi-root (bnobt, SB `xfs_sb_write_verify`, dir3 `xfs_dir3_data_reada_verify block 0x178`,
inode-cluster) = broad cross-node cache incoherency.

### sess93 — THE BIG REFRAME: bnobt is a RED HERRING (Gemini consult #2)
[[sess93_lessons]] (build `C4E65691`). Decoded the full P88 chronological trace for one leaf (AG9
daddr=18785888, test3 SOLE owner t=84-237, no peer): the allocator legitimately carves blocks 9-15 from
free rec `[9,7]`→...→`[13,3]`, deletes the record, then frees re-insert `[9,1]` and MERGE to `[9,7]`
(LSN legitimately climbs 459→670). **NOT a revert — legitimate forward B-tree math.** The P93-REVERT
probe (disk_nr>in_core_nr) was catching benign async-writeback lag + legit merge-frees. **STOP
instrumenting bnobt/AGF/cntbt for "stale clobber" — the P88/P93/P90/P70 family across sess42-92
mis-read legit btree math as corruption.** REAL ROOT: an inode's in-core BMAP is STALE and frees blocks
it already freed (bnobt correctly shows them free; second free overlaps → EFSCORRUPTED). Gemini Q2: a
stale cntbt/AGF would fail `xfs_alloc_fixup_trees` (i==0) and panic differently, so NOT AG-meta; a stale
INODE/BMAP absolutely causes the `ltbno+ltlen>bno` overlap. Corroborated by many existing
`INACT-SKIP-STALE ... reason=gen-mismatch|disk-free` in dmesg. This session's change (build `C4E65691`,
KEEP defensively): bump `pag_dlm_meta_gen` in both release_pending reclaim paths — VERIFIED it fires but
does NOT fix the criterion (dominant failure is inode/BMAP). Next-plan pivot: trap the double-free in
`xfs_free_ag_extent` (dump_stack) + `xfs_bmap_del_extent`/`__xfs_free_extent` (log ip->i_ino) to catch
the inode shedding the same extent twice.

### sess110 — clean-reboot run reconfirms bnobt shutdown; new clean-cached-skip gap
[[sess110_lessons]] + [[sess110_run2_result]] (builds `89C04201`, `87726318`). On a CLEAN cluster
(virsh destroy+start all 4) the cache_coherency shutdown is the bnobt double-free (NOT the sess109
sf_lookup NULL, which was a contaminated-cluster artifact, P110-SFNULL=0). Run: `passed=0 failed=4`;
cross_visibility FAIL "node3 reads node4's content" = two files share a disk block = data-block
DOUBLE-ALLOC (same root). Builds KEEP: P110-SFNULL guard (`xfs_dir2_sf_lookup` returns -EIO instead of
NULL-deref, defensive, never fired clean); P110-BIO-OVER-LOGGED guard on the plain-bio read path
(mirror of P91 FUA backstop). **RUN-2 (`87726318`, clean reboot) DISPROVED the bio-path: P110-BIO=0 on
ALL 4 nodes** → the bnobt in-core revert does NOT go through the plain-bio read path. With FUA path
(sync+locked, P91-guarded) AND plain-bio path both ruled out, remaining mechanisms: (a) ALIASING
(`xfs_buf_stale` on an in-AIL split clears `_XBF_DELWRI_Q`, cancels writeback), (b) **the CLEAN-CACHED-SKIP
gap** in `mxfs_dlm_ag_drain_meta_buffers` (`xfs_mxfs_dlm.c:6476-6480`): sess99's P99-AGMETA-STALE
`xfs_buf_stale` only stales DRAINED (in-AIL/pinned) bnobt bufs; a bnobt buf CLEAN at drain time is
SKIPPED → never staled → survives as a stale alias into the next tenure → fast-path re-grant RMWs it →
clobber. `mxfs_ag_meta_invalidate_stale` (~L4800) only invalidates gen-LAGGING bufs (the P70/P95
"buf_gen==pag_gen yet stale" hole). Proposed (GPT/sess98/NEWARCH cold-read): stale ALL cached
bnobt/cntbt at EX RELEASE PAIRED with cold-read (stale-incore) at every EX ACQUIRE — one side alone
fails. NEWARCH context: Phase 1 (kill P106 stale-EX) essentially done (chokepoint sess108, P106-STALE-EX=0);
cache_coherency still red because Phase 2 TCP invalidation mesh not built + this bnobt landmine.

### sess111 — course correction: STOP chasing bnobt/AG-meta cold-read
[[sess111_reframe_bnobt_red_herring]] (build `87726318`). Overrides sess110's framing: sess110 and
early-sess111 were chasing the bnobt/AG-meta cold-read (clean-cached-skip, P110-BIO, GPT tenure-local
pairing) — but **sess93's Gemini #2 already DEBUNKED this. DO NOT re-instrument bnobt/AGF/cntbt for
"stale clobber."** Why `disk_differs` is UNRELIABLE (confirmed by code read): cluster runs
`fua_disable=1` (`mxfs_fua_disable=1` default, `xfs_mxfs_dlm.c:6823`) → the coherent peer-visible store
is the SCST write-back CACHE; a plain read hits it (coherent), an FUA read hits the STALE PLATTER. But
`mxfs_ag_buf_disk_differs`/`mxfs_ag_buf_disk_bnobt` (L4960/4998) read via `mxfs_pal_scsi_read_fua_bdev`
= FUA = platter → platter-lag reads as false `disk_differs=1`. (Coherent compare would use
`mxfs_pal_bdev_read_plain_bdev`, added sess103 — but the bnobt isn't the bug, so don't bother.) REAL
root reaffirmed: a stale in-core INODE/BMAP issues a DUPLICATE free; the bnobt is CORRECT. ONE unifying
root for the shutdown AND the visibility failures = cross-node inode-cache staleness. Decisive
instruments already live at instr=0 at `xfs_alloc.c:2244-2308`: **P15-INSTR** (the shutdown),
**P47-INACT** verdict (`DISK-FREE=>B-stale/double-free` | `GEN-MISMATCH=>B-stale-inode` |
`DISK-LIVE-same-gen=>A-lost-removal`), **P81-DEXT** `disk_claims_freed` (1 = on-disk inode extent claims
freed block = tree wrong on disk; **0 = in-core BMAP STALE vs disk = inode-coherency bug**),
`INACT-SKIP-STALE` count (the sess47/78 DLM-locked double-free guard firing). The sess47 guard evolved
(xfs_inode.c:2208-2289: nlink==0 multi-node takes per-inode DLM EX, FUA-reads di_mode/di_gen, skips B1
disk-free / B2 reused); sess103 refuted that its FUA inode read is stale-platter (P103-FUA-DIVERGE=0×,
inodes destage fast). Residual double-free likely `DISK-LIVE-same-gen=A-lost-removal` (a
legitimately-owned inode whose in-core BMAP is stale) OR a non-inactivation free path
(truncate/bmap_del). Confirm via P47/P81.

## mxfs.1-era related finding (different architecture)
[[Session 55 — Bug 131 fix failed, found 19 unchecked writes]] — the OLD mxfs.1 (non-XFS-fork)
block-cache architecture. Bug 131 fix (release cached AG on membership change) was NOT root — corruption
recurred after 17 min with ZERO membership changes (`dlm_membership_cb` never fired). Root there: **19
calls to `mxfs_block_cache_write` in `alloc.c` don't check return values** (lines incl.
1645/1759/1849/1935/2039/2169/3493); if any fails (iSCSI timeout, cache pressure) the btree modification
is silently lost → blocks appear free in bnobt/cntbt while an inode holds an extent pointing to them →
next allocation hands out the same blocks → file data overwrites inode chunk headers. Underlying cause:
XFS wraps btree-mod + inode-extent-update in ONE atomic journal txn; mxfs.1 had no such atomicity
(separate non-atomic ops). Directionally consistent with the v5 verdict (inode extent vs free-space
tree disagreement) though a distinct codebase.

## Consolidated do-NOT-repeat / established refutations
- **Concurrent-EX / dup-slot / CAW claim-race** — REFUTED repeatedly: `CAW-DUP-SLOT`=0 (sess47/81),
  `ex_pop=1 ex_nslots=1` everywhere (sess52), P87 post-CAS re-read 0× (sess44). CAW EX serialization is
  SOUND.
- **Write non-durability / SCST ACK-without-persist** — REFUTED: P80-DESTAGE-RETRY 0× (sess92),
  disk_differs=1 = V1 durable (sess44/46), aggressive owner flush → clobber persists (sess46).
- **Drain-enumeration gap at release** — REFUTED: P-AILVERIFY n=0, `xfs_ail_push_ag_sync_bounded` empties
  AG-meta (sess92); P75=0 release leaves 0 pinned/in-AIL AG-meta (sess42/81) — but note that's AIL state,
  NOT in-flight-bio completion.
- **In-AIL preserve path (P77)** and **read-hook skipping a stale buffer (P86)** — 0× at the corruption
  (sess44).
- **frozen `pag_dlm_meta_gen`** framing — killed by sess89 (single-epoch pag_gen=1 is EXPECTED when an
  AG is held continuously).
- **FUA-refresh for coherency** — fundamentally too slow (45× slowness, hung tasks) AND makes a node miss
  its own target-cached-not-platter-durable writes (EACCES). `fua_disable=1` is deliberate. Never take
  ILOCK_EXCL or call `mxfs_dlm_reload_inode` in the hot read/getattr path (hangs on CAW poll).
- **`disk_differs=1` under fua_disable=1 is NOISE** (platter-lag vs write-back cache), not evidence of
  corruption (sess68/111).
- **mechanism F (read-completion TOCTOU) via `mxfs_buf_read_fua`** — IMPOSSIBLE: the FUA read is
  sync + under `b_sema` (sess92/93/110 code-reads confirm), so a concurrent txn can't modify mid-read.

## Where it stands (head of this cluster, sess111)
The `ltbno+ltlen>bno` shutdown persists but is INTERMITTENT/multi-root; on any given clean run it may not
reproduce (sess110-run2 ltbno=0, a different corruption type shut test2 down). The authoritative next
step is inode/BMAP-focused (P47/P81 verdicts at instr=0), NOT more bnobt/AG-meta instrumentation. The
whole "bnobt durable lost-update" line (sess20-92) is closed as a mis-diagnosis; the real defect is
cross-node stale in-core inode/BMAP issuing duplicate frees, unified with the rename/unlink/cross_write
visibility failures as cross-node inode-cache staleness. The sess47 stale-inode inactivation guard
(evolved through sess78/103) is the load-bearing defense and should be extended, not the free-space tree.
