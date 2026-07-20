---
name: compiled-dirreuse-sess47-48-wedge-fixes-extentmap-staleness
description: sess47-48 dir_reuse_coherency: 8-node wedge fixes + tenure-evict DABUF-hole heal; 1/2/4 tcp PASS, 8/tcp residual = reader dir extent-map staleness.
metadata:
  type: project
tags: [compiled, dir_reuse_coherency, tcp-8node, extent-map-staleness, dabuf-hole, release-pipeline-wedge, tenure-evict, lost-update]
---

## Compiled: dir_reuse_coherency — 8-node wedge fixes, tenure-evict DABUF-hole heal, residual reader extent-map staleness (sess47-48, ccloop 4cb2d0a2)

Central subject: getting the `dir_reuse_coherency` criterion (rm-rf + recreate churn, dir-inode REUSE)
green over TCP. sess47 killed the 8-node WEDGES and healed the fatal DABUF-hole tear; sess48 baked a
3-lever config that removes the multi-dirent P13-COLLIDE loss and passes 1/2/4 tcp 100%, but left an
intermittent ~1-2/24-round single-dirent lost-update at **8/tcp** that was decisively isolated to the
READER side (dir extent-map staleness) over a backing store that is provably coherent.

STATE AT HANDOFF: 1/2/4 tcp PASS 100% clean; **8/tcp NOT met**. Next root = reader dir extent-map
(`i_df`) reload not coherent with leaf/data on every cross-node handoff under inode reuse.

---

### Build progression (all sess47→48)
- `B349FD6E` — pre-fix base.
- `05BC5765` (05BC576518CA5792B2CB287) — **keeper**: base + 3 wedge fixes. First-ever clean 8-node pass (run1).
- `E9D1B1CB` — the two KEEP liveness fixes (relsafe lock + ilock_end defer), stable base.
- `45B640FF` — E9D1B1CB + P47-FILEBLOCK instrument (harmless, capped).
- `B887B7E8` — 05BC5765 + P48 instrumentation.
- `237F937D` — **config #1**, current base: bakes `dir_owner_scan=1`, `dir_grant_evict=1`,
  `dir_modify_target_flush=1` as DEFAULT (were 0). KEEP.
- `E871702B` — config #1 + `dir_relverify`-gated diagnostics (default 0, harmless).
- `FD6E4882` — 237F937D + P-DIRREL-DIFFERS extended onto `dir_relverify` (lightweight writer verify).

Enum decode for probes: MXFS_LOCK NL=0 CR=1 CW=2 PR=3 PW=4 **EX=5**; ISTATE NONE=0 CACHED=1 **BAST=2**
**DEMOTING=3** ACQUIRING=4.

---

### sess47 — THREE wedge fixes (all KEEP), then heal, then next wall
Diagnosis method: `DRC_STREAM=1` live `dmesg --follow` per node → NFS (survives node death) via
`tests/drc_detail8.sh`; foreground reboot+test; harvest `/src/mxfs/tests/tcp/drc_cap/stream_rank*.log`.
See [[sess47-FIXED-two-8tcp-wedges-relsafe-lock-and-ilockend-defer]] and
[[sess47-BREAKTHROUGH-3-wedge-fixes-8tcp-passes-sometimes-final-blocker-p13-collide]].

1. **relsafe lock** (`xfs_mxfs_dlm.c` ~8676): `bast_process` called non-relsafe
   `mxfs_dir_flush_data_blocks(ip)` which walks `for_each_xfs_iext(&ip->i_df)` WITHOUT `ip->i_lock`.
   On a REUSED dir a concurrent extent-fork mutation corrupted the lock-free walk → garbage
   `br_startblock` → out-of-range daddr → `xfs_buf_map_verify` `WARN_ON(1)` at `pal/linux/xfs_buf.c:423`
   fired **410727×** → synchronous console printk flood burns CPU → node stops servicing TCP >25s →
   `TCP_USER_TIMEOUT` → declared dead → round work lost (the dominant sess46 MASS loss). FIX: snapshot
   daddrs under `i_lock`(read), drop, then blocking-get (ABBA-safe) via
   `mxfs_dir_flush_data_blocks_relsafe`. warn423 → 0; rank2 stream 773MB→3.6MB.
2. **ilock_end defer-to-bast-wq** (~15280/15300): `mxfs_dlm_ilock_end` ran `bast_process` INLINE from
   `xfs_iunlock`; a `readdir` (`xfs_dir2_leaf_getdents`) still holds a dir DATA buffer → blocking
   `xfs_buf_lock` self-deadlocks. FIX: `ihold` + `queue_work(m_mxfs_inode_bast_wq,...)` (else `xfs_irele`).
   Latent before — masked by FIX-1's fast-failing garbage walk, exposed once the walk became correct.
3. **conversion-admit @ ilock_begin** (~14622): releasing a written REG file, `bast_process` does
   `filemap_write_and_wait` (~9966) AFTER clearing `i_dlm_mode=NL` (~9266); the `xfs_end_io`
   unwritten-extent conversion (needs EX) can't fast-path (mode≠EX) and blocks on the DEMOTING wait →
   PageWriteback never clears → bast deadlocks (PROVEN: both D-state; P47 mode=0 state=3). FIX: admit a
   non-dir op when `state==DEMOTING && MXFS_IF_DLM_RELFLUSH` set (on-disk grant still held). Dirs
   excluded (strict coherency gate).

Result: **8/tcp dir_reuse PASS 8/8 CLEAN, run1** — first clean 8-node pass. But INTERMITTENT: run2 (same
build) FAIL; run3 (+`dir_tenure_evict=1`) FAIL.

META-LESSON (contamination): most earlier "DABUF hole/shutdown" 8-node failures were CONTAMINATION from
killed/timed-out prior runs (sess29 hazard). PROOF: 4/tcp FAILED 0/4 right after an 8-node run but PASSED
4/4 after `rm /root/drc_failrounds.txt /root/drc_*.dmesg; dmesg -C` + full virsh reset +
`mosquitto_sub --remove-retained 'mxfs/#'`. ALWAYS fully sanitize between runs; never trust a result that
followed a killed run.

**DABUF_MAP_HOLE tear = sess20 stale-LEAF** (PROVEN, [[sess47-DABUF-HOLE-healed-by-tenure-evict-next-wall-is-release-pipeline-wedge]]):
P14 shows `loaded_gen==dir_gen` (extent map FRESH), data blocks 1,2,3 are legal HOLES (peer freed them),
but the **cached LEAF still references the freed blocks** → maps bno→hole → `xfs_da_btree.c:2876`
force_shutdown, cascades cluster-wide. Served stale because reader owns EX (`dlm_mode=3`) and the
read-time leaf re-read hook is disabled for owned_ex (`dir_unpub_skip=1`). Variant seen in
[[sess47-FIXED-two-8tcp-wedges-relsafe-lock-and-ilockend-defer]]: da-node references leafn 8388609 not
in this node's extent map (`off=3, off=8388608 leaf, off=16777216 free` — no 8388609) = da-node fresh,
extent map stale.

**HEAL** `dir_tenure_evict=1` (runtime modarg): enables EX-side prior-tenure leaf revalidation
(owned_ex-independent, epoch-gated, NOT per-op slow); P23-TENURE-EVICT fired 18× → 0 holes, 0 shutdowns.
This is the correctness fix for the leaf tear. Caveats ([[sess47-FINAL-state-fixes-heal-and-decoded-release-wedge-data]]):
it is only a PARTIAL heal in later runs — holes still occur (156-499/node) but mostly WITHOUT shutdown
(EFSCORRUPTED returned to caller, not force_shutdown); still FAIL 0/8. `dir_postread_reread=1` also heals
the hole but is a RULE-0 slowness wedge (per-op leaf re-read holds dir VFS `i_rwsem` → openers block >18s
→ timeout). Not viable.

**Next wall (sess47) — release-pipeline WEDGE, root found**: with E9D1B1CB + `dir_tenure_evict=1`, rank6
wedged. Cycle: bast kworker releasing inode X in `mxfs_dlm_bast_process → filemap_write_and_wait_range →
folio_wait_writeback → io_schedule` waits for X's writeback; the `xfs-conv` kworker completing that
writeback (`xfs_end_io → xfs_iomap_write_unwritten → xfs_trans_alloc_inode → xfs_ilock →
mxfs_dlm_ilock_begin`) blocks because X is DEMOTING and `xfs_end_io` is a DIFFERENT thread than the
demoter (`i_dlm_demoter!=current`) → hard deadlock → node declared dead. Data-file release-ordering bug:
a node releasing its OWN inode must let its OWN in-flight unwritten-extent conversion finish (grant still
held; conversion needs no new grant). P47-FILEBLOCK data: DOMINANT 4000× `req=EX mode=PR state=BAST
comm=rm` (unlink PR→EX upgrade during pending BAST, high-volume, likely resolves); RARE `req=EX mode=NL
state=DEMOTING comm=dd/awk` (the real conversion-vs-release case). Fix options: (a) extend demoter-skip so
same-node I/O-completion conversion on a DEMOTING inode whose grant this node holds proceeds; (b)
bast_process drains pending unwritten-extent conversions BEFORE `filemap_write_and_wait`/unlock.

**FINAL BLOCKER (sess47, intermittent ~50% at 8 nodes) = P13-COLLIDE** AG/extent double-alloc: test4
shutdown `P13-COLLIDE ino=131 daddr=102568048 ... ourdir=0 downer=<different-inode> bufgen=0 dirgen=51` —
the dir's in-core EXTENT MAP points to a freed-and-REALLOCATED daddr now owned by ANOTHER inode; the node
RMWs that block, clobbering the other owner. `bufgen=0` = stale base never gen-refreshed. NOT fixed by
`dir_tenure_evict` (that's leaf-side). This is the deep cross-node dir-extent / AG free-space coherence
family (sess39-47 bnobt). The DABUF_MAP_HOLE site should RELOAD the dir extent map and retry rather than
force_shutdown (transient stale map→hole is staleness, not on-disk corruption).

**GPT-5.5 consult** ([[sess47-GPT-consult-leaf-coherence-invariant-and-design]]) — invariant: at the
instant a node releases dir EX, stable storage holds a SELF-CONSISTENT image of data fork + LEAF/NODE index
+ inode extent map + alloc metadata through the releasing tenure's final LSN, and the releasing node has NO
remaining buffer/log-item/AIL-item/delayed-write that can modify any block after unlock. Mechanism, priority
order: (1) release-side flush expanded from "dir DATA blocks" to the ENTIRE data fork incl LEAF/NODE/free
index — force-COMPLETE (write+wait, NORMAL iodone retires BLI; NOT force-abort/ail_delete; `xfs_log_force`
alone insufficient); (2) write-fence at `xfs_buf_submit`: refuse to write a dir-fork metadata buffer unless
this node still holds the matching EX tenure (grant_seq+incarnation), else shutdown; (3) acquire-side
invalidate ALL clean dir-fork buffers incl LEAF/NODE (bno≥leafblk), stamp `owner_ino+incarnation+dir_gen+
grant_seq`; (4) once-per-handoff (NOT per-op) leaf validation → rebuild from DATA blocks if a leaf ptr hits
a HOLE. NOTE sess48 caveat below: the naive #1 as implemented (`dir_release_flush_all_done` / `_leaf`) did
NOT work — it still tears.

---

### sess48 — config #1 baked; 1/2/4 PASS; 8-node residual isolated to reader
See [[sess48-progress-ownerscan-flush-cuts-loss-residual-release-drain]],
[[sess48-config-combo-and-leaf-tear-and-relabort-lead]], [[sess48-8node-perhandoff-lostupdate-ruledout-set]],
[[sess48-FINAL-state-extentmap-staleness-is-next-root]].

**Config #1 (build 237F937D, KEEP)** bakes DEFAULT-1: `dir_owner_scan` (grant_gen-gated owner-evict of ALL
cached owned dir blocks on CONFIRMED cross-node handoff, slow-path acquire ~15084 — eliminates P13-COLLIDE
multi-loss 10→~1), `dir_grant_evict` (grant_gen modify-path evict; `i_dlm_cached_grant_gen` @14346/15110,
`b_mxfs_grant_gen` stamped in `xfs_da_btree.c`), `dir_modify_target_flush` (reader SYNCHRONIZE-CACHE before
dir read — cuts residual frequency). Each was "insufficient ALONE" in prior sessions; the COMBO removes
P13 multi-loss AND all shutdowns at 8/tcp, and holds 1/2/4 at 100%. RULE-0 caveat: `owner_scan` does a
full per-AG rhashtable walk per handoff ⇒ ~16-25s/round (too slow; optimize later; 24 rounds doesn't fit a
600s bash call — background run.sh or reduce reboot).

**RESULTS**: 1/2/4 tcp `dir_reuse_coherency` PASS 100% (24 rounds, 0 loss, 0 shutdown). **8/tcp FAIL** —
intermittent ~1-2 dirent loss per 24 rounds (readdir=796-799/800, LOOKUP_ENOENT REREAD_MISS, all nodes
agree, durable, NO real FS shutdown). Heavy but NON-FATAL `XFS_DABUF_MAP_HOLE_OK` (`xfs_da_btree.c:2876`,
~3800×/run) self-heals via datascan_lookup fallback.

**PER-HANDOFF lost-update (KEY finding)**: loss probability scales with EX-handoff COUNT. `inode_mht_ms=0`
(per-create handoff, ~800/round) → **8/10 rounds lose**; `inode_mht_ms=300` (batch) → ~1-2/24. MHT batching
HELPS (refuted as cause). Each cross-node EX handoff has a small chance a peer RMWs a dir DATA block on a
base LACKING entry X that was added+committed in the prior tenure. This is the ~130-session core.

**RULED OUT this session (all instrumented, RULE 4)**:
- Split-brain/double-grant: `P-DOUBLEGRANT`(dg_shadow) is a FALSE POSITIVE — `MX-DOUBLEGRANT` (chain-based,
  `dlm.c:601`)=0 always; P48-DG-CHAIN shows a SINGLE GRANTED EX holder (stale prior owner absent from chain).
- Acquire owner-evict skipping a DIRTY stale base: `P48-OWNEREVICT-DIRTYSKIP` dirty=1 count=0 (all skips
  `!DONE`/`done=0`, benign not-yet-read); acquirer cold-reads from platter.
- `owner_scan` causing DABUF_HOLE: refuted (holes just as high, 3800, with owner_scan=0).
- MHT batching as cause: refuted (disabling is far worse).
- Release write-durability (di_size): release DOES `blkdev_issue_flush` via `mxfs_dlm_dir_inode_durable`;
  P68-GROWREL-VERIFY / P-SFREL-VERIFY STALE-DISK=0.
- Writer data blocks: `DIRREL_DIFFERS=0`, P25-RELVERIFY-MISMATCH=0.
- Writer dinode/extent-map: P68-GROWREL-VERIFY all DURABLE (55-76×), 0 STALE-DISK.
- Writer modifies on stale bmap: P37-STALEBMAP-MODIFY=0.
- Reader readdir reload bail: P48-RDRELOAD bailed=0, nx_before==nx_after (9/10/11 consistent).

**REGRESSIONS (reverted, keep DEFAULT-0)**: `dir_release_flush_all_done` (DATA-only force-write at release)
and `dir_release_flush_leaf` (DATA+LEAF force-write) BOTH cause **P21H-LEAFHOLE tear → DABUF_HOLE storm →
FS shutdown**. DATA-only desyncs leaf; DATA+LEAF still tears (writing our leaf creates an inconsistent
on-disk index for the next acquirer). This is the ~30-session leaf-vs-data architectural core; the naive
GPT-consult-#1 force-complete-entire-fork did NOT work as implemented. `_flush_all_done` helps RDMISS
marginally but intermittently and adds RULE-0 slowness.

**The BACKING IS COHERENT — decisive reframe** ([[sess48-KEY-backing-is-coherent-writethrough-loss-is-bufcache-invalidation]]):
verified on clyde the target is NOT SCST but **LIO** (`target_core_mod`+`iscsi_target_mod`), backstore
FILEIO `mxfs` → single `/home/steve/disk.img`, `emulate_write_cache=0` (WRITE-THROUGH),
`emulate_fua_write=1`, `emulate_fua_read=1`. => single shared file behind a single host page cache,
write-through = PERFECTLY cross-initiator coherent; there is NO un-destaged write-cache staleness. This
resolves the long FUA-read-stale confusion: the lost-update is NOT a target/FUA coherency gap.

**force_coherent REFUTES stale-cache-serve** ([[sess48-force-coherent-worse-refutes-stalecache-residual-is-concurrent-rmw-race]]):
`force_coherent=1 dir_tenure_evict=1` (invalidate+re-read EVERY clean cached dir block from the coherent
backing, readers AND EX writers via `mxfs_ex_reval`) → 8/tcp **13/22 rounds FAIL** (vs ~1-2/24 baseline),
DRAMATICALLY WORSE. So serving a stale cached `xfs_buf` is NOT the root — forcing always-fresh reads from
a coherent backing exacerbates loss. Consistent with a TWO-PHASE / TORN-UPDATE window: a re-read pulls a
dir block mid-way through a peer's multi-step update (data-block write vs leaf/free/bestfree update vs
log-commit vs block-write ordering), or the aggressive invalidation discards a committed-in-AIL block a
concurrent path needed. Also refuted: `fua_disable=1` (read from write-cache instead of FUA) WORSE
(7/24 fail) — the FUA-read of the coherent backing is the BETTER path.

**Writer-vs-reader split RESOLVED → READER-side** ([[sess48-DECISIVE-loss-is-reader-extentmap-staleness-not-writer]],
[[sess48-REFINED-all-durability-passes-residual-is-fua-read-stale-content]]): decisive run FD6E4882
`dir_relverify=1` (read-only, perturbs TIMING, exposes MASS variant), Round 14: test1 & test4
readdir=726/800 **missing ALL ~74 of node8's entries** (node8_f1..f50 + .md5); writer test8 RDMISS=0
(sees its own). Writer verify clean (DIRREL_DIFFERS=0, P25=0) — node8's blocks ARE durable on platter. ∴
the loss is READER-side: peers' in-core view is STALE and misses a peer's just-grown dir blocks. MASS
variant = a peer's whole grow (~2 data blocks, nextents 8 vs 10) absent from readers' EXTENT MAP → readdir
skips those blocks → all entries vanish; the single-dirent variant (~1-2/24) is the same mechanism at the
edge. This matches the DABUF_MAP_HOLE storm (reader leaf refs blocks not in its stale extent map) and the
sess96 note ("evict+reread does NOT reliably pull a peer's just-committed dir block").

**NEXT ROOT (handoff lead)**: reader dir EXTENT-MAP / block reload on handoff is incomplete. After a peer
grows the dir + hands off EX, the reader must reload `i_df` to include the peer's new blocks AND cold-read
them. `mxfs_dlm_reload_inode` (triggered by `dir_gen>loaded_gen` at readdir/lookup/modify-refresh) either
does NOT fire for the reader or reads a stale dinode. `owner_scan` reloads DATA/LEAF buffers on handoff but
the inode extent-map reload may be inconsistent/stale → peer RMWs on a stale map → drops entries AND leaf
refs unmapped blocks (DABUF_HOLE). The P13-COLLIDE `ourdir=0 downer=foreign bufgen=0` variant points the
same way (extent map → foreign/freed daddr). DECISIVE PROBE to build: at readdir on the storm dir, FUA-read
on-disk `di_nextents` vs in-core `i_df.if_nextents`; in-core < disk ⇒ stale map not reloaded. Then fix:
force a reliable extent-map reload on EVERY cross-node handoff (grant_gen-based, like `dir_grant_evict`),
reading the durable dinode, so leaf + data + extent map reload as ONE consistent snapshot — especially
under rm-rf+recreate inode REUSE.

**Secondary residual lead** (P15-REL-ABORT, [[sess48-config-combo-and-leaf-tear-and-relabort-lead]]): the
single-loss correlates with **P15-REL-ABORT** (`dlm.c`, sess15 P58-avert): "holder re-acquired during
drain; release aborted, BAST re-armed" — fires 230×/node under 8-node MHT batching. Hypothesis: abort churn
leaves a window where a block isn't drained durable before a peer reads, or the abort reverts an add. Test
`inode_mht_ms=0` to see if the batch/abort interplay is root (RULE-0: mht=0 very slow).

---

### GFS2/OCFS2 reference (from GPT consult)
Dirty metadata belongs to a cluster-lock tenure; demoting DRAINS+INVALIDATES it; NO metadata writeback
after the lock tenure ends. They do NOT rebuild the dir index per handoff — they rely on drain-before-demote
+ invalidate-on-acquire discipline. The leaf is a DERIVED index: authoritative only within a tenure; across
handoff it must come from stable storage after the prev holder's release barrier, or be validated/rebuilt
for the current grant — never a casually-writable local cache.

### Reproduction / tooling
- `tests/drc_dirtyskip.sh "<modargs>" <rounds> <N>` — reboot-clean once, run 8/tcp dir_reuse, correlate
  RDMISS/CLASS/P13/DIRTYSKIP; logs to scratchpad. ~16-25s/round (owner_scan slowness).
- `tests/drc_detail8.sh` + `DRC_STREAM=1` (live per-node dmesg→NFS, survives node death); harvest
  `/src/mxfs/tests/tcp/drc_cap/stream_rank*.log`.
- `MXFS_EXTRA_MODARGS="dir_tenure_evict=1" MXFS_TEST_ENV="DRC_STREAM=1" ./run.sh 8 tcp dir_reuse_coherency`.
- ALWAYS fully sanitize between runs (rm failrounds/dmesg, `dmesg -C`, full virsh reset,
  `mosquitto_sub --remove-retained 'mxfs/#'`) — contamination produces false failures/passes.
