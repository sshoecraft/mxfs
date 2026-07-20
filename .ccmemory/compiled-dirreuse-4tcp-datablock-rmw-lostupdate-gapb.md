---
name: compiled-dirreuse-4tcp-datablock-rmw-lostupdate-gapb
description: sess68 ccloop: 4/tcp dir_reuse residual isolated to a pure single-block dir-DATA-block RMW lost-update; gap-B (inode extent-map durability) fixed+KEE…
metadata:
  type: project
tags: [compiled, sess68, dir_reuse_coherency, lost-update, gap-B, 4tcp, datablock-rmw, cache_coherency]
---

# sess68 (ccloop 4cb2d0a2) — 4/tcp dir_reuse_coherency residual: pure data-block RMW lost-update

**Central topic.** The last failing arm of the `cache_coherency` ship criterion is `dir_reuse_coherency` at 4 nodes over TCP transport. 1/tcp and 2/tcp PASS (sess58); 4/tcp fails ~1 round in ~15 (~310–313s per 24-round run, itself a separate RULE-0 slowness concern); 8/tcp untested. Failure signature: a durable single-/few-entry loss — `LOOKUP_ENOENT` + `REREAD_MISS` on ALL nodes after `echo 3 > drop_caches`, i.e. the entry is genuinely gone off the LUN. Lost name varies run-to-run (node2_f33.md5, node3_f2, node4_f40.md5, node1_f4+f5, node2_f37.md5, node1_f10/f10.md5/f11 contiguous). Session net: one real fix found (gap-B, KEEP), the residual **isolated to a pure dir-DATA-BLOCK content RMW lost-update** at a daddr all nodes agree on, with extent-map explanations exhaustively refuted.

## The one KEEP fix — gap-B (inode extent-map durability at EX release)

- **Bug**: `mxfs_dlm_dir_inode_durable` (xfs/xfs_mxfs_dlm.c ~1984) had `if (if_format != LOCAL) return;`, which SKIPPED making a grown EXTENTS/BTREE dir's **inode** extent map (di_size/di_nextents, inline in the dinode) durable at EX release — only data/leaf/bmbt *blocks* were flushed. A peer's post-handoff FUA read of the dinode then saw a stale SMALLER extent map → couldn't locate grown data blocks → re-allocated a divergent block (count loss) or adopted the stale-small disk image (`P33-FROMDISK-DIRSHRINK` tear).
- **Fix**: make the dinode cluster durable for ALL dir formats, **gated on the inode being dirty** (pincount/ili_fields/in-AIL) to avoid the sess42 ungated ~30× iflush perf regression. See [[sess68-gapB-proven-ownevict-moot-drop_caches-gpt-arch]].
- **Confirmed effective**: probe `P68-GROWREL-VERIFY` (EX-release path just after `mxfs_dlm_dir_inode_durable(ip)` ~line 6034) FUA-reads the on-disk dinode and compares di_size to in-core. Result **DURABLE on all 48 releases across test1-4, STALE-DISK=0**. So the grown dir extent map is durable on the platter at every EX handoff; the `P33-FROMDISK-DIRSHRINK` events are LEGITIMATE adoptions of a freshly rm-rf+recreated 1-block incarnation, not a durability failure. See [[sess68-gapB-CONFIRMED-residual-is-datablock-RMW-lostupdate]].
- **Ship caveat**: gap-B is not expected to regress 1/2 tcp (gated dirty + non-LOCAL; 1/2 workloads are mostly shortform/single-block) but **re-verify 1/2 tcp before shipping**.

## The decisive bounding result — it's single-block, not grow

`DRC_NFILES=3 DRC_ROUNDS=40 ./run.sh 4 tcp dir_reuse_coherency`: 3 files/node × 4 nodes × 2 (data+md5) = 24 entries → the shared dir stays **BLOCK format (one dir block, daddr=120, no LEAF conversion, no grow)** and **STILL FAILS** (nodes_pass=0/4). This eliminates multi-block growth, BLOCK→LEAF conversion, extent-map divergence, higher-block daddr allocation, bmbt, and all the grow machinery chased sess36/62/67 — so gap-B, while a real fix for the grown-dir case, is **irrelevant to the minimal repro** (its extent map is trivial). The question reduces to: how does concurrent add + rm-rf reuse on a single shared dir block durably drop one entry at 4 nodes when 2 nodes pass. See [[sess68-BOUND-single-block-dir-fails-simplest-repro]]. Minimal repro for next session: `DRC_NFILES=3 DRC_ROUNDS=12` (or 6–8) `./run.sh 4 tcp dir_reuse_coherency` — fewer entries = less log volume = dmesg ring won't rotate.

## Refutation tally (all 4/tcp single-entry durable loss)

- **Extent-map divergence at modify**: REFUTED. `P68-MAPDIVERGE` implemented sess67's documented MERGE-adopt in `mxfs_dlm_dir_modify_reload_prelock` (~3120, gated `mxfs_dir_modify_extent_adopt`): decode disk inline extents (xfs_bmbt_disk_get_all), compare each (startoff,startblock,blockcount) to in-core via xfs_iext_lookup_extent, reload+adopt on any divergence. **=0, never fired** across a full failing run — in-core map matches disk map at every modify-prelock, yet a contiguous whole-block loss still occurred (node1_f10/f10.md5/f11). FUA-per-modify is pure perf cost; `mxfs_dir_modify_extent_adopt` default 0, code kept. See [[sess68-MAPDIVERGE-rules-out-extentmap-loss-is-pure-datablock-RMW]].
- **Extent-map reload on acquire (epoch_adopt)**: INSUFFICIENT. epoch_adopt (full from_disk i_df rebuild on EX-acquire when DLM epoch advanced) once made count loss "disappear" (RDMISS=0) — but that was a LUCKY run; failure is ~1/15 rounds and that run failed on the leaf-hash arm instead. Clean run build **D3EA5B8D** (gap-B + epoch_adopt=1) STILL lost `node2_f37.md5` (LOOKUP_ENOENT all 4 nodes); P68-GROWREL-VERIFY durable=17 STALE=0. epoch_adopt also tears on shrink-adopt (P33-FROMDISK-DIRSHRINK). See [[sess68-FINAL-epoch-not-enough-datablock-durability-next]].
- **Cached stale-block survival**: REFUTED. The test does `echo 3 > /proc/sys/vm/drop_caches` every round; `P68-OWNEVICT` (owner-evict, `mxfs_dir_evict_owned_dir_blocks`) fires but **collected=0 evicted=0** every time — the owner-walk finds zero cached dir blocks. owner-evict is inert here and a likely revert (defensively correct only for a real no-drop_caches workload). KEY INSIGHT: drop_caches drops the buffer cache (data/leaf blocks) but NOT the in-core inode (i_df extent map persists) — so the persistent staleness that survives drop_caches is the i_df extent map, not cached blocks; and the durable loss is an on-disk write loss during the concurrent create wave. See [[sess68-gapB-proven-ownevict-moot-drop_caches-gpt-arch]].
- **Read-side stale re-read / SCST target-cache pierce**: REFUTED. Ran with `MXFS_EXTRA_MODARGS='fua_disable=0'` (re-enable SCSI-FUA reads so every cold dir-block re-read pierces the SCST target cache to platter). STILL FAILS (lost node3_f27.md5 round 1). The entry is genuinely WRITTEN-missing to the platter, not mis-read. Keep `mxfs_fua_disable=1` default (sess45 set it; FUA caused rename_visibility 372s+shutdown; coherency relies on buffer INVALIDATION + SCST's coherent shared cache, and cluster is SCST not LIO). See [[sess68-FUA-refutes-readside-loss-is-writeside-same-incarn]].
- **DLM double-grant / gen-detectable staleness**: REFUTED (P-DOUBLEGRANT=0, sess62; prior sessions).

**Therefore**: the loss is a durable WRITE of a dir DATA block, at a daddr all nodes agree on (MAPDIVERGE=0), MISSING a peer-committed entry, **same incarnation** (di_gen cannot catch it), landing last on the platter.

## Characterization — the lost-update SWAPS entries (count probes insufficient)

- **P68-DWR** always-on write-side probe (xfs/libxfs/xfs_dir2_data.c `xfs_dir3_data_write_verify`): for a multinode dir, count all "node[1-8]" dirent names in the block being written + log (daddr, nodecnt, comm). Cheap, no-IO, ratelimited 4000. See [[sess68-writeprobe-countdrops-need-incarnation-tag]].
- Count DROPS do occur (block0 daddr=120: 154→117, 155→146; test3 daddr=2093296: 87→44; test4: 152→1, 44→1) but the dir3 data-block header carries `owner` (inode #) but NOT the inode generation, so raw drops CANNOT distinguish a real same-incarnation lost-update from a legit rm-rf+recreate reset (drops to ~1 are clearly reset). Needs **incarnation tagging** — stamp the writing inode's i_generation into `b_mxfs_dir_incarn` (field already exists) at modify time and log it; or correlate with the test's `DRCph` PHASE kmsg markers (a drop between create-start and rm-done of the same round = lost-update; a drop straddling rm-done = legit reset). See [[sess68-writeprobe-countdrops-need-incarnation-tag]].
- **Incarnation-tagged P68-DWR** (build **42A3D0B2**): within round 19's create wave (node1_f49.md5 lost), NO (daddr,incarn) pair had a dirent-count DECREASE on any node — total count grew **MONOTONICALLY per incarnation**. Writes are ~all comm=bash/dd (live foreground create+sync); xfsaild writes 1–3 total per node → **NOT a stale-writeback/xfsaild-ABA clobber** (sess40 family ruled out). See [[sess68-lostupdate-swaps-entries-count-probe-insufficient]].
- **KEY INSIGHT**: the lost-update **SWAPS** entries, it does not shrink the block. Node X acquires EX, reads a STALE base missing peer-entry A, then adds its own entry B and commits — net count grows or holds, so a count-based probe sees only monotonic growth, but entry A is durably gone. This is GPT-5.5's bug #1 (same-incarnation stale-base RMW lost-update). See [[sess68-lostupdate-swaps-entries-count-probe-insufficient]].

## Sharpest open lead — evict inner loop never runs (EVDECIDE=0)

Probe **P68-EVDECIDE** (xfs_mxfs_dlm.c, always-on, inside `mxfs_dir_evict_data_blocks`' per-block loop just before the undurable/keep decision) on the minimal repro (`DRC_NFILES=3 DRC_ROUNDS=12`, build **A81DB821**): **total=0 on ALL 4 nodes** — the evict loop NEVER iterates a block for this dir. Implication: a node never evicts block0 before its RMW on the single-block dir → RMWs whatever is cached (potentially a stale base) → durable single-entry lost-update. Candidates for why total=0 (RULE 4, next session): (1) `mxfs_dir_evict_data_blocks` returns EARLY — SHORTFORM `return true` (~2241, `else if (if_format != EXTENTS) return true`); the 24-entry tiny dir may actually be SHORTFORM despite force_block=1, in which case the residual is a SHORTFORM-dir inline-dirent RMW lost-update (sess84/sess14 3-way-merge territory, `mxfs_dir_sf_3way_merge` the fix locus — note 2/tcp shortform merge works, 4-node breaks it). Verify actual format of the REUSED dir at modify via P62-SF2BLK / P62-DATAINIT-BLK0. (2) `modify_refresh` not reaching evict (prelock `mxfs_dlm_dir_modify_reload_prelock` returns early `if (dp->i_dlm_mode == MXFS_LOCK_EX) return;` ~3143; confirm `mxfs_dlm_dir_modify_refresh` reaches evict for a cached-EX holder). See [[sess68-LEAD-evict-data-blocks-never-runs-EVDECIDE0]].

## Where the stale-base RMW leaks despite force_evict + release fence

force_evict (`mxfs_dir_evict_data_blocks`, pre-RMW) drops CLEAN + destaged-in-AIL blocks so the RMW cold-re-reads; Invariant 1 requires data_durable before unlock. So the cold re-read *should* get the peer's committed block. Remaining candidate windows (none yet disproven): (a) cold re-read FUA does not pierce the SCST/iSCSI target write-cache to platter — but fua_disable=0 refuted read-side loss; (b) X keeps an **in-AIL-UNDESTAGED block0** (its own un-written work) that is a stale fork vs a peer's committed write — across an MHT-batched EX yield+reacquire mid-create-wave a node's in-AIL block0 can be stale-vs-peer; the sess41 EVICT-SIDE refresh is meant to catch this but is gated (`mxfs_dirrefresh`) and uses a live-dirent count that misses same-count-different-content divergence; (c) a sub-ms window in the EX handoff where two nodes' block0 dirty images both exist. See [[sess68-lostupdate-swaps-entries-count-probe-insufficient]], [[sess68-MAPDIVERGE-rules-out-extentmap-loss-is-pure-datablock-RMW]].

## GPT-5.5 architectural consult (RULE 5) — two bugs, two keys

- **Bug #1 (same-di_gen lost-update / count loss)**: needs a **DLM-EPOCH-keyed** invalidate/re-read BEFORE dir RMW. di_gen cannot catch it (same incarnation). The existing modify-prelock epoch gate (`mxfs_dir_modify_extent_adopt`, sess67) is INERT: it's count-based (divergence is content not count) AND valid_epoch is already == grant_epoch by modify time (grant_epoch>valid_epoch never true).
- **Bug #2 (gen-change tear)**: owner purge ordered BEFORE from_disk — moot here due to drop_caches.
- **Buffer stamps** should be keyed `(ino, di_gen/incarn, dlm_epoch, dir_cache_seq)` and validated in the READ path (xfs_da_read_buf / xfs_dir3_data_read), not just b_mxfs_dir_gen.
- **Deepest root**: an inode number REUSED cluster-wide while a peer still holds the old incarnation active violates a core XFS invariant. Robust fix = **inode-lifetime fencing**: a separate DLM lifetime lock; before xfs_ifree/reuse acquire EX → BAST peers → peers purge+reclaim old incarnation before reuse proceeds (large change). See [[sess68-gapB-proven-ownevict-moot-drop_caches-gpt-arch]].

## Concrete next steps (RULE 4, prioritized)

1. **Resolve EVDECIDE=0**: confirm whether the minimal-repro reused dir is SHORTFORM or BLOCK at modify — this bifurcates the whole diagnosis (shortform → sf 3-way-merge; block → evict-loop early return / never reached).
2. **Per-ENTRY (not count) write probe**: in `xfs_dir3_data_write_verify` hash the SET of dirent names (real bitmap or jhash-set, XOR cancels) and log it for the multinode dir, incarnation-tagged; a write of block0 whose name-set is MISSING a name a prior same-(daddr,incarn) write HAD = the swap-lost-update in the act, with comm + node.
3. **Data-block release-durability probe** (twin of P68-GROWREL-VERIFY, which only covers the INODE): in the EX-release drain (`mxfs_dir_data_durable` / release path ~5711), after data-block flush, FUA-read each dir DATA block and compare dirent count/content to in-core; disk FEWER = release-durability gap.
4. **Fix candidates**: force sess41 EVICT-SIDE refresh ON unconditionally for the in-AIL-kept case (drop in-AIL block if FUA disk read differs); OR on cross-node EX re-acquire evict in-AIL dir data blocks too (safe: drained at prior release per Invariant 1); OR GPT bug-#1 epoch-keyed mandatory re-read/invalidate before RMW; architectural fallback = epoch-keyed buffer stamp in the read path or inode-lifetime fencing.

## Build progression / markers

- Shipped-proven baseline: **91962D4A** (force_block=1, epoch_adopt OFF).
- **2CF2C45B** — early handoff, all sess68 changes.
- **59AED037** — gap-B + P68-DATAINIT/GROWREL-VERIFY (KEEP) + owner-evict (gated, moot) + MAPDIVERGE per-block compare (code kept, default 0).
- **D3EA5B8D** — gap-B (KEEP) + owner-evict (moot, collected=0) + P68 probes; also the epoch_adopt=1 clean-run build that STILL lost node2_f37.md5.
- **EAB3D32098D503EB6B34391** — gap-B + probes, P68-DWR always-on (pre-incarnation-tag).
- **42A3D0B2D67FFFA84914133** — gap-B + P68-DWR incarnation-tagged always-on; proved monotonic per-incarnation growth (swap, not shrink).
- **590E2E89** — gap-B + probes (P68-DATAINIT, P68-GROWREL-VERIFY, P68-DWR per-entry nameset+incarn) + gated-off MAPDIVERGE/owner-evict.
- **A81DB821 (HEAD)** — gap-B + P68-EVDECIDE always-on + other probes gated behind `mxfs.dirwr`; MAPDIVERGE/owner-evict gated off. EVDECIDE=0 on minimal repro.

**KEEP**: gap-B; cheap probes P68-DATAINIT, P68-GROWREL-VERIFY. **NOT the fix**: owner-evict (moot), epoch_adopt (insufficient), MAPDIVERGE-adopt (found nothing). **CRITERION NOT MET** (4/tcp dir_reuse_coherency; 1/2 PASS, 8 untested).

## Infra notes

- Repro: clean rmmod test1-4 (`umount -l` + rmmod test1 first or mkfs prep fails "bad nodes: testN(build mismatch)"), `./run.sh 4 tcp dir_reuse_coherency` (~310s, ~1/15 rounds FAIL). Reduce `DRC_ROUNDS` (env, still fails at 8) to keep the dmesg ring from rotating within a run.
- Instr caution (Heisenbug): instr=1 masks the race (~100× slow) — use cheap always-on stamps, NOT synchronous FUA probes in the hot path. `dmesg -w` streaming does not survive run.sh prep (rmmod + dmesg -C); start streaming AFTER insmod.
- Cluster left healthy (test1-4 mounted, test5-8 up for 8/tcp). test2 was rebooted once via `virsh destroy/start` after a wedged `mxfs-ino-bast` D-state kworker blocked rmmod (allowed — VM reboot, not host).
