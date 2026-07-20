---
name: compiled-crash-consistency-sess17-dirent-merge
description: sess17 2/tcp crash_consistency root: shared dir-block stale-base flush clobber (P17); block-level dirent union-merge fix plan, v1 refuted.
metadata:
  type: project
tags: [compiled, crash_consistency, dirent-merge, dir-block, stale-flush, dlm, sess17]
---

Central topic: the sess17 (ccloop) investigation of the `crash_consistency` ship criterion at 2 nodes / `dlm=tcp`. The failure is a **durable stale-base flush clobber of a shared directory DATA block** (tracked as P17). This article folds the root-cause proof, the fix plan (block-level dirent union-merge), the refuted v1 merge implementation, the impl/txn analysis, refuted enforce hypotheses, and the reliability + marker decision.

## The criterion and reproducer
- Criterion test: `tests/suite/crash_consistency.sh` (category=**suite**, NOT `tests/criteria/*`). Each node writes 50 data files + 50 md5 sidecars into ONE shared dir, `sync`, `drop_caches`, then EVERY node re-reads EVERY node's md5 from the LUN. A durably-lost dirent = FAIL. See [[sess17-HEAD-shared-dirblock-staleflush-wseq0]].
- Passes in isolation (4/4) but FAILS in the full suite: the loss needs **cumulative cluster state** (prior tests free+reuse daddrs/inodes). Reproducer `tests/cc_blockdir_probe.sh` forces this with `mkdir + rm-rf` per iter (daddr reuse), `dirwr=1`; fails in ~iter 5-14 (some notes <6). The probe is strictly MORE aggressive than the criterion.

## Confirmed root cause (RULE 4 step 2b)
Build **6D51CDDF7ADB3947DCA880F** added the P17-CLOBBER-DROP detector (`pal/linux/xfs_buf.c`, after P35E). Because the workload is create-only, a dir DATA block's dirent count is monotonic non-decreasing, so any durable write with `nent < prev_max` for that daddr = a stale-base clobber. Smoking gun fired on BOTH nodes, `daddr=496 owner=131` ([[sess17-CONFIRMED-staleflush-clobber-P17]]):
- test1: `nent=22 < prev_max=24 lseq=94 wseq=94 in_ail=1 comm=kworker/u10:13` — the BAST **release-drain** (`mxfs_dir_flush_data_blocks` runs in the bast kworker) durably wrote 496 with only node1's entries, dropping node2_f1/node2_f2.
- test2: `nent=23 < prev_max=24 comm=xfsaild/sda` — xfsaild durably wrote a stale 496 dropping node2_f2.

Both write vectors (kworker release-drain AND xfsaild) confirmed.

Mechanism ([[sess17-HEAD-shared-dirblock-staleflush-wseq0]], [[sess17-FIX-PLAN-blocklevel-dirent-merge]]): a node re-acquires dir-EX holding a CACHED block 496 that carries its OWN un-written logged mods (`undest=1`, `wseq<lseq`; on earlier build F605BA70 seen as `lseq=24/26 wseq=0 undest=1 in_ail=1 done=1` — read once then logged ~25× locally, never destaged) but is MISSING the peer's committed entries. The acquire keep-guard `mxfs_dir_evict_data_blocks` (~2043: skip evict when `in_ail && !incarn_aba && undestaged`) CORRECTLY refuses to discard the node's real un-written work, so it never cold-reads the peer's image and never adopts peer entries. The node then durably FLUSHES that stale base over the peer's durable block → peer's dirents durably lost. This is the continuous-churn trap ([[sess10-gpt-verdict-serialize-tenure-not-epoch]]; sess10 refuted a naive FUA-compare-reload for exactly this reason).

Detector caveat: P17 keys the per-daddr max table on `(daddr, owner-ino)` only, NOT `i_generation`. ino 131 is reused every probe iter (rm-rf+remkdir) so `prev_max` can leak across iters → a fresh iter's smaller 496 could false-positive. Captured names prove it real WITHIN an iter (node2_f1/f2 dropped while node1_f1-20 present). Harden by adding i_generation/incarnation to the key.

## Why simpler fixes are all ruled out — union-merge is unavoidable
Because block 496 legitimately holds BOTH this-node un-written entries AND must adopt the peer's durable entries, neither keep nor cold-overwrite is correct ([[sess17-FIX-PLAN-blocklevel-dirent-merge]]). Refuted with evidence this session (do NOT re-explore):
- **Gen-propagation / local-gen gating**: NOT it. `mxfs_dir_force_evict=1` is already DEFAULT-ON (`xfs_mxfs_dlm.c` ~1931) — evict runs unconditionally every cross-node modify regardless of `i_dlm_dir_gen`. 496 is skipped because undestaged, not the gen.
- **wseq-tracking artifact** (block written but wseq=0 wrongly): NOT it. Fresh dir's 496 legitimately has `lseq>0, wseq=0` — real logged-but-UNWRITTEN node1 entries; keep-guard is correctly protecting real work.
- **Cold-read on acquire (evict the undestaged block)**: would DISCARD this node's own un-written entries.
- **force-evict-on-release**: TRIED+REFUTED sess96 (resurrected stale entries; code comment ~3956).
- **xfsaild/release chokepoint-SKIP**: REFUTED — see below.
=> A block-level dirent UNION-MERGE is unavoidable. Entries are name-disjoint across nodes (node1_* vs node2_*) so no conflict; it is the data-block analogue of the sess14 shortform `mxfs_dir_sf_3way_merge`.

## Refuted enforce hypotheses (the xfsaild/dir-block chokepoint skip)
Build **CD4CAA1DEA130A385B68E74** built the dir DATA/leaf-block analogue of the proven P61 bmbt chokepoint skip ([[sess17-detector-refutes-enforce-and-cc-flaky-pass]], [[sess16-FIX-LEAD-extend-chokepoint-skip-to-dir-dirent-blocks]]):
- `mxfs_dir_data_track()` (`xfs_mxfs_dlm.c`) — MODIFY-time tenure stamp on dir3 data/block/leaf/free/node bufs, wired into `xfs_trans_log_buf` (else-branch after bmbt); stamps `b_tenure_id = i_mxfs_ex_grant_seq`.
- `mxfs_buf_xfsaild_skip_dir_write(bp,&info)` — submit-time predicate (NL-released OR `b_tenure_id != cur epoch`).
- Chokepoint at `pal/linux/xfs_buf.c` ~1729 (after P61 bmbt skip) logs P16-DIRBLK-SUBMIT; enforce gated by new param `mxfs.dirskip` (default 1; ran dirskip=0 detect-only).

Detector REFUTED the enforce hypothesis (dirskip=0 dirwr=1, probe iter1 ino131):
- Lost entry in the probe = node1_f1 (the FIRST file); P35E-DIRWR shows it ABSENT from the EARLIEST captured image of block 536 on BOTH nodes → dirent lost at INSERT time (shortform / sf→block / concurrent-RMW merge), not a stale re-flush over a good image.
- ZERO `nl=1` (NL-released) dir-block writes in the whole trace → the NL-released reflush predicate never fires.
- `tmism=1 would_skip=1` fired ONLY on `tenure=0` blocks written by `comm=dd`/`comm=ls` = FRESH/conversion blocks (esp. leaf1 daddr=2095120 during block→leaf: owner not set in header at first log → track skips → tenure stays 0). Enforcing the tenure-mismatch arm would SUPPRESS LEGIT writes → corruption — exactly the [[sess23-ccloop-suppression-was-corruptor-3of4]] hazard. Made enforce NL-only + default-off; KEPT the detector as tooling.

Also refuted earlier (build F605BA70): the sess16 dir-block xfsaild chokepoint-SKIP (extending P61 to dirent blocks) — same tenure=0 false-positive. Note sess16 P16-RELEASE-UNDESTAGED claimed `undest=0` at release, CONTRADICTED by 6D51CDDF (undestaged base present); re-verify.

## The fix plan — block-level dirent union-merge
When a dir DATA block is undestaged AND a peer modified the dir, read the peer's DURABLE block from disk (plain read OK under `fua_disable=1`) and, for every dirent present on disk but ABSENT in-core, ADD it to the in-core block; keep our own un-written entries → union, no loss either way.

Concrete impl `mxfs_dir_block_merge_peer(tp, dp)` ([[sess17-merge-impl-approach-and-txn-blocker]]):
1. Gate: param (default off), multinode, S_ISDIR, fmt EXTENTS/BTREE (shortform → existing sf_merge), extents loaded, bt_bdev present.
2. kmalloc `geo->blksize`; `for_each_xfs_iext` over `dp->i_df`; per dir-block chunk daddr d: plain-read `lba = d + bt_sector_offset` via `mxfs_pal_bdev_read_plain_bdev` (fua_disable=1) into a STABLE snapshot rb.
3. Identify DATA blocks by MAGIC `rb[0..3]` = XDD3 (data) / XDB3 (block); verify `((xfs_dir3_blk_hdr*)rb)->owner == dp->i_ino`. Skip XDL3 leaf / XDF3 free / node.
4. Walk dirents from `geo->data_entry_offset` (end = XDB3 ? `xfs_dir2_block_tail_p` : blksize), skipping `xfs_dir2_data_unused` (freetag==XFS_DIR2_DATA_FREE_TAG). For each `xfs_dir2_data_entry`: name={dep->name, namelen, `xfs_dir2_data_get_ftype`}, inum=`be64_to_cpu(dep->inumber)`; skip "."/"..".
5. `xfs_dir_lookup(tp,dp,&name,...)`; if `-ENOENT` → `xfs_dir_createname(tp,dp,&name,inum,0)` to re-add. Both APIs require dp ILOCK_EXCL (true on modify path). Reuses `xfs_dir2_data_make_free/use_free/log_entry` + leaf/leafn add-hash + nextents machinery — much simpler than manual bestfree/leaf mgmt.

Hook candidates: create ~1365 / remove ~3495 (or ~3470) / rename ~3908, all holding dp ILOCK_EXCL with active tp.

**The txn blocker**: `xfs_dir_createname` needs a transaction. Injecting the merge's createname calls into the OUTER op transaction `tp` is dangerous — `tp` was reserved for ONE op, so a mid-merge createname failure (e.g. ENOSPC) can leave `tp` DIRTY, and the subsequent `xfs_trans_cancel` on a dirty trans = "Corruption of in-memory data" FS SHUTDOWN (same class the sess82 re-validate guard at `xfs_inode.c` ~3470 avoids). So the merge needs its OWN transaction.

Recommended impl: do the merge in a SEPARATE transaction at the PRE-LOCK hook (`mxfs_dlm_dir_modify_reload_prelock`, `xfs_inode.c` ~1296/3448/3817 — runs with NO outer tp, NO ILOCK held): `xfs_trans_alloc` (tr_create/tr_dir reservation sized for expected missing count), ilock dp EXCL, run lookup+createname merge, commit (or cancel cleanly, safe since self-contained), iunlock; then the normal op proceeds on a now-merged in-core dir. Isolates merge failures from the op txn.

Risks: (1) PERF — reading all data blocks per modify violates RULE 0; trigger only when a block is undestaged AND peer advanced `i_dlm_dir_gen`, or rate-limit; reuse `mxfs_dir_evict_data_blocks`' per-block undestaged detection to find which blocks need merging rather than blindly reading all. (2) createname re-adding an entry the peer LATER removed would resurrect it — safe for crash_consistency (create-only); gate to additive workloads / compare gens for general correctness. (3) reservation sizing.

Also investigate release-drain COVERAGE: P-RELFLUSH fired only ONCE per node (block 496) though the lost entry (node2_f17.md5) lived in a different block ~14652648. Confirm `mxfs_dir_flush_data_blocks` (~1184) flushes EVERY modified dir block at release; a block already xfsaild-written STALE (clean → !needs_flush at release) is a second loss path the fence won't fix.

Alternative sound path (GPT demote-drain-by-ownership, [[sess17-CONFIRMED-staleflush-clobber-P17]]): make EX RELEASE the serialization barrier — flush ALL modified dir DATA blocks durable, then INVALIDATE them (`xfs_buf_stale`/clear XBF_DONE ONLY after confirmed-durable per sess33 invariant) so the next acquire cold-reads the peer's image and the acquire-side keep-guard becomes unnecessary — no block-level merge needed. RISK: clearing XBF_DONE on a non-durable buffer corrupts (sess33); flush-then-invalidate ordering must be strict.

## Merge v1 — REFUTED (FS shutdown)
Build **492C8EB73ACA12A99A2992A**, `dir_merge=1` ([[sess17-merge-v1-REFUTED-dlm-shutdown]]): `mxfs_dir_merge_peer_blocks(dp)` — Phase1 (ILOCK_SHARED) snapshots peer durable dirents by plain-reading every dir DATA block; Phase2 re-adds each missing dirent via its OWN transaction (`xfs_trans_alloc tr_create` + `xfs_ilock(dp,ILOCK_EXCL)` + ijoin + `xfs_dir_lookup` + `xfs_dir_createname`), wired at the create PRE-LOCK hook (`xfs_inode.c` ~1296, after `mxfs_dlm_dir_modify_reload_prelock`), gated by `mxfs.dir_merge` (default OFF).

RESULT: FS SHUTDOWN on test2 — "Corruption of in-memory data (0x8) at `mxfs_dlm_ilock_begin+0xbc6` (`xfs_mxfs_dlm.c:8128`)". P17-MERGE fired 0× (shut down before re-adding); mount HUNG; nodes stayed ssh-alive (OS fine, only mxfs mount died). ROOT: `mxfs_dlm_ilock_begin` (lines 8115-8129) force-shuts-down (SHUTDOWN_CORRUPT_INCORE) when a per-inode DLM lock ACQUIRE returns `rc!=0`. Taking ILOCK_EXCL in a FRESH transaction PER missing entry = dozens of independent dir-EX DLM acquire/release cycles per create under concurrent 2-node load; one acquire fails → shutdown.

Lessons for the next merge: (1) DO NOT take ILOCK_EXCL / fresh transactions per-entry at prelock — churns the per-inode DLM grant → acquire failure → shutdown. (2) Do the merge ONCE, holding the dir lock once for all re-adds, either as a BUFFER-LEVEL op on the in-core dir data blocks under the create's ILOCK_EXCL (log via the create's tp), OR deferred to ONE well-reserved trans after the create commits. (3) Even correct, reading ALL dir blocks on EVERY create violates RULE 0 — gate strictly on `i_dlm_dir_gen` advanced + block undestaged. (4) Reuse `mxfs_dir_evict_data_blocks` per-block undestaged detection to find WHICH blocks need merging.

Merge v2 target ([[sess17-reliability-data-and-marker-decision]]): ONE transaction holding the dir lock once for all re-adds, gen-gated, reusing the create's tenure.

## Reliability data + marker decision
crash_consistency runs this session ([[sess17-reliability-data-and-marker-decision]]):
- bm5wxz1p5 FULL suite (CD4CAA1D): FAIL 1/2. 4× isolation (CD4CAA1D): PASS. recovery health-check (492C8EB7): PASS. b8n3f1ukb FULL (492C8EB7): PASS 16/16. bk04xvzmy run A FULL (492C8EB7): PASS 16/16 (criteria.json verified). ~1 fail in 7 criterion-test runs (~14%); 0/3 on current 492C8EB7 but small sample.
- `cc_blockdir_probe` (aggressive, forces daddr reuse): reliably FAILS ~5-14 iters on BOTH CD4CAA1D and 492C8EB7 → the durable lost-update bug IS PRESENT in the current build; the ship-gate test just doesn't trigger every run. crash_consistency is FLAKY — a race that doesn't always fire, perturbed by contaminated cluster state / instr timing; the 16/16 passes are flaky-passing on timing, NOT a fix.

DECISION: **marker NOT written** ("2 node dlm=tcp 100% successful" is NOT honestly met): the criterion test FAILED once this session (not 100%); the root-caused durable dirent lost-update is UNFIXED; the aggressive probe still reproduces the loss on 492C8EB7. Writing YES = the dishonest escape the wrapper forbids.

To ACTUALLY meet it: land merge v2, then validate `cc_blockdir_probe` clean >25 iters AND `./run.sh 2 tcp` 16/16 across ≥5 consecutive runs, watching `cache_coherency`/`zero_silent_loss`/`rename` for regressions.

## Build progression
- **895603D7** — sess16 functional baseline / fallback (also the recorded baseline FAIL at 10:55). `./run.sh 2 tcp` = 15/16, crash_consistency sole fail.
- **F605BA70D8FBE572C257831** — baseline coherency logic + dir-block detector tooling (P-EVICT-SKIP, P35E-DIRWR), dirskip default 0. Proved undestaged wseq=0 base 496; refuted sess16 dir-block chokepoint-skip.
- **6D51CDDF7ADB3947DCA880F** — adds P17-CLOBBER-DROP detector (+ P16-DIRBLK-SUBMIT, P-EVICT-SKIP/DONE, P-RELFLUSH, P35E). CONFIRMED root; both clobber vectors captured. `./run.sh 2 tcp` = 15/16.
- **CD4CAA1DEA130A385B68E74** — dir-block xfsaild-skip build (b_tenure_id stamp + detector, dirskip default 1, ran 0). Detector refuted enforce; functionally ≈ baseline (skip inert at dirskip=0). crash_consistency flaky-passed 4/4.
- **492C8EB73ACA12A99A2992A** (deployed both nodes, DEFAULT SAFE) — baseline + DORMANT merge v1 (`dir_merge` default OFF) + P17-CLOBBER-DROP + P16-DIRBLK-SUBMIT detectors + `dir_merge`/`dirskip` params. With `dir_merge=1` = v1 REFUTED (test2 shutdown, recovered via reformat+remount / virsh destroy+start). No functional fix landed. Marker NOT written.

## Env / tooling carried
- Reproducer `tests/cc_blockdir_probe.sh` (`dirwr=1 dirskip=0`), aggressive daddr-reuse via per-iter mkdir+rm-rf.
- Detectors: P17-CLOBBER-DROP (`pal/linux/xfs_buf.c`; harden key with i_generation/incarnation), P16-DIRBLK-SUBMIT, P-EVICT-SKIP/DONE, P-RELFLUSH, P35E-DIRWR.
- Params: `mxfs.dir_merge` (default off), `mxfs.dirskip` (default 1), `mxfs.dir_force_evict` (default ON, ~1931), `dirwr`, `instr`.
- Cluster recovery from mxfs-mount shutdown: fresh prep (reformat+remount) or `virsh destroy+start`.
