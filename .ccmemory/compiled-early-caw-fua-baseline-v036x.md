---
name: compiled-early-caw-fua-baseline-v036x
description: v0.3.61-v0.3.109 baseline: SCSI READ-FUA, cached-AG divergence root cause, CAW cross-init OK, kernel CAW broken, false-positive script fix.
metadata:
  type: project
tags: [compiled, caw, fua, bnobt, cache-coherency, dlm, stress-harness]
---

# Early CAW/FUA baseline (v0.3.61 → v0.3.109, sess22–26)

Central thread across these five sessions: the **bnobt LEFT/RIGHT-FAIL** corruption family
(and its twin, **Mode A** `xfs_dir_removename` ENOENT) under 2-node (test1/test2) shared-LUN
stress. The arc goes: extend SCSI READ-FUA to more buffer classes → discover the reported
PASSes were fake → prove the real root is **silent cached-AG state divergence between nodes**
→ prove the CAW/FUA *transport* itself is correct at userspace → finally localize a residual
to the **in-kernel SCSI CAW passthrough** reporting write-success without persisting. Local
single-node XFS was proven clean throughout; every bug here is cross-node.

## sess22 — extend FUA, first false dawn ([[Sess22 lessons (v0.3.61-v0.3.67)]])
Build progression (2026-05-03):
- **v0.3.61** — P25-INSTR at `xfs_inode_mark_reclaimable` (xfs_icache.c:2465); confirmed sync `inactive_ifree` executes.
- **v0.3.62** — SCSI READ(16) FUA passthrough extended from disklock (v0.3.58) to **xfs_buf AG-meta reads**. New helper `mxfs_pal_scsi_read_fua_bdev` (pal/linux/kern.c), declared in xfs/xfs_mxfs_dlm.h. Hook in `xfs_buf_submit` gates on `(XBF_READ && !WRITE && !READ_AHEAD)` + multi-node + AG-meta predicate; falls back to bio on -EOPNOTSUPP.
- **v0.3.63** — `peer_joined_flush` invalidates cached AG-meta across every perag (xfs_mxfs_dlm.c:2459). AG-meta cached at mount via bio (single_node=true), persists XBF_DONE; FUA hook only fires on cache-miss.
- **v0.3.66** — stripped P27/P26 (instrumentation was perturbing timing → CAW timeouts).
- **v0.3.67** — FUA hook extended to `xfs_inode_buf_ops` + `xfs_inode_buf_ra_ops` (inode cluster bufs), targeting Mode A dir/inode coherency.

Key findings: **most AG-meta reads hit cache, not the FUA hook** (P26 counts T1:65 vs T2:2241 — first-mounted node caches via bio and never re-reads). **bnobt corruption occurs during exclusive AG hold (intra-node)**: FUA-reading a cache-miss buf *while unflushed in-memory mods exist* replaces them with pre-modification disk state. `invalidate_ag_meta` during an open transaction is dangerous — staling a buf with an active BLI loses the trans's modifications at commit. Peer-joined invalidation is necessary but not sufficient (only stales bufs already in `pag_bcache`). **Unconditional pr_warn counters in hot paths (xfs_buf_submit) dramatically perturb timing** and shift failure modes (recurring lesson, re-confirmed from sess21). Peer-joined invalidation must run AFTER log_force+ail_push+blkdev_flush, never before.

Late sess22 claimed FUA verified cross-initiator via `tools/fua_verify.c` (both WRITE-FUA and READ-FUA see latest content, falsifying "FUA broken on LIO") and a "first 15/15 PASS at v0.3.78". **Both the PASS claim and the derived conclusions were later retracted — see sess23.**

## sess23 — the PASSes were a script bug; honest baseline ([[Sess23 lessons (script-bug + honest baseline)]])
The stress harness `/tmp/mxfs_stress_v033.sh` only grepped dmesg for corruption markers, cleared dmesg between runs, and **never checked whether dd/rm actually succeeded**. The "3× 15/15 PASS" runs were cases where test2's mount was already in shutdown state — every test2 dd hit EIO from iter 1, invisible to the dmesg-cleared check (T2_DD_OK=0 in all three "PASS" logs). **Discard from the record: the 3 PASS runs, "FUA architecture validated," and the 17% pass rate (that was the false-positive rate).**

Replacement harness (later `scripts/stress_session.sh`) **requires both T1_DD_OK and T2_DD_OK plus T1_RM_OK/T2_RM_OK per iter**, doesn't clear dmesg, and uses `date -u` for `journalctl --since` (test nodes run UTC; local shell may be CDT).

Honest **v0.3.82 = 0/3** (iter-1 test2 DLM inode timeout ino=128 rc=-110; iter-3 test1 DLM timeout ino=131; bnobt LEFT-FAIL). 
- **v0.3.83** = v0.3.82 + CAW slot-garbage fix. Root: GRANT-POLL captured slot 51123 with `hex=e0041d00e1000413`, popcount=16 in the EX bitmap — **stale-disk garbage from a prior FS because mkfs's pwrite-O_SYNC isn't durable on the LIO target**. Existing `slot_appears_corrupt` only checked granted_mode/waiter_mode, so garbage in the holders bitmaps blocked peer acquires forever. Fix in `dlm/dlm_caw.c`: also flag `popcount(holders_ex)>1 || popcount(holders_pw)>1 || granted_mode != recompute(holders)`; `caw_repair_slot` zeros invalid h_ex/h_pw (and h_pr if both invalid); added inline `mxfs_pal_popcount64`. This **closed the iter-1 DLM timeout family**; bnobt LEFT/RIGHT-FAIL became the dominant residual (v0.3.83 avg ~3.7 iters before failure vs 0 for v0.3.82).

v0.3.83 fires bnobt only under **drop_caches stress** (no-drop production-style workloads were release-quality at 15 iters; the "100% no-drop PASS" was a small-sample artifact — 30+ iters trips it regardless). P32-INSTR proved the `xfs_buf_stale`-on-BLI events fire **after** corruption (downstream of shutdown I/O failures), not the cause — corruption originates upstream in `xfs_alloc.c:2106` free_ag_extent before the stales. v0.3.84 fix attempts (return 0 from `xfs_fs_free_cached_objects`/`nr_cached_objects`; ail_push barrier in the shrinker) all caused dd hangs or broke reclaim — **all reverted, v0.3.84 == v0.3.83 in tree**.

New: **CAW slot infinite-repair loop** — post-wedge, a slot repairs >100×/s, CAS reporting success but next read showing identical corruption. Top hypothesis: **CAS reports success but doesn't persist** (LIO CAW/FUA or scsi_execute_cmd false-positive). Motivated writing `tools/caw_verify.c` (COMPARE AND WRITE opcode 0x89 is a distinct LIO code path from WRITE(16)/READ(16), so fua_verify doesn't cover it). Also: test2 rmmod-fail is transient (refcnt momentarily >0, drops within 60s) → `cluster_reset.sh` retries rmmod 8× with 10s sleeps.

## sess24 — smoking gun: cached-AG divergence; LIO CAW exonerated ([[Sess24 lessons (cached-AG divergence + ruled out LIO bug)]])
**Headline root cause of bnobt LEFT/RIGHT-FAIL: cached-AG state divergence.** P33-INSTR (in tree, `xfs/libxfs/xfs_alloc.c`) captured **both nodes simultaneously allocating overlapping ranges from the same AG** (run-1 iter4: test1 [24568..48008) + test2 [16392..91288) at AG=0). P35 confirmed neither node did a fresh-acquire on AG=0 — both used the `fast-cached` path with `pag_dlm_cached=true` simultaneously, for ~50s, with no BASTs exchanged.

Ruled OUT: **LIO target loses CAW writes** (sess23 hyp #1) — FALSE. `tools/caw_verify.c` (built standalone with gcc, not added to tools/Makefile) showed cross-initiator CAW-write + FUA-read work correctly both directions (0xAA/0x55). Also re-confirmed the sess23 `xfs_buf_stale`-on-BLI exoneration.

Failed fixes (all reverted): post-CAS FUA-verify in caw_slot (mount-time false positives); UDP BAST on claim-empty (strictly worse — run failed iter 3 vs iter 9); disabling the cached fast-path entirely (wedged inode-DLM in DEMOTING, needed reboot); bast_poll self-correction firing bast_cb on our_mode=NL (**failed iter 1 with Mode A**). **Critical: Mode A and bnobt LEFT/RIGHT-FAIL share the same root (silent cached divergence); any cache-invalidation fix triggers Mode A immediately because the upper-layer drain/release path is itself incorrect.** srcversion at end: `9A023439F613AE4B6120C26` (v0.3.83 + P33).

## sess25 — why the cache diverges: the single→multi transition bug ([[Sess25 lessons]])
Root cause of the divergence found. After a fresh reset, **test2 cannot see directories test1 created** (`ls` shows `d?????????`, cat ENOENT, zero BASTs post-mount). Mechanism: each node mounts in single_node mode taking the caw fast-path (`mem_lock_track`, in-memory only, no disk slot write) with cached `i_dlm_mode=EX`; on discovery, `mxfs_dlm_caw_set_single_node(false)` → `flush_held_to_disk` **unconditionally OR'd holder bits** into disk slots, so both nodes' EX bits coexist and the "already_held" check sees our own bit and returns success without conflict detection. `peer_joined_flush` flushed data + AG-meta but **never invalidated `i_dlm_mode` on inodes nor `pag_dlm_cached` on perags** — the divergent cache survived the transition (explains sess24's P35). Inode divergence self-heals via evictions; `pag_dlm_cached` for AG=0 never evicts, so AG divergence persists.

Implemented fixes (KEPT):
- **v0.3.86** — single→multi transition: `flush_held_to_disk` no longer ORs bits to disk (slots stay empty); `peer_joined_flush` walks each perag's `pag_ici_root` forcing `i_dlm_mode=NL / i_dlm_state=NONE / i_dlm_stale=true` on cached inodes (no holders, not demoting) and `pag_dlm_cached=false`. (Note: an *earlier* v0.3.86 "periodic-verify forced slow-path" REVERTED — crashed test2 xfsaild at exit.c:821 because `invalidate_ag_meta` is destructive when we legitimately hold the grant.)
- **v0.3.87** — `mxfs_dlm_reload_inode` now `i_size_write(VFS_I(ip), ip->i_disk_size)` after `xfs_inode_from_disk`; without it VFS `inode->i_size` stayed stale → truncated reads. → **cross-node read-after-write and dir visibility now WORK** (first real coordination).
- **v0.3.84** (dir-block stale in bast path) + **v0.3.85** (caw already_held `compatible_excluding_self` check) KEPT as defensive; P36/P37 fire zero times in stress (root dir stays LOCAL format; divergence isn't both-bits-set).
- **v0.3.88** — Mode A fix: dcache invalidation in reload_inode (`d_find_alias → shrink_dcache_parent → dput`). Mode A root: peer-modified dir reloaded into xfs ip but VFS dcache stayed stale → `rm` hits stale child dentry → removename on now-empty dir → ENOENT. After fix Mode A no longer fires.
- **v0.3.95** — bnobt partial fix. Root: `xfs_log_force(SYNC)` returns BEFORE `xlog_ioend_work` (on `l_ioend_workqueue`) runs `xlog_cil_committed→xlog_cil_ail_insert`; drain in that gap misses still-in-CIL items → peer reads stale. Fix: `msleep(3)+xfs_log_force(SYNC)` before `drain_meta_buffers` in `mxfs_dlm_ag_bast_work_fn` Phase-2. Empirical, variance remains.
- **v0.3.99** — force-clear `bp->b_flags &= ~XBF_DONE` after `xfs_buf_stale` in `invalidate_ag_meta` (stale only sets XBF_STALE, leaving XBF_DONE → buf reused without re-read).

Didn't work (reverted): v0.3.96 flush_workqueue, v0.3.97 polling drain, v0.3.93 force-drain-all-XBF_DONE (iunlink corruption), v0.3.89-92 BLI/FUA skip variants (P42 0×). New failure mode at end: **15×512 both nodes fdatasync CAW-timeout simultaneously at iter 3** — a genuine cluster deadlock exposed only because coordination now actually works. 5×64/5×128 PASS 5/5; 5×256 fails iter 3.

## sess26 — two root causes; kernel SCSI CAW is broken ([[sess26_lessons]])
Concluded the bnobt family has **two independent root causes**:
1. **FIXED, v0.3.106**: `xfs_trans_dup` doesn't migrate `t_mxfs_ag_unlocks` to the new tp; trans_free of the old tp drains pendings → releases AG-DLM mid-defer-chain; peer mutates bnobt; new tp's defer items process a stale view → corruption. Fix: `list_splice_init(&tp->t_mxfs_ag_unlocks, &ntp->t_mxfs_ag_unlocks)`. **Do NOT migrate `t_mxfs_inode_unlocks`** (causes peer ETIMEDOUT on ilock(ino=128,EX) at remount). P47-INSTR fired ~70× in a 70s run confirming the mechanism. **Do not revert v0.3.106.**
2. **OPEN**: **in-kernel SCSI CAW on this LIO target under sustained stress reports CAS-success without persisting the write.** P49-INSTR: post-CAS FUA-readback shows the slot still holds pre-CAS content (`v_magic=0xa29380 v_our_mode=4 expected=5`), deterministic across retries. v0.3.107 retry-on-divergence → infinite loop (target keeps reporting success). P51 (sense data): CAW always returns ret==0, GOOD status, no sense — not a missed MISCOMPARE.

Bisect proof: **single-node 15×256 PASSES 15/15** — local XFS/buffer-cache/defer-chain are clean; the bug is exclusively cross-node. Experiment 1 sha256-matched T1-in-memory == T1-disk == T2-disk bnobt at fail, falsifying all remaining "stale buffer / read-coherency" hypotheses. Crucially, **`caw_verify` userspace SG_IO under concurrent dual-writer load PASSES (zero divergence) — the LIO target is correct; the bug is in the in-kernel `scsi_execute_cmd` CAW passthrough**, distinct from the SG_IO ioctl path.

Didn't work for RC#2: global mutex / 16-bucket LBA mutexes around `bdev_compare_and_write` (inode-DLM ETIMEDOUT), blkdev_issue_flush after CAS (degradation), retries=0, DEADBEEF poison prefill (read confirmed fine), P53 pre/post buffer compare (write data not mutated). 

Final builds: **v0.3.108** srcversion `7C4289EA87BE01A8286E108`; **v0.3.109** srcversion `6E8D09629680A3B131EB8F4` (disables P49 verify-read in production via `if(0 && ...)` in dlm_caw.c to halve SCSI command count — flip to 1 for diagnostics). Pass rate highly variable (one 9/10 batch then 0/5 all bnobt LEFT-FAIL); **disk-state contamination is real** — after a failing batch the corrupted on-disk state isn't durably zeroed by mkfs's pwrite-O_SYNC and poisons later runs.

Sess27 suggested path: (a) **try TCP DLM transport** to sidestep kernel CAW (needs porting to v5_mount.c, currently CAW-only); (b) investigate kernel `scsi_execute_cmd` vs SG_IO differences; (c) slot-collision — `find_slot` linear probe may select an empty slot holding prior-session/inode-DLM data, and in some race the CAS doesn't take (add P52 to log resource-type/slot combos); (d) durably WRITE-FUA-zero the disklock region at mkfs.

## Durable cross-session lessons
- **Never trust a stress PASS verdict without T1_DD_OK + T2_DD_OK marker counts** — dmesg-only checks yield false positives.
- **Any pr_warn in hot paths (xfs_buf_submit, CAW poll) shifts timing and hides/changes the race.** Strip diagnostics before drawing perf/pass conclusions.
- **Test nodes are UTC**; use `date -u` for `journalctl --since`.
- **Mode A and bnobt LEFT/RIGHT-FAIL share a root** (cached divergence); a cache-invalidation fix must handle both or it just converts one into the other, and it must drain before invalidating or it crashes xfsaild.
- **`invalidate_ag_meta` is destructive while we hold the grant** — only safe after Phase-2 drain.
- **mkfs pwrite-O_SYNC zero is NOT durable on this LIO target** — stale-disk slot garbage and post-fail contamination recur; account for it.
- CAW/FUA transport is correct at userspace (fua_verify, caw_verify); doubt lives above the buffer cache and in the in-kernel SCSI passthrough, not in the LIO target.
