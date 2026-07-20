---
name: sess90_lessons
description: "sess90 — PROBE-A refuted xfsaild AG-meta clobber; unlink_visibility ENOTDIR root = reader-side inode-REUSE stale cache (P90-PICK proves single-node-per-AG alloc, NOT allocator double-alloc); two gen signatures (off-by-one=reuse, same-gen=cluster stale-flush clobber d_revalidate can't catch)"
metadata: 
  node_type: memory
  type: project
  originSessionId: 775f2647-7c8f-47db-a885-434390a59dc5
---

# sess90 (2026-06-05, ccloop run 29df431e)

Criterion `cache_coherency` still FAIL (one run passed=2 failed=2: unlink_visibility + cross_write_read; a later run with extra probe hung at 580s = barrier-stall variance). Marker NOT written.

## REFUTED this session (decisive)
- **PROBE-A did NOT fire on any node.** Build `0BC933EE` deployed to all 4; cache_coherency run; `dmesg | grep PROBE-A` = 0 everywhere. PROBE-A traps any AG-meta buffer WRITE in xfs_buf_submit while the node does NOT hold the AG. Zero hits ⇒ **kills the sess89/Gemini "post-release xfsaild CIL→AIL bnobt clobber via bast_work_fn handoff" theory.** No node writes AG-meta while not holding the AG. (Also: that run had NO shutdown at all — the bnobt double-free shutdown did not reproduce.)

## PROVEN this session
- **unlink_visibility ENOTDIR root** = node4's PARENT dir inode flips DIR→REG mid-test. node4 creates `unlink_visibility/node4_file1` OK, then file2..30 + all deletes fail `Not a directory`. P-RELOAD-TYPEFLIP fired: `ino=2097285 incore_mode=040755(DIR) disk_mode=0100644(REG)`. Path resolution of children of a now-REG inode → ENOTDIR.
- **NOT allocator double-allocation.** Added always-on probe **P90-PICK** (xfs_ialloc.c xfs_dialloc after `*new_ino=ino`, build `92A8E01B`): logs `slot=<node_slot> ino agno ifmt parent` on every multi-node alloc. Grep of ino=135/136 (AG0) across all 4 nodes ⇒ **ONLY test1/slot0 ever picks them.** Allocation is single-node-per-AG (node-affine `node_slot % m_maxagi` holds for ALLOCATION). So the conflict is **reader-side cross-node CACHE staleness**, not the allocator handing one ino to two nodes. Slots: test1=0, test2=3, test3=1, test4=2 (unique, no all-same-slot bug). Geometry: 20GB dev → ~20 AGs (agino field=21 bits, AG=2097152 inodes); affine AGs 0-3, AG4-19 = spill; nodes spill far (test4 slot2 allocated in AG8) when affine AG peer-held/full.
- **TWO TYPEFLIP gen signatures** (both = reader serving a stale cached incarnation of a number the OWNER reused/rewrote):
  1. **off-by-one** (incore_gen=...949 / disk_gen=...950, ino=135 AG0): legitimate inode REUSE by owner test1 (free→realloc bumps gen +1); peers test2/test3 hold stale cached incarnation → reload flips type. d_revalidate's FUA gen-check (sess86) SHOULD catch this (gens differ) — but ENOTDIR persists, so either it isn't firing on the parent-dir dentry path or eviction doesn't complete.
  2. **same-gen** (incore_gen==disk_gen=400696095, ino=2097285 AG1): type differs with IDENTICAL gen ⇒ **sess86 d_revalidate gen-only check CANNOT catch it.** Consistent with inode-CLUSTER stale-flush clobber (sess44 P97 INODE-CLUSTER-CLOBBER): a node flushes a stale 16KB cluster buffer carrying an OLD REG incarnation of the inode (same gen) over the owner's new DIR.

## Fix gap (for next step / Gemini)
Existing defenses all compare GEN: sess86 mxfs_drevalidate FUA di_gen vs incore (pal/linux/xfs_super.c), sess48 ftype-mismatch evict in xfs_lookup, sess87 reload snapshot-validate. The **same-gen type-mismatch slips through every gen check**, and the parent-dir dentry may not hit d_revalidate. Need: (a) TYPE-aware (not just gen) staleness trap on the parent-dir lookup path; AND/OR (b) stop the inode-cluster stale-flush that produces same-gen DIR→REG (durable-flush ordering on inode-cluster buffers, or invalidate-before-flush). This is the 9+-session cross-node inode/inode-cluster coherency wall (sess44/46/48/52/54/80/86/87/88).

## ROOT CONFIRMED (Gemini RULE-5 + decisive probe) — THE fix for next session
**mxfs FUA-reads buffers that carry LOGGED-but-not-yet-checkpointed modifications, clobbering them with stale disk content** = the lost-update family (inode-cluster clobber AND bnobt lost-removal → double-free shutdown).
- Gemini mechanism (matches all evidence): read-time hook clears XBF_DONE on a clean gen-lagging buf; buf gets modified+logged; a later re-read (post `xfs_trans_roll`, gen advanced) sees XBF_DONE/!_XBF_FUA_FRESH and FUA-reads disk into `bp->b_addr`, DMA-obliterating the uncheckpointed change. cntbt survives, bnobt reverts → btrees diverge → block 24 double-allocated → inactivation double-frees → `ltbno+ltlen>bno` xfs_alloc.c:2244 SHUTDOWN.
- **PROVEN**: decisive probe `P90-FUA-OVER-LOGGED` (pal/linux/xfs_buf.c in `mxfs_buf_read_fua` just before `mxfs_pal_scsi_read_fua_bdev(...,bp->b_addr,...)`) — traps FUA read when `b_pin_count>0 || !list_empty(&b_li_list) || b_log_item`. **FIRED 7× on the node that shut down (test1)**, build `D1E532E2`. Details: `ops=xfs_inode daddr=128/4174768/2087448/6262088 pin=0 li_empty=0(=HAS log items) has_bli=0 bflags=0x1(XBF_READ) comm=rm/mv`. daddr=128 = inode-cluster holding ino 136. Explains P81-DEXT (disk inode 136 → 0 extents). (Buffers seen were xfs_inode clusters; the bnobt instance is the same bug class on the AG-meta path.)
- **REFUTED this session** (don't rechase): sess89 post-release xfsaild clobber (PROBE-A 0×); my invalidation-DISCARD-of-in-core-ahead (P90-DISCARD-LOSTUPD 0× — discard checks at CLEAR time when buf still==disk; loss is at the LATER re-read); frozen-gen (gen=5).

## FIX TO IMPLEMENT NEXT SESSION (Gemini)
Guard the FUA read (and ideally the XBF_DONE-clear hook): **NEVER FUA-read / clear XBF_DONE on a buffer that is PINNED or has LOG ITEMS (`!list_empty(&bp->b_li_list) || b_log_item || b_pin_count>0`)** — that buffer holds this node's authoritative uncheckpointed change; keep in-core, treat as fresh.
1. Minimal: in `mxfs_buf_read_fua` (pal/linux/xfs_buf.c ~L1518) at entry, if pinned/logged → `return -EOPNOTSUPP`/skip (do NOT overwrite b_addr); and in `xfs_buf_submit`'s FUA-needs gate `mxfs_buf_needs_fua_read`, return false for pinned/logged bufs. Convert the P90-FUA-OVER-LOGGED probe into this guard.
2. Gemini also: the invalidation hook's rule "preserve dirty/pinned/in_AIL but leave gen-lagging (don't stamp)" is a time-bomb — once xfsaild cleans it, next read re-stales+clobbers. **STAMP preserved bufs** with pag_dlm_meta_gen (they're this-node-authoritative). (xfs_mxfs_dlm.c skip branch ~L3669.)
3. Architectural alt: move gen-check into buffer-GET (after lock, before return), synchronously FUA-read THEN + set XBF_DONE; OR on AG-acquire xfs_buf_stale() all clean cached AG-meta bufs (atomic-at-acquire instead of lazy per-block). 
After fix: re-run cache_coherency; confirm shutdown gone + P90-FUA-OVER-LOGGED 0×. Then the TYPEFLIP-STALE-SKIP (below) handles residual reader type-flips.

## Probes added (KEEP, both always-on cheap)
- **P90-PICK** (xfs/libxfs/xfs_ialloc.c ~L2182): per-alloc slot/ino/agno/ifmt/parent. Decisive for same-vs-cross-node alloc.
- **PROBE-A** (pal/linux/xfs_buf.c, from sess89): AG-meta write while not holding AG. Refuted the clobber theory — could remove but harmless.

## Build/infra
- Current build `D1E532E2` (on all 4 nodes) = PROBE-A + P90-PICK + **TYPEFLIP-STALE-SKIP fix** (xfs_mxfs_dlm.c mxfs_dlm_reload_inode ~L1989: refuse a reload that flips S_IFMT unless `disk_gen > incore_gen` — mxfs bumps gen +1 on reuse, so a same/older-gen type-flip = stale/corrupt disk; keep authoritative in-core. Reader-side defense for unlink_visibility ENOTDIR, KEEP) + P90-DISCARD-LOSTUPD probe + P90-FUA-OVER-LOGGED probe. cache_coherency still passed=1 failed=3 — the SHUTDOWN (FUA-over-logged) dominates & cascades (test1 dies → barrier timeouts fail the rest); fix the shutdown FIRST.
- Earlier builds: `670086DC`=+TYPEFLIP fix; `92A8E01B`=`0BC933EE`(PROBE-A)+P90-PICK.
- NFS `/mnt/mxfs-src` (192.168.120.1:/src/mxfs) DROPS on node reboot — remount per node before reset4. test3 wedged at session start (pinged, SSH hung) → `virsh -c qemu:///system destroy/start test3` + remount NFS.
- cache_coherency hangs sometimes at 580s (barrier 120s stalls) — re-run; not always reproducible. After a killed run, nodes left half-unmounted → `bash tests/reset4.sh 4` to clean.
