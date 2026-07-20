---
name: sess50-phantom-ex-waiter-recompute-rootfix
description: sess50 (run14d): PROVEN+VERIFIED fix for phantom-EX-waiter wedge — recompute_waiter_mode couldn't downgrade EX; added waiters_ex bitmap (build 5276B1…
metadata:
  type: project
---

# sess50 (ccloop 14d31183) — phantom-EX-waiter wedge ROOT FIXED + VERIFIED

Build `5276B108E3284AEC8E85A95` (VERSION 0.5.7). dlm/dlm_caw.c + dlm/dlm_caw.h. **PROVEN + VERIFIED.**

## State at start
Only `posix_semantics_multi16` FAILs (18/19 PASS per .criteria_results.json). Cluster phase (`run_tests.sh --phase cluster`, 16 nodes) WEDGED on the **first** test test_concurrent_mkdir (>580s, no completion). NOTE: the ccloop resume-doc framing (cross_write_read dirent loss, build ABD1F70) was a sub-issue; ccmemory + .criteria_results.json are authoritative.

## ROOT (RULE 4 2b — field + code evidence converge)
- Field (live wedge, ABD1F70): all D-state threads were `find` PR readers in `mxfs_dlm_ilock_begin`←xfs_readdir; ZERO EX requesters in any stack on any node. Barrier dir `ino=8388738` slot frozen `waiter_mode=5(EX) waiters=2 h_ex=0 h_pr=...` — a leaked EX-waiter bit, no live owner. `defer_for_waiter` (dlm_caw.c ~1865) defers every fresh PR/CR/CW acquire while `waiter_mode==EX && other waiters set` → total reader wedge.
- Code: `recompute_waiter_mode()` (dlm_caw.c:232) returned `slot->waiter_mode` UNCHANGED whenever `waiters != 0` ("we don't track per-waiter modes on disk"). So when the EX waiter's bit cleared but PR waiters remained (`waiters` still nonzero), waiter_mode stayed sticky-EX forever. sess48's `caw_drop_own_waiter` cleared the bit correctly but recompute defeated it.

## THE FIX
Added `uint64_t waiters_ex` (bitmap of nodes waiting for EX/PW) to the on-disk slot, carved from `reserved[392]→[384]` (512B `_Static_assert` still passes; fresh mkfs each run = no migration). 
- `recompute_waiter_mode`: `waiters==0→NL; (waiters_ex & waiters)→EX; else→PR`. Now DOWNGRADES.
- Set `waiters_ex |= node_bit` at both waiter-register sites (mode==EX||PW): dlm_caw.c ~2138 (lock) + ~2594 (convert/upgrade).
- Clear `waiters_ex &= ~bit` at ALL 5 clear sites: caw_drop_own_waiter (~963), waiter→holder promote (~1079), release (~2744 node_bit), dead-node cleanup (~2880 dead_bit, ~3053 dead_mask).
- Repair path: waiters_ex zeroed by existing memset(0) base — no edit.
- Added `waiters_ex=%llx` to SESS50-STARVE log for field verification.

## VERIFIED (build 5276B108, fresh 16-node cluster via cluster_reset_n.sh 16 + reset4.sh 16 + bind mount /mnt/mxfs-src)
`POSIX_PHASE=cluster posix_phase_timing.sh --nodes 16`: test_concurrent_mkdir 22s PASS (was >580s wedge), concurrent_touch 30s, concurrent_write 15s, cross_visibility 7s — all PASS. Wedge GONE.

## REMAINING BLOCKER (next)
`test_cross_write_read` FAILs: "1 failure in 18 assertions" on all 16 nodes, and SLOW (~246s — vs 7-30s for the others; RULE 0 slowness is itself a fail). This is the session-49 residual dir/data lost-update. Next: read tests/cluster/test_cross_write_read.sh, identify which of 18 assertions fails, get per-node logs. Prior dir-clobber roots: [[sess48-phantom-ex-waiter-bit-leak-rootfix]], mxfs_iflush_cluster_merge_dirs (xfs_inode.c:4332, P133/sess61 co-resident cluster-buffer stale dir overlay).
