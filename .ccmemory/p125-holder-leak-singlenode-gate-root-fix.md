---
name: p125-holder-leak-singlenode-gate-root-fix
description: P125 CLOSED v0.11.81: ilock_end's !dlm/single-node early-returns skipped the holder decrement for multi-era begins — leaked counts block reclaim gate…
metadata:
  type: project
tags: [p125, holder-leak, ilock_end, single-node-gate, rule4-proven, ccloop-c7ee71c6]
---

# P125-EVICT-SUSPECT root cause + fix (v0.11.81, ccloop c7ee71c6 sess1)

## Deterministic repro (VM 2/tcp)
Converged 2-node → `virsh destroy` peer → survivor `touch /mnt/shared/x` (blocks ~41-65s: 19-20s settle gate + remote retries to the dead master until 40s death) → `umount` → `P125-EVICT-SUSPECT ino=128 ex=1` (or `pr=1` — flavor depends on which begin was in flight). 2/2 pre-fix, 0/2 post-fix.

## Root cause (RULE-4 ring-proven)
Extended the `mxfs_dlmtr` watch-ino ring with ex/pr holder counts + annotated every holder mutation (`MXFS_DLMTR_H`); ring on ino=128 showed: PR begin/end pairs balanced (L23527→L23691), then the create's EX begin blocked through the peer death, granted at +65s (`L23524 ex 0→1`) — and NO decrement ever. **`mxfs_dlm_ilock_end` early-returned on `mxfs_v5_dlm_is_single_node()`** (membership had collapsed to 1 by unlock time) — same hazard for the `!dlm` gate at umount. Begin incremented in the multi-node era; end skipped the decrement.
**Blast radius**: leaked `i_dlm_ex/pr_holders` block the reclaim gates (`ex_holders>0` checks in xfs_mxfs_dlm.c ~12648/14784) → the busy-inodes-after-unmount / slab-leak / VFS_BUG_ON(I_FREEING) teardown family that P125 was originally hunting (old dialloc-era builds panicked on rmmod via a zombie mxfs-worker after this class of teardown damage).

## Fix (v0.11.81)
`ilock_end`: holder bookkeeping (stamp + guarded decrement) now runs UNCONDITIONALLY (needs only the inode); the `!dlm`/single-node returns moved AFTER it (they still gate the multi-node machinery: BAST fire, flush arming). P71-UNDERFLOW prints gated on multi-node (a single-node/torn-down unpaired end is EXPECTED — begin's bypass never incremented; the guarded no-op decrement absorbs it silently).
Kept in-tree: ring records holder counts (`exh/prh` in P12-DLMTR), P125 prints `exh_pid/exh_comm/exh_age_ms` and auto-dumps the ring when `mxfs.watch_ino` matches.

## Verification
- Repro ×2 post-fix: P125=0, P71-UNDERFLOW=0, touch+umount clean.
- Suite subset green: cache_coherency 534, posix_multi, dlm_membership, crash 104, dir_reuse 170, fence, soak.

## Mirror case (audited, safe)
Begin in single-node era (bypass, no increment) → membership grows → end decrements... guarded `>0` no-op + no print. Begin's shutdown-fence unpaired ends likewise absorbed.
