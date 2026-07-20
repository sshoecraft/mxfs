---
name: caw-16node-dlm_scaling-FIX-private-ex-fua-skip
description: 16/caw dlm_scaling FIXED (ccloop 0d6e174d, build 98D240B3): dir_priv_ex_skip=1 skips dir-FUA for EX-held never-BAST'd dirs → PASS 16/16. Regression c…
metadata:
  type: project
---

## 16/caw dlm_scaling — FIXED (ccloop 0d6e174d, 2026-07-06, build 98D240B3 from D8BEF5A5)

Root proven in [[caw-16node-dlm_scaling-ROOT-PROVEN-private-dir-fua-storm]]: ~5000 coherency-
UNNECESSARY SCSI-FUA reads/node of each node's OWN private dir block (daddr=72), sinking the
op-rate under the 50/s floor at 16 nodes.

### THE FIX (build 98D240B3, param `dir_priv_ex_skip` default 1)
New "provably private" signal: `i_dlm_mode==MXFS_LOCK_EX && !i_dlm_dir_contended`. MXFS caches
the inode DLM lock — a dir EX releases to NL ONLY on a peer BAST (which sets the sticky
i_dlm_dir_contended, xfs_mxfs_dlm.c:13142) or on eviction (resets flag + fresh reload at next
acquire). No idle/per-op release. So EX && !contended ⟹ held continuously since a fresh acquire,
zero peer contention ⟹ no peer could have modified the blocks ⟹ cached image authoritative.
Strictly STRONGER than the bare `i_dlm_mode==EX` that xfs_da_btree.c:3081-3088 rejected: that
reject case ("released on a peer BAST, re-acquired after a peer modify") SETS i_dlm_dir_contended
and is therefore excluded. The NL-window peer-modify case is handled BEFORE the skip engages by
the acquire-reload staling + the owned_ex-INDEPENDENT honor hook (xfs_da_btree.c:3228).

Applied at BOTH dir-FUA sources, same gate:
1. `xfs_da_read_buf` owned_ex (xfs/libxfs/xfs_da_btree.c ~3090): broadened from `i_dlm_unpublished`
   to `unpublished || (priv_ex_skip && EX && !contended)`. owned_ex gates the invalidate block at
   :3473 so the buffer stays DONE → cache hit → no cold re-read → no xfs_buf FUA gate.
   NOTE: needed `#include "../dlm/v5_mount.h"` for enum mxfs_lock_mode (MXFS_LOCK_EX) — da_btree.c
   didn't have it (dir2_data.c did).
2. `mxfs_dir_addname_coherent_refresh` (xfs/libxfs/xfs_dir2_data.c ~2087): early `return 0` for the
   private-EX case — skips the per-addname FUA-platter compare (the 2nd, uncounted FUA source).
Param declared xfs/xfs_mxfs_dlm.c after dir_unpub_skip (~9710): `int mxfs_dir_priv_ex_skip = 1;`.

### RESULT
`MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS="dirwr=1 dirland=1" ./run.sh 16 caw dlm_scaling`
→ **PASS 16/16**. Mechanism confirmed: test5 clean run-D FUA-COUNT `total=256 dir=1 agm=243`
(dir FUA 5859→1). test1/test8 did <256 total FUA so emitted no new FUA-COUNT line (their tail
shows a STALE old-build 5888 line — cross-run dmesg accumulation, not a non-fix).

### STILL TODO before marker
1. **Regression check (CRITICAL)** — the fix touches the fragile dir-coherency path. Must confirm
   cache_coherency / posix_multi / strong_consistency / mmap_coherency / zero_silent_loss still
   PASS 16/16 (those SHARE dirs → contended=true → skip does NOT engage → expected no change).
2. **dir_reuse_coherency 16/caw** — SEPARATE root (EIO on node3/4 md5, test1 "no-result readdir
   0/1600"). Was failing BEFORE this fix. Still needs its own fix.
3. Then full 16/caw suite on 98D240B3, then 32/caw, then re-run 1/2/4/8 on the SAME build → marker.
4. A/B available: `dir_priv_ex_skip=0` reverts to old behavior.
</body>
