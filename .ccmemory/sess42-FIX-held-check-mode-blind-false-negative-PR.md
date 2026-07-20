---
name: sess42-FIX-held-check-mode-blind-false-negative-PR
description: sess42 VERIFIED FIX (build E8C6B4B6): mxfs_v5_dlm_inode_held was mode-blind (>=EX), false-negatived valid PR → P108 spurious-demote storm + 65s dir_r…
metadata:
  type: project
---

## sess42 VERIFIED FIX — DLM held-check was mode-blind, false-negatived PR holds → 65s dir_reuse stall

### ROOT (proven by code + log + before/after test)
`mxfs_v5_dlm_inode_held(ctx, ino)` (dlm/v5_mount.c) hardcoded `mxfs_dlm_held_mode(...) >= MXFS_LOCK_EX ? 1 : 0`. But the P108 phantom-lock verify (xfs/xfs_mxfs_dlm.c ~8250) uses it to validate **PR** cache-hits too (`i_dlm_mode==PR && mode==PR`). For a legitimately-held PR lock, held_mode=PR(3) < EX(5) → returns **0 (false-negative)** → P108 demotes the valid PR and forces slow-path re-acquire. BOTH nodes thrashed PR re-acquires on the SHORTFORM PARENT dir (ino=128, the dir CONTAINING `.dir_reuse_coherency`), starving node1's mkdir/rm EX-acquire → `P36-RETRY ino=128 mode=PR retries_left=59..0` storm (~60×1s = the **65s round-N verify stall** seen right before the round-N+1 data loss). Log smoking gun: `P108-REACQUIRE ino=128 cached_mode=3 req=3` on BOTH nodes (cached_mode=3=PR).

### NOTE on errnos: `DLM inode lock failed rc=-35` is **-EDEADLK** (35), NOT -EAGAIN(11). It's the ABBA deadlock-avoidance path (handled by the BAST-drain-and-retry orchestration @ xfs_mxfs_dlm.c ~9043; routes through the drain, does NOT skip Invariant 1). mxfs_dlm_lock returns -EAGAIN(-11) only after exhausting the 60-retry -ETIMEDOUT budget (dlm/dlm.c:1461).

### FIX (build E8C6B4B6): added `mxfs_v5_dlm_inode_held_rawmode(ctx,ino)` (returns raw NL/PR/EX from mirror; CAW held→EX). `mxfs_v5_dlm_inode_held` now delegates `>=EX`. P108 (xfs_mxfs_dlm.c ~8255) computes `p108_held = (raw >= ip->i_dlm_mode)` — phantom iff hold < cached mode. Logs `held_raw=%u` so residual fires reveal real phantoms (held=NL).

### RESULT (capture, deployed E8C6B4B6, dir_reuse 2/tcp): P36-RETRY=0 (was 60×/round). P108-REACQUIRE new-format fires = **0** (was hundreds; ALL prior churn was the false-negative). Test ran ~293s = normal time, **NO 65s stall**. → STALL FIXED. KEEP.

### BUT data loss PERSISTS (separate root → see [[sess42-ROOT-dir-block0-divergent-alloc-dinode-not-durable]]): round-N node1_f1..f14 (block0) still lost. Other held-check callers (P135/5893, tcpex/8304, P106/8791) are all EX-intent — left on `>=EX` (correct).
</body>
