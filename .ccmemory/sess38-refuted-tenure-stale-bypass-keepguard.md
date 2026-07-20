---
name: sess38-refuted-tenure-stale-bypass-keepguard
description: sess38: dir_tenure_stale_bypass=1 (bypass in_ail-undestaged keep-guard for tenure_stale reads) REFUTED — round-21 loss + 11 shutdowns. Keep-guard mus…
metadata:
  type: project
---

## sess38 — REFUTED: bypassing the read-path in_ail-undestaged keep-guard for tenure_stale buffers.

Added lever `dir_tenure_stale_bypass` (xfs_da_btree.c ~3413 + xfs_mxfs_dlm.c, default 0): when set (with dir_tenure_evict=1), a read-path `tenure_stale` buffer (b_mxfs_dir_epoch < MASTER dir epoch) ALSO bypasses the `!in_ail || !undestaged` keep-guard and is invalidated+re-read. Hypothesis: dir_tenure_evict's residual ~1/3 readdir=799 is a prior-tenure stale base preserved by the keep-guard because it's in_ail-undestaged.

**RESULT: REFUTED** (build 08DE37FD, dir_tenure_evict=1 dir_tenure_stale_bypass=1, 24 rounds): FAIL — round 21 readdir=799 (still lost a dirent) THEN cascade to readdir=0 + **11 Metadata-CRC shutdowns**. So bypassing the keep-guard (a) did NOT prevent the loss and (b) ADDED shutdowns — exactly the harm the keep-guard comment + the parallel epoch_stale-bypass ("suspected shutdown source") warned about. The in_ail-undestaged keep-guard MUST be honored; you cannot distinguish "my un-landed work" from "a stale base that looks un-landed" by clearing it on a flag heuristic.

**Implication:** the read-side cannot safely refresh an in_ail-undestaged stale base by invalidation. GPT's deeper point stands: the reliable signal is the DLM grant/LVB sequence, and the fix likely needs the master epoch to advance reliably (so the stale base is caught BEFORE it becomes in_ail this tenure) OR the release-side to guarantee the base is durable+clean at re-acquire. Lever left default-off. dir_tenure_evict=1 alone (0%→67%) is still the best lead. See [[sess38-HEAD-handoff]].
</body>
