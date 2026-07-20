---
name: sess30-WIN-4tcp-17of17-soak-fixed-by-P30-ops-recover
description: sess30(ccloop) WIN: 4/tcp = 17/17 (build 04A615EE + winning modargs). soak FIXED by P30 ops-recover (re-derive verifier from magic when b_ops==NULL).…
metadata:
  type: project
---

## sess30 WIN — 4/tcp = 17/17

Build **04A615EE** + modargs `dir_gen_per_handoff=1 dir_modify_extent_adopt=1 dir_release_invalidate=1 dir_relinval_clean=1`:
FULL `./run.sh 4 tcp` (via tests/tcp/full8.sh 4) = **17 PASS / 0 FAIL**. ALL tests including dir_reuse_coherency 4/4, crash_consistency 4/4, soak, fence, fault, tcp_dlm_scaling.

### soak FIX confirmed = P30-OPS-RECOVER (pal/linux/xfs_buf.c)
soak failed at 4/tcp on build F449AACE because a rare `xfs_buf_verify_write: no buf ops on daddr` (inode buffer, mxfs reload/FUA left b_ops==NULL, xfsaild delwri-flush) did `dump_stack()` → soak's DPAT `call trace` → FAIL. The new `mxfs_buf_ops_from_magic()` re-derives the verifier from the on-disk magic (AGI/AGF/AGFL/inode/bnobt/cntbt/inobt/finobt/bmbt/dir3-block/data/free) and runs verify_write (stamps CRC) instead of warn+dump_stack. soak now PASS.

### Criteria status (`./run.sh {1,2,4,8} tcp` 100%):
- 4/tcp = **17/17** ✓ (this build+modargs)
- 1/tcp, 2/tcp: verifying (expected pass — lighter load)
- 8/tcp: still blocked by dir_reuse_coherency 0/8 (AGI-CRC shutdown flaky-face + readdir=0/dir-missing face) — see [[sess30-HEAD-crashconsist-fixed-soak-P30fix-dirreuse-readdir0-parent-dirent]].

### TODO before a bare-run.sh criteria check: make the 4 levers MODULE DEFAULTS (currently default-0, passed via MXFS_EXTRA_MODARGS). Validated at 4/8 nodes extensively.
See [[sess30-FIX-crashconsist-ABBA-flush-snapshot-relsafe]].
