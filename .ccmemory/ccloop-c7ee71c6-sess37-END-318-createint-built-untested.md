---
name: ccloop-c7ee71c6-sess37-END-318-createint-built-untested
description: sess37 END: 0.11.318 (2E2DD3DB) CREATEINT BUILT NOT DEPLOYED/TESTED — next: prep 32, instr-window verify (rc=-35→0, single EX/wave), dir_reuse ×3 (≥9…
metadata:
  type: project
---

# sess37 END — relay boundary state

## 0.11.318 srcversion 2E2DD3DB4087301C773DD73 — BUILT, NOT DEPLOYED, NOT TESTED
CREATEINT implemented per the sketch (memory ...createint-implementation-sketch):
- xfs_inode.h: XFS_ILOCK_MXFS_CREATEINT (1u<<7) + xfs_lookup signature +create_intent.
- xfs_inode.c: #include <linux/hashtable.h>; task registry (mxfs_createint_ent/enter/exit/active) placed ABOVE xfs_ilock_data_map_shared (order matters — first build broke on use-before-def); lock_flags_assert tolerance (CREATEINT valid with ILOCK shared|excl); xfs_ilock + xfs_iunlock arms AFTER the PRIREAD arm (CREATEINT wins, both sides mirrored); data_map_shared consults registry once per dir lookup (gated mxfs_create_intent_ex && m_mxfs_dlm && S_ISDIR); xfs_lookup arms around consumer_refresh+xfs_dir_lookup ONLY, disarms immediately after (iget must not inherit).
- pal/linux/xfs_iops.c: +#include <linux/namei.h>; vn_lookup + vn_ci_lookup pass (flags & (LOOKUP_CREATE|LOOKUP_EXCL)).
- pal/linux/xfs_export.c: dotdot lookup passes false.
- pal/linux/xfs_aops.c: knob mxfs.create_intent_ex (int, 0644, default 1).

## NEXT SESSION exact sequence
1. MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster (deploys 318).
2. instr=1 on test5/test12, one dir_reuse lap: expect in create windows: 'DLM inode lock failed ... rc=-35' count → 0; GRANT-WAIT-START on dir per wave: PR,PR,PR→EX,PR,PR→EX becomes ~one EX (mode=5) per wave; knob A/B (create_intent_ex=0 restores old shape).
3. dir_reuse ×3 — target ≥9 rounds (margin, not just floor 8; 317 got exactly 8 once).
4. Full 32-board (create path is hot in EVERY test — cache_coherency/crash/zsl especially). Watch: O_CREAT-on-existing now takes dir EX (rename/open-existing heavy tests). If any regression: knob off first.
5. Then ledger updates for the pace family; then the AUTHORITY family (3 entries, untouched since sess33-36): D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, D-FOREIGN-REPLAY-UNGATED-IMAGES, D-RELEASE-BARRIER-OPEN — read their ledger entries + sess32/33 memories first.

## Cluster/tree state at boundary
- Cluster runs 317 (7EEBFAFD) prepped 32/caw, board 20/21 on it, dir_reuse got its FIRST PASS (58/58, exactly 8 rounds) then the campaign continued.
- Tree: 318 built; VERSION=0.11.318; CHANGELOG through 318; all sess37 records complete (5 earlier memories, ledger, awareness docs incl. pal.md tool-edit).
- 8 OPEN defects. Criteria NO.
