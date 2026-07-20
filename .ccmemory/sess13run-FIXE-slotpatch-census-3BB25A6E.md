---
name: sess13run-FIXE-slotpatch-census-3BB25A6E
description: sess13 FIX-E (3BB25A6E): slot-level FUA patch breaks the P91-guard ENOENT loop. Census: 7/8 clean (1 zsl silent-stale singleton). 6 consecutive clean.
metadata:
  type: project
---

# sess13 FIX-E + census

## FIX-E (build 3BB25A6E)
PROVEN loop (run_dlm_scaling_20260704T094645Z): P12-IGETMISS-RELOAD
invalidate → retry read captured by sess91 P91-FUA-SKIP-LOGGED (li_empty=0:
ANOTHER slot's inode AIL item on the cluster buffer) → in-place serve of the
stale image → ENOENT ×64. Guard authority is per-logged-slot, not per-buffer.
FIX: in mxfs_dlm_iget_miss_reload stage 2, when the invalidate can't act and
the TARGET ino has no attached inode log item on the buffer, FUA-read the
cluster to a temp page and memcpy ONLY the target slot into b_addr
(P13-SLOTPATCH probe, ret=2). xfs_lookup retry then reads a fresh dinode.

## Census on 3BB25A6E (17-test suite, 4/tcp)
- 8 iters: 7 clean, 1 zero_silent_loss (1/4: peers read node1's 10×256K
  files as size=0/empty-md5 — silent stale dinode, iget SUCCEEDS so the
  FIX-D/E retry stack never engages; 0 P13 probe fires that iter; sess90/91
  family; FIRST occurrence in ~30 session iters — watch frequency).
- 6 consecutive clean at checkpoint time.

## Full session iteration history (4/tcp, all builds)
~30 suite iters total: fence -110 starve 0 since FIX-C (was 1-in-4);
drc readdir-miss ×2 (both pre-FIX-E, block-phase in-core commit dropped —
P13-PLACE/P64-present2 armed, no occurrence since); ds got=0 ×4 (root chain
proven → FIX-D v1/v2 → FIX-E; expect converged); fairness EUCLEAN ×1;
fence n4_14 sf-dangling leak ×1 (P13-SFRM + P56 ours armed); zsl ×1.

## Next steps
1. Continue suite loop to ~10 consecutive clean on 3BB25A6E.
2. Then same build: 8/tcp ×3, 2/tcp ×2, 1/tcp ×2 (criteria = 1/2/4/8 100%).
3. On any face: drc → P13-PLACE/P64 write sequence; fence leak → P13-SFRM +
   P56 ours/post; ds → expect P13-SLOTPATCH convergence (verify in probes);
   zsl → check P74/mirror engagement for file inodes in artifact kernlogs
   (/tmp/run_zero_silent_loss_20260704T100906Z kept).
4. Deeper roots on file (unfixed): di_gen not advancing on realloc; sf
   clean-skip release vs sf-dinode destage; free (mode→0) destage ordering.
