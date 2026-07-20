---
name: sess34-6s-dir-handoff-is-LOCK_ACQUIRE_WAIT_MS-deferred-bast
description: sess34 ROOT of dir_reuse 2/tcp SLOWNESS: 6s dir handoff = MXFS_LOCK_ACQUIRE_WAIT_MS=6000 requester grant-wait; holder release is <5ms but defers the…
metadata:
  type: project
---

## sess34 — the ~6s dir-131 handoff (dir_reuse 2/tcp SLOWNESS root) = MXFS_LOCK_ACQUIRE_WAIT_MS

### PROVEN chain:
- P34-ACQ-SLOW (xfs_mxfs_dlm.c:8661, added sess34): dir-131 inode acquires take **5992/6142/6233ms,
  attempts=1, rc=0** — a SINGLE blocking mxfs_v5_dlm_inode_lock returns success after ~6s.
- The requester's grant wait is `pending_wait(pend, MXFS_LOCK_ACQUIRE_WAIT_MS)` (dlm/dlm.c:912).
  **`#define MXFS_LOCK_ACQUIRE_WAIT_MS 6000`** (include/mxfs/mxfs_dlm.h:255). The ~6s == this exactly.
- Holder-side dir release is FAST: **P138-BAST dir=1 count = 0 on both nodes** (the >5ms gate never
  fires for dir releases; bast_process drain for the dir is <5ms). So the 6s is NOT the holder drain.
- => the requester waits the (near-)full 6000ms grant timeout because the HOLDER does not HONOR the
  dir BAST promptly. Holder release, once it runs, is <5ms.

### WHY the holder defers ~6s (hypothesis, strong): bast_notify defers a BAST that arrives while the
holder is in ISTATE_ACQUIRING (its own create slow-path) via `i_dlm_stale=true` (xfs_mxfs_dlm.c:5513)
with NO timer — it is only honored at the holder's NEXT slow-path acquire's post-publish check. A hot
dir holder doing back-to-back creates uses CACHED fast-path acquires (no slow path, no i_dlm_stale
check) → the deferred BAST sits unhonored until ~the 6000ms requester timeout boundary. (MHT-deferred
BASTs DO have a timer at xfs_mxfs_dlm.c:5345/5250; the ACQUIRING/i_dlm_stale defer does not.) Verify:
does ilock_end actually fire the deferred BAST? comment at :5535 claims "ilock_end or unpin fires it"
— if it did promptly, the 6s wouldn't happen, so that path is leaking.

### FIX directions (NOT yet tried — pick carefully, shutdown risk):
1. Honor a deferred dir BAST PROMPTLY: add a short timer (like MHT) for the i_dlm_stale/ACQUIRING
   defer, OR check i_dlm_stale in the fast-path acquire and queue bast_process there, OR ensure
   ilock_end reliably fires the deferred BAST.
2. Do NOT just lower MXFS_LOCK_ACQUIRE_WAIT_MS: the outer acquire loop is only 3 attempts
   (xfs_mxfs_dlm.c:8652, msleep 50 between); 3×wait then FORCE-SHUTDOWN (8720). Lowering the wait
   without raising the attempt count risks shutdowns when a grant legitimately needs >N×wait.

### This is the SLOWNESS (3/5 runs timeout ~16-20s/round; ≤6s/round needed). Separate from the
CORRECTNESS face (acquire-side stale dir-block RMW, [[sess34-dirreuse-acquire-side-stale-rmw-trylock-skip]]).
Both must pass for 2/tcp 100%. P-CONVBLK-DENY (conversion thrash) also contributes to slowness.
[[sess34-dirreuse-three-faces-slowness-and-leafhole]]</body>
