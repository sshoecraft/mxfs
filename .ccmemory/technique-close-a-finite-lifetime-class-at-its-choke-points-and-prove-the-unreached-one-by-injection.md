---
name: technique-close-a-finite-lifetime-class-at-its-choke-points-and-prove-the-unreached-one-by-injection
description: TECHNIQUE (D-0924, 0.87.14): a stranded-token class with an unattributable historical event was disposed by returning the token at both choke points…
metadata:
  type: feedback
tags: [d0924, agmeta, disposition, injection, ring-rotation, conservation]
---

# Closing a leak class whose one historical event cannot be attributed

D-0924 (AG-meta track token stranded once on 0.75.63; per-cycle unload leak already disproved as slab merging) sat for ten sessions on "name the route". What disposed it, and what Astra (2026-09-18) said was required for "fixed and verified; historical trigger unattributed" to be honest:

1. **Prove the lifetime class is finite and name its choke points.** A single deallocator caller proves a DESTRUCTION funnel; the obligation class also needs "no epoch ends without destruction or terminal completion" — grep for wholesale flag resets (`bli_flags = 0`), teardown paths that detach the item (`b_log_item` writes in xfs_buf_free), re-init in place. Here: none exist, so the two choke points (funnel with NO_IODONE, completion epilogue after `b_iodone`) cover every end.
2. **Return the obligation at every choke point, including the one you think is redundant.** The completion epilogue was a pure diagnostic ("keep the leak visible"); printing AND returning keeps it visible and closes it.
3. **State the exclusion argument for the late return.** A binary cmpxchg token cannot tell epochs apart; the post-callback return is safe only because the buffer lock is held from submit to the completion's relse and re-arming needs that lock. Write that down next to the code.
4. **Exercise the arm a healthy build never reaches.** A knob (`dbg_agmeta_iodone_skip=N`) that makes the callback leave N tokens armed; the epilogue must return exactly N (SKIP=8, MISSED=8, why=ioend-unconsumed=8) with conservation exact afterwards. A closure that ships unreached is a claim, not a measurement.
5. **Check conservation per unit, not only globally.** `acquires == returns_iodone + returns_reclaim` balances while one AG is over and another under; the unmount census prints each AG's pending after drains+flush.
6. **Say which routes are measured and which are closed by construction.** The put route is unreachable from a shutdown here (CIL abort retires via ioend); do not let a harness's non-vacuity FAIL become either a defect or a silent pass — state it.

## Trap that cost a lap
The injection's evidence lines land in the first second of the churn; at this rig's ~700 lines/s the ring rotated past them before the post-run sweep, while the knob read 0 and the counters were consistent with 8 returns. Evidence lost to rotation is not evidence absent: stream the ring (`setsid nohup dmesg -w > /dev/shm/x &`) from BEFORE the arming marker and grep the stream, and check the marker is still in whatever you sweep.
