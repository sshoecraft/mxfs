---
name: ccloop-c7ee71c6-sess249-488-fix-landed-and-noino-mass-repro
description: sess249: -488 sticky-revoke fix IMPLEMENTED+BUILT+DEPLOYED (0.11.489 sv D0737D29) but NOT exercised; NEW mass repro of #18 noino-relfence — 20/32 nod…
metadata:
  type: project
---

# sess249

## -488 sticky revoke: LANDED, NOT VERIFIED
sess244-248 produced nothing — tree was still 0.11.488 with no
MXFS_LKF_DEMAND and no revoke field. Implemented the whole sess243
ruling this session.

VERSION 0.11.489, srcversion **D0737D2921E9A186AE257D9**, clean build,
deployed fleet-wide with `scripts/module_swap_deploy.sh 32 caw`.

Edits:
- dlm_caw.h: slot `uint16_t pad` -> `uint8_t revoke + uint8_t pad0`.
  512B _Static_assert unchanged; old on-disk images read revoke=0, so no
  proto-gen bump needed (an old node simply doesn't participate, which
  is exactly pre-fix behavior).
- include/mxfs/mxfs_dlm.h: MXFS_LKF_DEMAND (1<<6).
- dlm_caw.c NOQUEUE exit: if DEMAND && !cur_slot->revoke -> copy slot,
  revoke=1, gen++, best-effort caw_slot(); then caw_send_bast_mcast;
  still -EAGAIN.
- NEW helper `caw_revoke_consume(new_slot, ref)` immediately after
  `slot_has_holders`: clears revoke iff ref has no holders. Called with
  ref=cur_slot at the post-wait grant and the compat-add grant; called
  with ref=new_slot in the release CAS, positioned BEFORE the
  fair/direct-handoff arms re-add a waiter as holder. Fresh-claim path
  already memsets.
- poll thread: revoke check inserted BEFORE the `!slot.waiters` continue
  (that skip is the actual hole). Emits P280-REVOKE-RX, submits
  caw_bast_submit(EX), sets saw_contention.
- __mxfs_ag_dlm_lock gained a `demand` param. ONLY
  mxfs_ag_dlm_lock_bounded passes true (first try + every >=500ms WALL
  CLOCK + get_random_u32_below(128)ms jitter). mxfs_ag_dlm_lock and
  mxfs_ag_dlm_trylock pass false; the pre-blocking probe at the second
  ag_lock_nb call site also passes false (its blocking wait registers a
  real waiter, a strictly stronger signal).
- tools/caw_slotdump.c prints `revoke=N`.

VERIFICATION STATUS: NOT DONE. The livelock did not recur, so the cause
was never exercised. Fleet after the run: 0 new P5G, 0 P280 anywhere.
(test30's P5G=192 are stale, from uptime 6438s, long pre-swap.)

## NEW: mass reproduction of #18 D-NOINO-RELFENCE-AIL-FREEZE-474
`./run.sh 32 caw rsync_paired` -> FAIL 0/32 NO_TERMINAL_RECORD 60s/60s.
NOT a capture fault: **20 of 32 nodes shut down**, exactly one wedge
each. Wedged: test 1,2,3,7,8,9,10,11,12,14,15,17,19,22,24,26,28,29,30,32.
Clean: 4,5,6,13,16,18,20,21,23,25,27,31.

test8 chain (uptime 85058, ~193s after its remount at 84865):
```
P-NOINO-DRAIN-STUCK ino=1062401 try=8 — AIL min frozen at 0x100002309
    across 8 bounded pushes (post-listdrain)
P-NOINO-RELFENCE-WEDGE ino=1062401 — shutdown
XFS (dm-1): Metadata I/O Error (0x1) at
    mxfs_dlm_noino_bast_work_fn+0x19b (xfs/xfs_mxfs_dlm.c:20147)
```
Immediately before it, same node:
- `P5N-AG-ORPHAN-NAK ag={4,5,8,13,14,20} src=bast-rx rc=0 disk_held=0
  repair=0` — "CAW holder bit on the platter with no in-core tenure is a
  STRANDED AG: no peer BAST can schedule its release"
- `mxfs_dlm_ag_bast_notify: 478 callbacks suppressed`, P12-AGBAST-RX
  bursts (one showed ag=2 holders=1 readopt=7 page_ms=137446 holder=rsync)
- repeated `heartbeat received from unknown node 2152128402`

Working hypothesis (untested): the module-swap remount strands AG holder
bits on the platter (disk_held=0 = no in-core tenure), the AIL cannot
drain the no-inode lock's items, 8 bounded pushes fail, fail-closed
wedge fires. If true the trigger is the swap/remount path, not rsync.

## Rig facts
- Clyde healthy throughout: load 8-10, ZERO D-state tasks.
- All 32 VMs were up and mounted on .488 before the swap; the sess243
  "wedged rig" fear was stale — test30's rsync had died long before.
- `grep -c P-WITHDRAW-STAMP` finds nothing: the log emits
  `P163-WITHDRAW-STAMP`.
