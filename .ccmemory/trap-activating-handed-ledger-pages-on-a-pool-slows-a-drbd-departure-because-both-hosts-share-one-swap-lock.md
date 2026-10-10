---
name: trap-activating-handed-ledger-pages-on-a-pool-slows-a-drbd-departure-because-both-hosts-share-one-swap-lock
description: TRAP (0.90.109 D, measured): survivor activations on a worker pool made DRBD departures 20.6 ms/page vs 13.6 inline; pair swap lock is shared. Remove…
metadata:
  type: feedback
tags: [drbd, tauth, ledger, departure, swap-lock, measurement]
---

On a DRBD pair every ledger page commit on EITHER host takes the one pair-wide swap lock (pal/linux/drbd.c mxfs_drbd_lock). A departure costs two commits per page: the departing host's PREPARE and the survivor's ACTIVATE.

Tried (0.90.109 change D, `tauth_async_activation`): the survivor activated handed pages on an 8-thread pool instead of its receive thread, so its commits would batch. Physical pair A/B, tests/pve_depart_wall.sh KNOB=tauth_async_activation, evidence tests/evidence/pve_depart_wall/20261009T044938Z:
- pool on: 70.8 s / 3391 pages and 70.3 s / 3450 pages (~20.6 ms a page), departing host's swap wait/batch 27-45 ms
- pool off: 47.0 s / 3465 pages (13.6 ms a page), wait/batch 12-20 ms

The survivor's parallel activations took lock share from the departing host, so the unmount got slower. Removed in 0.90.110. A pool also had one unexplained dlm_ledger_test case-15 failure (a request parked REMASTER on a page whose activation was queued).

Lesson: on DRBD, speeding one side's ledger commits by adding concurrency slows the other side's; judge any commit-path change by the pair-wide swap statistics on BOTH hosts (P-DRBD-CAS-STATS), not by one host's throughput. Also: inline activation is not complete either. A departing host that closes its connection loses the FROZENs still queued unread (844 of 3465 activated); the survivor's GOODBYE takeover consumes those PREPARED-to-self pages.
