---
name: trap-a-write-authority-mask-with-no-notion-of-recovery-drops-every-replayed-dinode-and-a-no-io-completion-reads-as-landed
description: TRAP (D-0976, 0.87.8): the inode-cluster authority mask dropped every dinode a foreign replay applied (no in-core inode, no log item) and refused the…
metadata:
  type: feedback
tags: [recovery, inode-cluster, authority-mask, foreign-replay, 2/tcp, D-0976]
---

# A publication filter earned under live tenures is blind to recovery, and a refused write completes as success

**Measured (2/tcp, sess46, `tests/recov_bmbt_reuse.sh`, builds ABD7370F and
9C04D519):** the survivor's foreign replay applied all 7 dinode images of the
victim's slice (`P77-FRINODE verdict=APPLY`, last at changecount 64509 /
32253 extents) into its cached inode cluster and queued it; the cluster write
went through `mxfs_submit_partial_inode_write`, which saw one slot with no
in-core inode and no inode log item (`P218-CLUSTER-PASSENGER nocore=1
skipped=1`), masked it, found nothing else owed in the cluster, and refused
the write with no I/O (`P218-WRITE-REFUSED`) — then completed the buffer as
if it had landed, so `P226-FR-HOMEFLUSH ... flushed home` printed.  The
victim's bmbt leaves (buffer items, not masked) landed.  After rejoin the
victim's `rm` found the platter dinode at the pre-death flush (19271 extents,
cc 38546, di_lsn 0x10000c389) against leaves stamped with the last replayed
checkpoint (`P-BMBT-OVERCOUNT`), and shut down.  Same lines on the earlier
control lap.  This is also the mechanism behind D-0517's 32-node
`P-ALLOC-FREE-CORE` (creation half-applied after survivors replayed two
victims).

**Why it hid for months:** every earlier death lap created its files long
before the kill, so the inode items in the slice read `disk_cc >= log_cc`
and were skipped — no cluster write was owed.  Only a kill with in-flight
core changes (nextents growing, size growing, a create) exposes it.  And the
refusal path is a *successful* no-I/O completion, so nothing downstream
(home flush, IMAGES_REPLAYED, P163) could see the loss; only the victim's
next read or a cold `chk_mxfs` can.

**Lessons.**
- A filter that decides "who may publish this slot" from live-tenure state
  (log items attached, in-core grant mode) has no answer for a producer with
  no tenure at all — recovery.  Every such filter needs an explicit
  recovery-ownership input (`b_mxfs_recov_slots`), tested BEFORE the
  free/NL/PR/no-core exclusions.
- A "refuse with no I/O and complete as success" branch converts a lost
  obligation into a reported success.  A nonzero recovery obligation reaching
  it must fail the write (`P218-RECOV-REFUSED`), never complete it.
- A replayed image on a cached cluster patches only the LOGGED fields (core,
  and each fork only when logged; four bytes for an unlinked pointer); the
  rest of the slot is whatever the survivor's cache held.  Give the slot a
  platter baseline once per recovery before its first patch (Astra's hazard,
  sess46), never after the recovery owns it (that would drop the in-order
  images applied so far), and never for a slot this node has in core.
- An icreate replay initialises a whole cluster; if an inode item of the same
  recovery later fills one slot, the partial write would drop the other 31
  initialised free slots — record all initialised slots as owed.
- Death-lap harnesses must kill with core changes IN FLIGHT and end with the
  cold structural check; a lap whose files landed before the kill measures
  nothing about replayed dinodes.
