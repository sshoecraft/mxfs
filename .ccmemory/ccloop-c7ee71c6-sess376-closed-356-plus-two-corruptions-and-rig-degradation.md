---
name: ccloop-c7ee71c6-sess376-closed-356-plus-two-corruptions-and-rig-degradation
description: sess376 final: #3 D-REFUSAL-GRANT-FREEZE-356 CLOSED FIXED AND VERIFIED (8-row hazard matrix); 2 disproofs; 4 filed incl. 2 free-space-btree corruptio…
metadata:
  type: project
tags: [rule6, closure-purge, corruption, rig-health, disklock, incarnation]
---

sess376 end state. Build 0.14.9 sv 25057F6813DDAF1ECB477CF. Ledger 47 open of 103
(was 46 of 99): 3 closed, 4 filed.

## CLOSED

- **D-REFUSAL-GRANT-FREEZE-OUT-OF-CLOSURE-356 -> FIXED AND VERIFIED.** The
  sess363 Hazards-section-7 matrix is complete at 8 rows, each with a harness and
  a platter/dmesg artifact. Rows added this session: 5 (hint->read reuse,
  A->tombstone->B, 3/3, attributed by P299-HINT-MOVED naming slot/hint ino/found
  ino), 6 (read->CAS ABA, A->tombstone->A, 2/2, P299-STRIP-CASMISS with identical
  resource AND identical lineage), 7 (publisher death BEFORE publication,
  KILLPUB=1), 8 (node-slot incarnation reuse, 2/2). Causal acceptance with the
  timing knobs OFF passed; board on that build 25 PASS / 2 FLAKY(passing) /
  0 FAIL / 1 POLICY.
- **D-CLOSURE-DEMAND-SCRUB-NOT-FIRING-FOR-BLOCKED-WAITER-375 -> DISPROVED.** The
  scrub fires at wait age 1ms; the 76s was the test's own injected pause, which a
  single global countdown let the WAITER consume instead of the scan.
- **D-CLOSURE-REMOTE-WAITER-NO-REPAIR-BEFORE-PUBLICATION-376 -> filed and
  DISPROVED same session.** "The publisher purges before it publishes" is false:
  durable publish is xfs/xfs_mxfs_dlm.c:46711, scan :46759, the PUBLISHED line
  :46791 is only a summary. Proof: a publisher destroyed mid-scan never emits
  that line and all 30 remote survivors still imported the verdict. Scan = 418ms.

## THE INTERLOCK THAT SETTLED THE ABA QUESTION (row 8)

GPT's RULE-5 review named node-slot incarnation reuse as the last blocker: the
CAW bitmaps index nodes by HEARTBEAT SLOT, a reusable resource, so a new
incarnation could in principle re-set "the victim's bit". It cannot, and the
reason is `recov_desc_present()` in dlm/disklock.c: every closure gate reads the
victim's heartbeat sector FRESH and requires
`flags == MXFS_DISKLOCK_FLAG_RECOVERY_GUARD (3)` plus a descriptor naming the
sector it sits in. A live tenant writes FLAG_ACTIVE (1) and cannot present a
descriptor at all. Measured 2/2 with tests/closure_hb_slot_reuse.sh: the rebooted
victim takes a DIFFERENT slot, the guard record keeps its original node_id+epoch
byte for byte, zero strips after the rejoin.

## FILED, ALL OPEN

- **D-FDW-REJOIN-BNOBT-OVERLAPPING-FREE-SHUTDOWN-376 (critical).** TWO free-space
  btree corruption shutdowns on 0.14.9, different nodes, different sides of the
  same picture: test6 `bno + len > gtbno` freeing (ag10,9,2) over an existing
  (10,3) during a truncate; test8 `i != 1 in xfs_alloc_fixup_trees` during
  xfs_create allocation. Both ended in "Corruption of in-memory data (0x8)" and a
  withdraw. The fence in occurrence 1 is NOT established as necessary -
  occurrence 2 had no fence, no refusal, quarantined=0x0 on a freshly mkfs'd FS.
  A clean re-prep restored a fully green board both times. Third hypothesis added
  at the end: HOST STORAGE (see below). Discriminator recorded: log volume_id /
  fs_gen on the mount line so "this node is running the previous filesystem" is
  detectable at all, and harvest SCSI/dm errors + host await on any recurrence.
- **D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376 (critical).** A terminal
  quarantine permanently occupies a heartbeat slot; usable slots = the volume's
  log-slice count; **mkfs caps -n at 32** ("XFS caps the internal log at
  2GiB-10MiB"). So at the maximum cluster size one refusal permanently costs a
  node, the mount error's advice ("reformat with more slices") is impossible to
  follow, and there is NO IMPLEMENTED REPAIR PATH - no tool clears a quarantined
  GUARD record, only mkfs -f does. Measured: rejoining node got claim_slot -28
  and aborted its mount.
- **D-FENCE-RECONVERGE-POSTCONDITION-280S-376 (high).** Instrumented (run.sh now
  records the alive/N trajectory + dissenting nodes into criteria.json) and
  reproduced on first repeat: flat 31/32 for the whole window,
  dissent=[test6=nores] - the node had taken the corruption shutdown above, not
  merely been slow. The original 2026-08-15 incident stays unattributed.

## RIG HEALTH AT SESSION END - READ BEFORE TRUSTING A BOARD

clyde's nvme0n1 is 88% full (1.5T/1.8T) with block-layer r_await 68-157ms and
w_await 14-27ms; the documented healthy figure on D-DIR-REUSE-COHERENCY-32-FLAKY
is w_await p50 1.19ms. A node (test4) wedged with an UNKILLABLE D-state sync
whose stacks are **ext4/jbd2 on dm-0, the node's own ROOT disk** - MXFS nowhere
in the path. Its qemu then became an unreapable zombie and `virsh destroy`
returned "Failed to terminate process ... Device or resource busy"; the domain
sat in "in shutdown" for 20+ minutes. No D-state tasks on clyde itself and host
util only 15-27%, so clyde is NOT wedged - per RULE 2 nothing was done to it.
The board's node-fault diagnostic used to print only `sync[sync_inodes_sb]` and
name D-BAST-WRITEBACK-ABBA-DEADLOCK (an MXFS defect) for exactly this; run.sh now
tags each D-state task with the subsystem from its top stack frames
({EXT4-ROOTDISK} vs {MXFS}) so that misattribution cannot recur.

## HARNESS CHANGES LANDED

run.sh: reconvergence trajectory/dissent/wall; MXFS_LOG_SLICES pass-through to
prep_fs.sh; subsystem-tagged node-fault diagnostics.
tests/setup/prep_node.sh: `blockdev --flushbufs` now FAILS instead of WARNing.
tests/closure_purge_scrub.sh: PROBE_FANOUT, KILLPUB arms.
tests/closure_reuse_directed.sh: PAUSE_WHO/PAUSE_WHERE/REUSE_TO/ABA arms + a hold
loop that keeps the re-bound resource LIVE across the publisher's wake.
tests/closure_hb_slot_reuse.sh: new, the incarnation interlock.
