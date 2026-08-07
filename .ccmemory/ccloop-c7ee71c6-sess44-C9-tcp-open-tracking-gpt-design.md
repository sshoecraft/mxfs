---
name: ccloop-c7ee71c6-sess44-C9-tcp-open-tracking-gpt-design
description: sess44 GPT C9 ruling: HYBRID preferred (open bits stay in CAW disk slots under TCP grants; ordering replaces CAS); invariants + 18 fault arms + rollo…
metadata:
  type: project
tags: [ccloop, open-unlink, tcp, C9, design]
---

# sess44 — GPT design ruling for C9 (TCP open-file tracking), D-CROSSNODE-OPEN-UNLINK

Full text in session transcript (task kcz5en0bo). Actionable distillation:

## VERDICT: hybrid disk-bits, NOT master-tracked (for near-term correctness)
Keep `open_holders` EXACTLY in the CAW per-inode slot sectors (they exist on the
shared LUN regardless of DLM transport — mkfs lays the table out always) and have
TCP-mode nodes run the SAME publish/clear/B6-read/fence-strip machinery. TCP DLM
grants supply the exclusion; the missing atomic release-CAS is replaced by strict
ORDERING:
- SET durable → only then open()/mapping usable → only then TCP release permitted
- activity 0 → CLEAR durable → only then release permitted (reopen serialized locally)
- B6 reads the bitmap ONLY while holding EX via TCP DLM; read error ⇒ defer whole
  truncate+ifree (fail closed)
Crash windows all conservative (stale bit ⇒ defer; fencing strips). The forbidden
transitions: TCP release before durable SET; clear while activity remains; reopen
bypassing republish. AUDIT EVERY release/downconvert path (normal unlock, BAST,
lease expiry, teardown, error unwind, reconnect, unmount): none may drop a grant
behind a pending SET.

## Hybrid viability gates (reject if any true)
1. TCP resources lack stable CAW slot identities / slot lifecycle unavailable in
   TCP mode (KEY OPEN QUESTION: today CAW slots are allocated by CAW-mode grant
   writes; TCP mode must be able to allocate/find an inode's slot purely as an
   open-bit registry).
2. Slot exhaustion reintroduced; 3. slot reuse before bit+zombie cleanup; 4. disk
   FUA/sector-atomic guarantees absent in TCP mode; 5. unfenced slot reuse;
6. any release path bypassing the SET-complete guard; 7. B6 without EX.

## Implementation shape
Transport-neutral `mxfs_open_tracking_ops { publish_open, clear_open, b6_check,
fence_cleanup }`; CAW and TCP-hybrid point at the SAME disk implementation. Full
master-tracked protocol (OPEN_ON_GRANT flag, SET/CLEAR/OPEN_ACK with per-node
monotonic open_seq keyed by (node_id, boot-incarnation UUID), B6_CHECK_OPEN
EX-holder-only, freeze→fence-or-hear→rebuild with zero-entry DONE distinguishing
"has nothing" from silence) is documented in the transcript as the later
scalability option — do NOT build it first.

## Invariants (test assertions)
1 publication-before-use; 2 publication-before-release; 3 serialized last clear
vs reopen; 4 B6 linearized under EX after all prior publications; 5 fail closed
(unknown/error/recovering/unfenced ⇒ possibly-open); 6 no partial destruction;
7 incarnation safety (node IDs keyed with boot UUID).
Central assertion: "B6 may return EMPTY only while holding EX, after all prior
publication-before-release obligations resolved, under a non-recovering fully
fenced membership view."

## Rollout (C7 completion)
HB feature word alone insufficient — need: join-handshake enforcement BEFORE any
grant (reject unknown mandatory bits, no ignore-fallback) + superblock INCOMPAT
bit (MXFS_SB_FEAT_INCOMPAT_CLUSTER_OPEN_TRACK) so an old module refuses the fs
outright. Rolling mixed-version RW upgrade is NOT safe: drain/fence old, upgrade
all, set incompat, new unanimous view, then enable destructive reaping.

## Test matrix for TCP mode
The 9 CAW cases unchanged (tests/openunlink_matrix.sh) + 18 fault arms (ACK lost,
master dies at each stage, delayed old CLEAR vs newer SET, B6 queue orders,
zero-entry rebuild DONE, fence-unconfirmable freeze, incarnation reuse, hybrid:
SET-ok-then-TCP-dies, release-while-SET-pending must be held, bitmap read error
defers, crash after CLEAR before PR release, slot reuse with stale bit prevented).

## Current blockers noted sess44
- tcp condition UNRUNNABLE on this rig: no XML-wired LIO disk exists (virsh XML
  has only vda+virtio-scsi; /dev/mxfs-shared absent on host); /dev/sda is now a
  PATH MEMBER of the caw mpath map — prep_fs.sh sess44 guard refuses mkfs on
  claimed devices (FS_PREP_REFUSED-style message, verified firing). Rig work
  needed before ANY tcp verification: create host LUN + wire into 32 VM XMLs.
- C6 (membership masking of open bits at B6/reap) status unverified in code.
- C7 join-handshake ENFORCEMENT status unverified (hb_feature_fill exists).
