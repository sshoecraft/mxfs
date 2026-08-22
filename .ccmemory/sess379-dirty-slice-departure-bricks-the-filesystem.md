---
name: sess379-dirty-slice-departure-bricks-the-filesystem
description: sess379: a node that retires its PR key while leaving a dirty slice makes the FS permanently unmountable — no key to preempt, so no fence certificate…
metadata:
  type: project
tags: [sess379, critical, pr, fence, admission, unmountable, 379]
---

# sess379 — a clean PR retirement over a dirty slice BRICKS the filesystem

Ledgered as **D-DIRTY-SLICE-DEPARTURE-RETIRES-FENCE-KEY-UNMOUNTABLE-379**
(critical). Found incidentally while trying to remount 28 nodes between
mass-unmount reps; it is not a harness artefact.

## Symptom

After a 28-of-32 mass unmount, **none of the 28 could remount**, repeatedly,
over 10+ minutes, with 4 healthy peers mounted the whole time:

```
P163-RECOVERY-PENDING slot=9 node=2569023191 epoch=7860688283116785074
disklock: P236-CLAIM-UNCERTIFIED slot=9 victim=2569023191 stage=1 kind=0
    — fencing ATTEMPT only — no exclusion has been proved yet
MXFS mount recovery: slice slot=9 NOT replayed (-1)      x4 rounds
MXFS mount ABORTED: slot mask 0x200 still requires recovery after 4 inline
    replay round(s) and 30000 ms
MXFS mount recovery barrier failed
```

Only `mkfs_mxfs` recovers it (confirmed — a re-prep cleared it).

## Mechanism

`pal/linux/xfs_super.c` ~1727 retires this node's SCSI PR registration at the
end of `put_super` **unconditionally** — no gate on whether this node's journal
slice is clean. That key is the only thing a survivor can PREEMPT AND ABORT to
mint the fence certificate that authorises replaying the dead slice.

`dlm/scsipr.c` ~441 is deliberate and, for the case it was written for, right:

> Key absence bounds only what the victim may START. It does not establish that
> anybody ever aborted the task set the victim had ALREADY started … it has to
> consume the winner's durably published evidence.

→ `MXFS_FENCE_KIND_KEY_ABSENT_UNPROVEN`. Correct **when a winner exists**. Here
no winner ever existed: the victim retired its *own* key, so no peer ever fenced
it and no evidence was ever published. Terminal, not transient.

The design handles a node that **dies** (key still registered ⇒ preempt+abort ⇒
certificate). A node that **retires its key but leaves a dirty slice** falls in
the hole between the two.

## Proof the key is the missing piece

- victim node_id 2569023191 = key `0x99202ED7`.
- `sg_persist --in --read-keys` → gen 0x3ca0, exactly 8 keys
  (`0xb0560b70 0xf7bf8b5d 0x62722b3a 0xdaa7d9ca`, each twice = 4 live nodes ×
  2 nexuses). `0x99202ED7` absent.
- The mounting node logs `P303-FENCECAP-OK … WE-RO held, persistence active,
  key view complete, own key present, PREEMPT AND ABORT issuable` — every other
  precondition is satisfied.

## On-platter forensics (`tools/chk_mxfs -Q`)

```
heartbeat slot 9: RECOVERY GUARD
  sector identity   node=2569023191 fs_gen=0xCD02AC7F incarnation=7860688283116785074
  recovery          owner=3668433354 term=0 gen=1 stage=1 flags=0x0
  fence certificate kind=0 resv_type=0x00 victim_key=0x0000000099202ED7 prover=3668433354 term=1
  NOTE: this guard is NOT quarantined — it is a recovery in progress
live members 4 · released slots 27 · withdrawn slices 0 · usable RW slices 31 of 32
```

**The recovery OWNER (3668433354 = test30) was mounted and healthy throughout.**
So this is not an orphaned lease awaiting takeover — it is a *live* owner stuck
at stage=1 with `kind=0`, permanently unable to advance. That is why waiting
never helps.

## Two secondary defects in the reporting, both ledgered under the same entry

- `chk_mxfs`'s **summary contradicts its own detail**: the detail says "NOT
  quarantined", the summary counts "quarantined verdicts 1", prints the
  terminal-quarantine advice, and points at
  D-QUARANTINED-SLOT-EXHAUSTS-CLUSTER-ADMISSION-376 for a repair that is "not
  implemented yet". Wrong classification, wrong repair. It also says "usable RW
  slices 31 of 32 … the cluster runs that many members short", i.e. describes
  losing ONE slot — when the measured effect is that **no node can mount at
  all**, because the admission barrier requires slot mask 0x200 to be *replayed*
  and does not route around it to any of the 27 free slots.
- The kernel text actively misleads: `P300-CLAIM-WITHDRAWN` prints "All three
  are TRANSIENT — a live peer resolves them. Retry the mount rather than
  reformatting." Nothing resolves this one.

## The tension that makes the fix a RULE-5 question

D-CLEAN-UNMOUNT-LEAKS-PR-REGISTRATION-377 (sess377) made this unregister
**mandatory and fail-closed** — a departing node must not keep write authority.
This defect requires it to **leave a preemptable key behind** when its slice
still needs replay. One unconditional call cannot satisfy both. Candidate
shapes recorded in the ledger entry: gate retirement on slice cleanliness;
publish a SELF-departure fence certificate at teardown (the departing node is
the one entity that can prove it stopped issuing I/O); let admission accept
"key absent AND a durable clean-quiesce stamp"; plus an offline `chk_mxfs`
repair for volumes already in this state.
