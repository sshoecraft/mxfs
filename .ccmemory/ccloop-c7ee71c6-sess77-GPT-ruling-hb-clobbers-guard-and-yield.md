---
name: ccloop-c7ee71c6-sess77-GPT-ruling-hb-clobbers-guard-and-yield
description: sess77 RULE-5 ruling: the blind HB write CLOBBERS a recovery guard in its own slot — destroys the one-shot fence certificate AND lets a node being re…
metadata:
  type: reference
tags: [fencing, disklock, heartbeat, gpt-ruling, scsipr, recovery-descriptor, critical]
---

# sess77 — GPT RULE-5 ruling on the fence-evidence channel

I brought GPT one hole (the intent holder is an undisplaceable SPOF).
It refuted four of my premises and found a **second, worse defect**.

## THE NEW DEFECT — the HB writer clobbers the guard

`disklock_hb_fn()` (`dlm/disklock.c:499-536`) does
`memset(hb,0,512)` → fill → **blind `write_sector_fua()`**. No read, no
CAS. So any RECOVERY_GUARD a survivor CASes into that node's slot is
destroyed by the victim's very next heartbeat, 2 s later
(`MXFS_DISKLOCK_HB_INTERVAL_MS = 2000`).

GPT's interleaving:
1. A writes the FENCING intent into the live victim's ACTIVE record.
2. The victim's heartbeat overwrites it.
3. A issues the 0x05 and **successfully excludes** the victim.
4. A's certify CAS fails — the intent is gone.
→ the one-shot key is consumed and **no successor can ever prove
exclusion**. Slice permanently unreplayable.

**This is NOT confined to the version-gate path.** The primary TCP-death
path exists precisely for "TCP-dead-but-disk-alive (partition,
stall-then-revive)" peers, and sess38 MEASURED a node whose HB failed to
land for the full 62 s lease while it was alive. A revived node writes.

**It is also a defect on its own terms, independent of certificates:** a
node whose slot is guarded keeps heartbeating and keeps writing to the
FS while a survivor replays its journal. Nothing makes it self-fence —
`P131-SELF-FENCE` fires only on an fs_uuid change, and a failed HB write
is merely logged (`disklock.c:539`) before the loop continues.

**Fix (GPT's own preferred option): CAS-guard the heartbeat write.** CAW
against our own last-written image — one SCSI command, not two
(`mxfs_pal_bdev_compare_and_write`, `pal/pal.h:723`, `-EAGAIN` =
MISCOMPARE, `-EOPNOTSUPP` → read+verify fallback already modelled by
`recov_cas_durable`, `disklock.c:2050`). MISCOMPARE ⇒ somebody is
recovering us ⇒ **self-fence**. That is the correct semantic: the only
foreign writes to our own slot are a recovery guard or a purge-zero.

## FOUR PREMISE REFUTATIONS (mine were wrong)

1. **`ERROR` is NOT non-consuming.** A transport timeout / lost
   completion can mean the target executed the 0x05 and we never heard.
2. **`RACE_LOST` does NOT establish someone else consumed the key.** By
   its own definition our command performed nothing; the key may still
   be there. Under a correctly serialised cluster it is ANOMALOUS —
   it implies an uncoordinated initiator (pre-upgrade node, admin,
   other control plane), not a benign lost race. Re-read PR state.
3. **Not all other non-proving kinds leave the key intact** —
   `KEY_ABSENT_UNPROVEN`, `NOT_REGISTERED`, `SELF_PREEMPTED` don't.
4. **A's own slot is NOT "always writable"** — same path failure applies.
   Rejected as a fallback certificate location.

## THE RULINGS

**Q1 yield — YES, but partition by EVIDENCE, not by enum.** Three
classes, not two: *definite non-execution* → yield in place; *observed
key absence without a certificate* → quarantine as unproven; *
indeterminate execution (timeout/lost response)* → do NOT assert the key
survived; reconcile PR state first. Yield must invalidate the old
`fauth` via the owner/term CAS so a late prover cannot certify.

**Q2 where — (a) YIELD IN PLACE.** `GUARD{FENCING, owner=UNOWNED,
term=N, certificate zeroed}`. Never roll back to ACTIVE: that
reclassifies the slot as ordinary, re-opens reuse/ABA, and hides an
unresolved recovery obligation. A permanently-FENCING guard IS the
correct fail-closed state.
**Caution:** stop using ordinal `stage >= FENCED` anywhere. Every
consumer needs the positive predicate: certificate-bearing stage AND
identity/CRC valid AND `proves_exclusion(kind)` AND certificate matches
victim epoch/key/generation/term. Audit slot reuse, join scans, recovery
enumeration, admin cleanup and upgrade paths — **not just replay
dispatch**.

**Q3 certify retry — 5-and-give-up is TOO WEAK.** Once the token is
consumed, retry until success / positively-understood loss of authority
/ self-fence. Never yield. Classify a CAS mismatch: same FENCING
identity+term → retry; identical valid certificate already there →
idempotent success; materially changed → fatal invariant violation.
Do not let ordinary shutdown discard the obligation. Rejected my
"write it to A's own slot" idea; a real replicated fence-evidence
journal would be the only sound redundancy, and even that cannot close
the die-immediately-after-0x05 window.

**Q4 live-node fence — the post-0x05 overwrite I feared should NOT occur
on a conforming target** (P&A completion means the victim's task set is
aborted; later destage must preserve completed-command ordering). The
real hazard is the pre-0x05 clobber above.

**Q5 advisory/unsupported rigs — REFUSE the RW clustered mount.**
Mount-time qualification must check: PR support, unique per-node
registrations across ALL paths, WE-RO + P&A behaviour, untruncated key
visibility, multipath consistency. Fail closed if the property is later
lost — mount-time testing alone is insufficient. Defensible alternatives
are strict clustered RO (no replay, no metadata/HB writes), single-node
exclusive enforced by a hardware reservation, or a separately qualified
external fence (power/fabric/hypervisor) as its own proving kind. NOT
defensible: relabelling advisory topology or expected write failures as
proof of exclusion (which is what the tree does today).
