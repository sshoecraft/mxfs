---
name: ccloop-c7ee71c6-sess273-GPT-ruling-488-tristate-unlock-verify
description: sess273 RULE-5 ruling (-488 birth fix): tri-state unlock outcome RELEASED/STILL_HELD/UNKNOWN, verify read-back, re-mint epoch only on proven STILL_HE…
metadata:
  type: project
tags: [D-488, GPT-ruling, caw-unlock, bast-work-fn]
---

# sess273 GPT ruling — D-488 stranded-bit birth fix shape

Evidence base: sess271/272 (silent unlock paths in caw_unlock_gen_body + void
mxfs_v5_dlm_ag_unlock wrapper discards all rc; bast_work_fn unconditionally
clears demoting after unlock).

## Ruling
1. **Tri-state unlock outcome**, not errno: RELEASED / STILL_HELD / UNKNOWN.
   Worker state machine: RELEASING (demoting=1, epoch invalid, acquires
   blocked) → RELEASED→FREE; STILL_HELD→HELD(new epoch)+delayed release
   retry; UNKNOWN→quarantine (authority blocked)+escalation. Option C
   (rely on readopt repair) REJECTED as primary path.
2. **Re-mint epoch on STILL_HELD is sound** (equivalent to fresh acquire —
   grant never left the node). Must be a genuinely fresh monotonic epoch,
   never restore surrendered one; mint under pag_dlm_lock before cached=1
   becomes visible. Reuse readopt-mint as a common helper.
3. **clr_committed ambiguity**: before trusting STILL_HELD, the failed CAW
   must be quiesced (cannot complete late) and the verify read ordered
   after it + identity/gen checked. If not establishable → UNKNOWN.
4. **-ENOENT**: for a held resource is anomalous; verify, never map to
   success blindly.
5. **Deadline**: remove INODE/ICLUSTER type gate; wall-clock + retry cap;
   expiry feeds the structured outcome (is not proof of either state).
6. **RX watchdog** (not just probe): if sched=1 but work neither queued nor
   running past threshold → requeue safely (seq numbers so stale worker
   can't clear newer request's flags). RX should refresh release intent on
   BAST during sched=1.
7. **Acquire-side own-bit reconciliation** (F): acquire seeing own bit set
   with no in-core tenure → verified readopt immediately, don't wait for
   peer BAST.
8. **Dead-holder escalation (leg v)**: NEVER clear on lease expiry/stale
   gen alone (partitioned node may still write). Requires positive SCSI-PR
   fencing completed + incarnation identified + gen-protected purge.
   ARCHITECTURAL: fence-confirmed dead-lock purge must be DECOUPLED from
   torn-replay progress — a node can legitimately die holding a bit, so
   this is required for closure, not optional hardening. Health state +
   targeted fencing trigger first; unfenced override never ships.
9. Audit ALL unlock wrappers/call sites for the same void/discard pattern
   (AG, inode, icluster, purge, unmount, worker-cancel paths).
10. Crash between verify and publication must never be worse than
    "dead owner with bit set" (fence/purge path must handle independently).

## Implementation order (GPT):
structured outcome → authoritative verify → worker state machine → AG
deadline+probes → RX watchdog → acquire-side reconcile → dead-holder
escalation (fence-confirmed purge decoupled from replay).

## Core assertions for tests
- in-core FREE ⇒ disk bit proven clear
- in-core HELD ⇒ valid current epoch + disk ownership proven
- RELEASING/UNKNOWN ⇒ no local metadata authority issued
- new epoch ≠ surrendered epoch
- newer release request cannot be cleared by older worker

## Fault-injection matrix (min): find_slot -ENOENT / read err; CAS hard
fail (committed & not); 100 miscompares; deadline expiry; late completion;
read-back clear/set/gen-changed/foreign-bit/fail; worker queue loss; BAST
in every state; crash at every transition.

## Session-side analysis that fed this (verified by code read):
- caw_unlock_gen_body: AG gets NO wall-clock deadline (8499 type gate),
  paths: (a) -ENOENT→rc=0 8573; (b) find_slot err 8577; (c) CAS hard err
  8953 (clr_committed=true if caw_may_have_written); (d) exhaustion -EIO
  9030 (logged). ALL discarded by void mxfs_v5_dlm_ag_unlock (v5_mount.c
  6130). bast_work_fn:42216 ignores; 42224-42228 unconditionally clears
  demoting/release_pending.
- Own-bit reads through same target are coherent (write-back cache serves
  own writes) so a CLEAN -ENOENT is authoritative for own bit; garbled
  read would be an IO error, not ENOENT. Verify maps: found+bit→STILL_HELD,
  found+nobit→RELEASED, ENOENT→RELEASED(+probe), read err→UNKNOWN.
