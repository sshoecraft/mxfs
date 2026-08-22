---
name: ccloop-c7ee71c6-sess289-GPT-ruling-488-legs7-8-readopt-mint-manifest-purge
description: sess289 RULE-5 ruling (D-488 legs 7+8): forced READOPT mint (never restore surrendered epoch), rx READOPT_PENDING state, leg-8 shape A copy-before-cl…
metadata:
  type: project
tags: [D-488, GPT-ruling, readopt-mint, victim-manifest, leg8-purge]
---

# sess289 GPT ruling — D-488 closure legs 7+8

Evidence base (sess289 code read): CAW already-held fast path
(dlm_caw.c:7388-7568) reaffirms with the slot's OLD ex_grant_epoch, no
CAS/no mint; STILL_HELD re-arm (xfs_mxfs_dlm.c:42449) comment claiming a
fresh mint is FALSE; rx readopt (41799) sets cached=true with epoch 0 →
epochless-writing-tenure window via cached reclaim; dead-bit purge only
in recovery_complete after IMAGES_REPLAYED (v5_mount.c:3523); victim
manifest read (dlm_caw.c:3401) depends on that coupling.

## Ruling 1a — fresh mint MANDATORY on post-surrender readopt
- Restoring the surrendered epoch is NOT acceptable; closure assertion
  "new epoch != surrendered epoch" stands. WRITE_ONCE(epoch,0) is an
  authority surrender; the old epoch must never authorize new activity.
- New narrowly-scoped READOPT mint transition (distinct from sess169
  edge-trigger, which stays for ordinary grants):
  legal only when: own bit present for expected incarnation + local
  published epoch == 0 + no incompatible peer + proven surrendered/
  post-drain orphan (not ordinary reentrant acquire) + compare image
  still shows expected Eold/identity/gen/lineage.
  CAW leaves bit present, overrides preserve arm, writes fresh
  monotonic Enew != Eold. Publish in-core ONLY after definite CAS
  success or verified read-back of exact intended image. On mismatch/
  unresolved: never restore Eold, no metadata writes, quarantine.
  Crash after CAS before publication: later readopt mints AGAIN (never
  publish Enew just because found on disk).
- Already-held reaffirm GUARD: reaffirm allowed only if local published
  epoch != 0 && == slot epoch && tenure active. Own bit + local epoch 0
  is NOT reaffirmation.
- Old Eold log records: refusal at foreign replay is acceptable ==
  genuine release→reacquire boundary (Invariant 1 homed everything);
  replay must skip stale images but complete bookkeeping. Equivalence
  REQUIRES post-drain provenance proof; a path that cannot prove it
  must NOT mint (would invalidate possibly-needed old-epoch replay).
- Tests: force STILL_HELD; verify CAW despite bit present, bit never
  absent, Enew > Eold; no local write before publication; crash-inject
  at before-CAS / after-CAS-before-publish / ambiguous / after-publish;
  no recovery path republishes Eold; Eold images rejected, homed
  metadata correct.

## Ruling 1b — rx path: READOPT_PENDING state, never silent cached=true
- BAST observing own bit + no tenure sets READOPT_PENDING (not cached
  ownership, not write authority) under the AG lock; queues worker off
  the rx path. Concurrent local acquire joins/waits or retries; must
  not cached-reclaim, must not write.
- Worker rereads slot: bit gone → clear pending; proven post-drain
  orphan → same verified READOPT mint as 1a, publish, drain/release,
  service BAST (cleanup-only: don't hand temp tenure to writers before
  drain obligation); provenance/CAW unprovable → quarantine.
- Extend P243 no-authority probe to EVERY writable-tenure entry path
  (cached reclaim + rx readopt, not just fresh acquire).
- Tests: inject BAST w/ bit present + epoch 0 + racing local acquire;
  assert cached=true never visible without nonzero published epoch; no
  AG write during READOPT_PENDING; exactly one serialized forced mint.

## Ruling 2 — leg 8: shape A, resumable COPY-BEFORE-CLEAR sweep
B (targeted) insufficient; C (replay-wedge fix only) necessary but NOT
closure. Required architecture:
1. Fence+identify: positive SCSI-PR confirmation bound to exact victim
   incarnation; versioned recovery descriptor under GUARD/freeze;
   durable recovery epoch + FENCE_CONFIRMED. Lease expiry alone never
   authorizes a clear.
2. Durable victim manifest OFF the HB thread: resumable worker
   enumerates slot table; per victim slot: read+validate identity/mode/
   epoch/gen/lineage → append manifest record to durable descriptor →
   make durable BEFORE clearing → gen/incarnation/lineage-protected CAW
   clear → ambiguous results resolved by read-back (manifest committed
   first so absence loses nothing). Progressive retirement OK. Then
   durable MANIFEST_SEALED. Idempotent/restartable.
3. Replay evaluator uses the DESCRIPTOR manifest, not live bits. Simple
   rule: FENCE_CONFIRMED → sweep → MANIFEST_SEALED → victim replay
   evaluation (clears may progress before seal).
4. Recovery-ordering barrier survives physical purge: recovery
   reservation/freeze per resource so elected replayer acquires without
   blocking on former victim bit; ordinary writers can't overtake
   required replay; unresolvable replay → explicit RECOVERY_BLOCKED
   quarantine, never CAW-holder livelock, never restore dead bits.
5. Epoch replay gate adjustment: fenced-victim replay validates against
   SEALED MANIFEST epoch/lineage + descriptor incarnation + recovery
   epoch/guard + barrier — a narrow recovery exception; normal paths
   keep current-slot-epoch equality.
Failure semantics: no fence → no clear; manifest write fail → no clear;
crash windows all idempotent via manifest-first ordering; node-ID reuse
protected by exact-incarnation+gen checks; descriptor corruption/lost
GUARD → fail closed.

## Implementation order suggestion (mine): 1a guard+mint helper first
(small, closes the active epoch-discipline defect), then 1b state, then
leg-8 sweep (largest; touches descriptor format + replay gate — overlaps
#1 D-FOREIGN-REPLAY-UNGATED-IMAGES enforcement design).
