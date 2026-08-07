---
name: ccloop-c7ee71c6-sess32-GPT-ruling-A-D-foreign-replay-stop-ship
description: GPT sess32 ruling: foreign BUFFER replay ungated = stop-ship (contain: skip buf/dquot/icreate live); P222 unlanded→shutdown; inodegc must reacquire a…
metadata:
  type: project
---

# sess32 — GPT ruling on conditions 2/4/7 + release-quiescence root fix

Full text in transcript (session 14, task kj7vxsw61). Implementation order ruled:

1. **C containment FIRST (stop-ship hole)**: live foreign-slice replay applies
   BUFFER records (dir blocks, AGI/AGF, btrees, ifree'd cluster bufs) with the
   upstream LSN gate — cross-slice LSNs are INCOMPARABLE (our own sb-lsn check
   admits this), so false-APPLY reverts survivor state and false-SKIP drops the
   dead node's acked changes. dquot/icreate same (noquota moots dquot).
   Containment = skip untagged buf/dquot/icreate images in live foreign replay
   (inode records STAY: di_changecount gate is node-independent and correct),
   or block survivor resume / require exclusive-offline recovery. Mount-time
   re-replay of the still-dirty slice has the SAME hole (survivors resumed).
2. **A fail-closed**: P222 unlanded-at-NL = invariant assertion → dedicated
   fatal counter + full capture + xfs_force_shutdown (default). Never bare
   PUB_SKIPPED at NL (measured AIL livelock), never ledger-only. Old behavior
   allowed only as explicit debug mode.
3. **D root fix (primary)**: deferred inactivation (inodegc) must REACQUIRE
   publication authority BEFORE it can dirty/attach/stage covered metadata:
   select by ino+incarnation → acquire inode DLM fresh grant → AG/cluster
   authority in protocol lock order → revalidate orphan → inactive/ifree under
   fresh token → land → release via ordinary drain. ISTALE/ifree_cluster needs
   an explicit authority class (AG or inode-cluster resource) — reacquiring
   only the target inode is insufficient for cluster-wide ISTALE attach.
   (c) BAST-pending eager inactivation = optional optimization only.
   (a) mount-wide inodegc flush = rejected (too broad, no authority rule).
4. **C full protocol**: log records must carry authority tokens
   {resource_id, grant_incarnation, tenure_id} captured at logging time;
   replay applies iff token == exact grant held at death (held-at-death ALONE
   insufficient — old-tenure records of a re-held resource can still revert);
   released-tenure records skip ONLY once D's landing invariant is in;
   unknown/untagged → fail closed. Durable manifest: capture held-set+tokens
   pre-purge, checksummed; IMAGE_REPLAY_DONE marker gates purge/survivor
   resume; mount-time recovery sees marker → suppress image records, process
   retained intents. Replayer death: restart from manifest while quarantined.
   Untagged old logs: no live foreign buffer replay, require upgrade
   checkpoint or offline recovery.
5. **B EX-side gate LAST** (regular inode images only): capability-based
   (validate resource id + grant incarnation + epoch vs the token of THIS
   submit), not mode==EX. EX skips set PUB_SKIPPED UNCONDITIONALLY (retry can
   succeed at EX): restage under same grant if still held / transfer to
   release drain / authority-reacquiring destage if lost. Never blind repush
   at NL. Keep pending_seq as obligation. ISTALE/ifree publication EXCLUDED
   until it has an explicit authority class. Separate knob
   (stale_stage_skip_ex), never overload the NL knob. Measure: EX skips /s,
   retries-to-land, drain extension, AIL tail age, repeated-skip assertion.

## D-RELEASE-BARRIER-OPEN closure criteria (GPT)
(1) code audit: inodegc cannot dirty/stage without valid token; (2)
deterministic race injection shows reacquire-before-first-dirty; (3) SOURCE
counters zero (inodegc dirty-at-NL, stage-at-NL, ISTALE-attach-without-
authority, class-X stage!=authorized, P219 orphan detections), not just wire
counters; (4) mask stays on, zero class-X across guard board + extended
unlink/reuse/BAST stress; (5) reacquired tenures drain clean (no AIL growth /
leaks); (6) pace within 2x ceiling; (7) crash/replay + reuse tests with
faults injected at 5 points (before dirty, during ifree, after commit,
during landing, during reacquired release).

## Class-X mechanism (refined this session, fits ALL measurements)
Pre-free orphan flush LANDS under its tenure (durable==flush, IFLUSHING
clears) → release bumps epoch (flushing=0 at bump ✓) → LATER ifree_cluster
ISTALE-attach sets IFLUSHING with NO restamp (stage stays old) → xfsaild
submits cluster at NL with pre-free bytes → P219 stale_nl, landed ✓ →
mask skips losslessly ✓. The freed-state (mode=0) write publishes under the
live ifree tenure (ex=true → no mask) — freed-at-NL would require the drain
to have missed it (the same release-barrier hole; defense in depth).
