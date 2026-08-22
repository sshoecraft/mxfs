---
name: ccloop-c7ee71c6-sess379-GPT-ruling-detector-io-off-the-fast-path
description: sess379 RULE-5 ruling for D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B: detector I/O must leave caller context; deferred samples need ABA-proof generati…
metadata:
  type: project
tags: [ruling, gpt, rule5, 526B, detector, fua, caw, rule0, sess379]
---

# sess379 RULE-5 ruling — taking detector I/O off the DLM fast path

Consulted with the sess379 root-cause evidence (32-node mass umount: 30/32 nodes'
`statx()` blocked 60.5 / 121 / 181.5 s inside `mxfs_pal_scsi_read_fua_bdev`, all on
**the same LBA 144080** = the root directory inode's CAW slot; `ret=0x30000` =
`DID_TIME_OUT`).

## The framing the ruling insists on

> The central correctness question is not "synchronous versus deferred." It is:
> **is the cached grant independently authoritative, or is the verify read part of the
> protocol that makes the grant safe?**

If cached grants stay valid until an explicit revoke/release/fence transition, both
verifies are DETECTORS and belong off the caller's path. If a peer can take a
conflicting grant while this node still believes its cached grant is valid, the DLM
protocol is already unsafe and a 1 Hz poll does not establish mutual exclusion either
way.

Corollary the ruling draws from the existing throttles: a 100 ms / 1000 ms throttle
**already** admits operations inside the unverified window, so neither check is a full
correctness barrier today. At most each gives detection of a persistent fault,
probabilistic containment, and shorter time-to-notice.

## Per-check verdicts

- **(A) P108 stale-EX verify** (cached EX, or cached PR + PR request; 1000 ms/inode):
  move out of caller context. Sound *if* grants are revoke/fence-authoritative.
- **(B) dir-EX phantom verify** (cached dir-EX serve; 100 ms/inode on CAW): do NOT
  defer merely on the "throttle already allows TOCTOU" argument. Either prove cached
  EX is independently authoritative, or keep a **bounded, fail-closed** check *at the
  mutation boundary* (where the inode is about to be dirtied under EX) — never on an
  unrelated cached serve such as `getattr`. "A 20-minute synchronous check is not a
  safe answer. It preserves safety only by destroying liveness."

## A deferred sample is NOT retrospective validation

A later read cannot prove the slot was valid at the earlier serve. A local tenure
counter does not exclude **ABA**: local tenure unchanged, on-disk grant lost and
re-obtained, conflicting op in between, slot looks valid again when the sample lands.

Capture at queue time: lock/inode key + slot identity, local grant-tenure generation,
requested and cached mode, expected holder/node incarnation, membership/fencing epoch,
expected on-disk grant generation, mount incarnation, reason. Prefer wide
monotonically-increasing ON-DISK generations; a local-only generation is insufficient.

On completion: retake the local DLM lock, re-validate incarnation/tenure/epoch, discard
if stale, and on a real mismatch mark the cached grant **SUSPECT under the same lock
the fast path uses** so no new cached serve slips past. Do not "just reacquire" a
phantom EX — that hides evidence after possible corruption; prefer quiesce/withdraw/
fence unless you can prove no mutation occurred in the suspect interval.

## The single-LBA hotspot is a SEPARATE defect

Moving reads to a workqueue without load control just converts a syscall stall into an
async I/O storm. Required: at most one outstanding verify per inode/tenure; a **per-LUN**
concurrency cap (not merely per-inode); global detector rate limit; randomized jitter so
32 nodes do not sample in lockstep; time-based (not op-count-based) scheduling;
exponential backoff after timeout/congestion; exported skipped/timed-out/mismatched
counters; and **unmount must not flush indefinitely-blocked detector work**.

On the alternatives offered: verifying PR from a non-CAW location is valid only if that
location is authoritative and transactionally ordered with grant changes (a casual
mirror lets the detector validate stale data); heartbeat piggyback proves node liveness,
not that a particular inode grant is still held — making it work is a protocol redesign;
"accept it, healthy reads are fast" is rejected — 32 nodes polling one serialization
point is inherently vulnerable to target queueing, EH, failover, ALUA transitions and
synchronized retry storms.

Preferred long-term model: verify ownership at acquisition/transition boundaries, hold
it through revoke-ack + membership epochs + fencing, never poll storage on a cached
serve, and run bounded jittered background scrubbing for defense in depth.

## Retry / deadline discipline

`30 s × 2 SCSI attempts × 20 wrapper attempts` is exactly the failure-amplification
pattern to remove. Use ONE absolute monotonic deadline per logical operation, attempt
budgets capped by remaining time, a small bounded attempt count, retry only for
explicitly classified transient results, jittered backoff, and **no nested independent
retry policies**.

For a detector read: no answer = **no sample**, NOT "grant is valid". Skip, count, back
off, escalate only if verification stays unavailable for a sustained interval.

Caution the ruling adds: do not aggressively shorten SCSI request timeouts — that can
cause SCSI EH / abort / reset / path-failover storms worse than the original detector
load. Logical deadlines plus concurrency control are safer.

For an authoritative (correctness-path) DLM read, a timeout may never be treated as
success: fail the acquire (`ETIMEDOUT`/`EAGAIN`/`EIO`), and if the node may hold EX but
can no longer renew a lease or process revokes, quiesce and withdraw/fence BEFORE the
safety window expires.

**CAW retries need special care**: a timed-out COMPARE AND WRITE has an ambiguous
completion state — the target may have performed it. Never blindly retry a
non-idempotent CAW; reconcile with an authoritative read using unique
operation/tenure generations.

## Deferred-work lifetime hazards named

inode reclaim while work holds a pointer; unmount waiting on a stuck detector; work
running after mount/membership incarnation change; module unload / workqueue
destruction; a result applied to a reused inode or slot; unbounded workqueue growth
during target failure.

## Follow-up the ruling flags as HIGHER priority than the perf fix

The **one** P108-REACQUIRE observed across 32 nodes in a ~2 h boot must be understood
before weakening (B): dump old/new slot contents, node ids/incarnations, grant
generations, membership epoch, whether the inode was mutated in the suspect tenure,
whether it was an ABA/reuse artifact. "Low detector yield is not the same as low
consequence." If it was a genuinely lost grant, that protocol defect outranks this one.

## Recommended order (verbatim intent)

1. Audit the DLM invariant + the single P108 event.
2. Split APIs: authoritative DLM I/O vs diagnostic scrub I/O, different timeout/retry/
   failure semantics.
3. Remove (A) from caller context.
4. (B): prove EX independently safe and defer, OR bounded fail-closed check only before
   mutation while fixing the protocol.
5. Replace nested retries with an absolute logical deadline.
6. Per-LUN concurrency limit, coalescing, jitter, backoff for detector work.
7. Tenure/incarnation/on-disk-generation validation on deferred samples.
8. On phantom EX prefer withdrawal/fencing over silent reacquisition.
9. Unmount and reclaim must not wait indefinitely for detector work.
10. Long term: eliminate per-serve slot polling entirely.

## Nit accepted

Do not describe READ FUA as "bypasses the target cache" — FUA imposes freshness
semantics that an implementation may satisfy from a coherent cache. The material
behavior here is SCST's overlap serialization between CAW and READ on the same range.
