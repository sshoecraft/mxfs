---
name: ccloop-c7ee71c6-sess69-GPT-ruling-advisory-PR-fail-closed-FENCED-is-false
description: sess69 GPT ruling: on advisory PR there is NO safe automatic recovery — fail closed. The FENCED stage is a FALSE claim today, and this hits INITIAL v…
metadata:
  type: reference
tags: [foreign-replay, recovery, fencing, scsipr, gpt-ruling, critical, corruption-risk, in-progress]
---

# sess69 — GPT ruling: advisory PR ⇒ fail closed; `FENCED` is a false claim today

Supersedes the "the consult answer was lost" line in
`ccloop-c7ee71c6-sess69-purge-CAS-fixed-board-green-PR-advisory` — the call
returned after the relay warning.  **Do not re-issue it.**

Context given to GPT: the recovery-descriptor wedge (refresh/takeover called
from nowhere), and the constraint that `mxfs_scsipr_fence_node()` returns 0
for "fenced, never there, **OR advisory topology**", so on the VM rig (all
nodes share ONE host I_T nexus) nothing is ever actually fenced.

## THE HEADLINE — this is bigger than takeover

> "This problem also applies to initially recovering victim V, not only to
> taking recovery over from A.  **If V has not been excluded, replaying V's
> journal while V can still write is unsafe.**"

So the defect is **not** confined to the unbuilt coordinator.  The SHIPPED
code path — survivor sees peer death, calls `fence_node()`, gets 0, records
stage `FENCED`, replays the victim's journal slice in place — is performing
in-place XFS replay against a node that may still be writing, on every rig
where PR is advisory.  `FENCED` is a durable on-disk claim of a guarantee
that was never obtained.

**P0 is corruption prevention, not design work.**

## The five answers

**1. Takeover predicate.**  Descriptor CAS serializes the *record*; it does
not serialize or revoke bulk writes an old replay worker can issue to
unrelated LBAs.  Therefore: abandonment time is only a failure detector;
`owner_term` is only a label unless the *device* enforces it on every affected
write; a tombstone preserves evidence but **cannot manufacture exclusion**;
reactive fencing (EBADE on next write) is insufficient if the first stale
write can reach metadata.  Required evidence is one of: PR
preempt-and-abort that actually covers that incarnation's distinct I_T nexus
*and drains/aborts outstanding commands*; platform/VM/HBA fencing + I/O
drain; an owner-written clean-quiescence ack published only after it stopped
submissions and drained; or a rigorously specified watchdog/reset with real
timing and drain guarantees.  Liveness conditions (owner not live, descriptor
stable for ABANDON_MS) **do not substitute** for exclusion.

Two distinct exclusion facts — **victim exclusion** (V cannot write while its
journal is replayed) and **previous-recovery-owner exclusion** (A cannot
continue an old replay after B takes over).  **Do not overload one `FENCED`
stage to mean both.**

**2. Fail closed — yes, and it is the honest answer.**  "Allowing recovery to
proceed would trade an availability failure for possible silent metadata
corruption.  For a filesystem, that is the wrong trade."  But it must be an
explicit, actionable state, e.g. `RECOVERY_BLOCKED_NO_IO_EXCLUSION`, with
real escape hatches: hypervisor/BMC/power fencing, SAN port or initiator
fencing, fencing a whole shared-nexus host even if that removes several
members, full-cluster quiesce + offline recovery, or administrative
submission of a *verified* fencing result.  **An admin must not be able to
just set a "fenced" bit** — the action must perform or verify real exclusion.
If automatic recovery is a product requirement, advisory-only hardware must be
rejected at mount/cluster formation or advertised as lacking automatic
recovery.  A controlled fail-closed outcome is a documented availability
limitation; **silently treating advisory PR as fencing is a correctness
defect.**

**3. Gating bulk replay writes on `owner_term` via C&W — NOT constructible.**
The race survives: A verifies term 7 → A queues an ordinary metadata write →
B CASes to term 8 → B starts replay → A's term-7 write lands after.  C&W on
the *descriptor* does not condition a write to an unrelated LBA.  Per-target
CAS is sound only if the authority term lives *inside the same atomic C&W
range as the data*, every writer (including normal XFS writeback) uses the
protocol, takeover converts each block's term first, and no previously
submitted ordinary write can overwrite a converted block.  "Read target, check
descriptor, C&W target" is also insufficient — the target comparison proves
only that the data did not change, **not that we still own authority**.
Safe-and-live software-only recovery requires one of: device-enforced
per-write authority tokens; conditional writes with the authority value in the
same atomic unit; COW/private replay + a single authority-gated atomic
publication; or a rigorously bounded lease + independent watchdog/reset.
All are filesystem-architecture changes, not descriptor enhancements.

**4. Split the stage and record WHICH guarantee was obtained — yes.**  Fix the
API first: return a typed outcome, not 0/-errno —
`HARD_PR_DRAINED / PLATFORM_DRAINED / OWNER_QUIESCED_DRAINED /
ADVISORY_ONLY / NOT_SUPPORTED / FAILED / STALE_INCARNATION`.  Only the first
three authorize execution; `ADVISORY_ONLY` must never advance to an
exclusion-proven stage.  For PR specifically, distinguish: unique nexus/key
identified; preempt completed; outstanding I/O aborted/drained; shared-nexus
topology.  "A successful command that does not identify and exclude the
intended I/O capability is not a successful fence."
Wire format (still free — no deployed cluster has written a descriptor):
prefer explicit fields over clever reuse —
`u16 stage; u16 victim_exclusion_kind; u16 owner_exclusion_kind; u16 reserved;`
with values NONE / HARD_PR_PREEMPT_ABORT / PLATFORM_FENCE_DRAINED /
OWNER_CLEAN_QUIESCE / WATCHDOG_RESET_DRAINED / ADVISORY_ONLY.  Keep `version`
a real format version.  Better stage names:
`CLAIMED → VICTIM_EXCLUSION_PROVEN → IMAGES_REPLAYED → OBLIGATIONS_DONE →
GRANTS_RELEASED`.  Bind evidence to exact incarnation, I/O identity/fencing
scope, fence method, and fence certificate id — **a PR fence of a shared host
nexus may fence several nodes or none, so node ID alone does not describe the
scope.**

**5. Per-image progress is independently required — (3) does NOT subsume it.**
Authority/exclusion stops concurrent-or-late effects; progress tracking
handles a crash *after* an effect completed but *before* its record was
published.  Even with perfect fencing, "write image; update progress" has a
crash window, so the tail must be repeat-safe.  Structure: validate
gen+authority → apply image/batch → flush data → CAS+flush progress →
continue; resume from the last durable prefix and assume the next image may
already be applied.  Monotonic prefix beats a bitmap when ordering matters.
Each effect must additionally be idempotent, a deterministic after-image
applied while modification is excluded, conditional on an expected old
version, or deduplicated by durable operation ID.  **Same for obligations and
grant release — one coarse `OBLIGATIONS_DONE` bit does not remove the crash
window.**

## Implementation order (GPT's, adopted)

- **P0 — stop recording false fencing.**  Typed fencing outcomes; never record
  `FENCED` on advisory topology; **block both initial replay and takeover
  replay without proven exclusion**; explicit blocked state + diagnostics;
  audit whether our PR path uses an operation with real abort/drain semantics
  and whether the target gives unique per-node I_T nexuses.  *This is the
  immediate corruption-prevention fix.*
- **P1 —** separate victim vs owner exclusion invariants; explicit exclusion
  kinds in the wire format; bind evidence to incarnation + I/O scope; platform
  /administrative fence integration; clean-quiescence as its own evidence class.
- **P2 —** safe refresh + takeover (refresh improves detection, never replaces
  exclusion); stale owners must not advance/zero/release after losing the CAS.
- **P3 —** ordered per-image progress; crash injection at every
  "effect done, progress not advanced" boundary.
- **P4 —** decide the supported liveness contract: require hardware/platform
  fencing for automatic recovery, support advisory rigs only with manual/
  host-wide fencing, or redesign around per-block authority / COW publication.

## What this means for the campaign

P4 is a **product-level** decision that bears directly on "is it production
ready?".  On the current VM rig, automatic recovery cannot be made safe by any
descriptor-level change.  The defensible position is: fail closed on advisory
PR, and require real per-node PR (or platform fencing) for automatic recovery
— then verify on the physical rig, where PR may genuinely be active
(see `physrig-fixes-v74-76-landed-and-verified`).  **Audit that first** — if
the phys rig gives unique per-node I_T nexuses with working preempt-and-abort,
P0's blocked state is rare in production and common only on the VM rig.

## Next session — start here

1. **Ledger three defects** in `tests/criteria/OPEN_DEFECTS.json` (the board's
   `open_defects` cell reads it): (a) purge non-atomic publication — FIXED in
   0.11.412, concurrent-purger verification still owed; (b) `FENCED` recorded
   without proven exclusion — **critical**; (c) in-place victim replay
   dispatched without proven victim exclusion — **critical**, this is the
   corruption risk.
2. Implement **P0**.  It is a contained change: typed fencing result, a
   blocked state, and gates at the two replay-dispatch sites.
3. Re-board (0.11.412 is a green baseline: fence_during_write 17/60,
   crash_consistency 204/204 86/90, dir_reuse_coherency 93/93 107/120).
   Expect the advisory-PR rig to now REFUSE recovery — that is the fix
   working, and it will turn recovery criteria red until P4 is decided.
   Do not "fix" that by loosening the gate.
