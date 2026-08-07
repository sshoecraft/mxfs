---
name: ccloop-c7ee71c6-sess118-GPT-ruling-clear-window-8-blockers
description: sess118 RULE-5 ruling: snapshot-before-read CONFIRMED; but 8 release blockers — the residual demotion window stays IN SCOPE, and 50ms fail-forward is…
metadata:
  type: reference
tags: [mxfs, dlm-caw, lreq-registry, sess118, gpt-ruling, samenode-waiter, stop-ship]
---

# sess118 RULE-5 ruling on the clear-window linearization

Consult put the sess117 clearer side + the sess118 publication side to GPT with
four questions. Verdict: **"I would not take this to the 32-node rig as
release-candidate code yet"** — 2 hard blockers + 6 conditional.

## Q1 — snapshot ordering: MY CORRECTION IS CONFIRMED

Snapshot MUST be taken BEFORE the slot read. The sess116 design note ("after
the read") was wrong; sess118 implemented it before. GPT reproduced the exact
missed execution (clear begins, commits, ends, THEN we snapshot the new seq and
validate equal → publish stale holder). Snapshot-before-read catches all three
overlap shapes: active at snapshot (`quiet==false`), still active at validation
(`clr_active != 0`), begins-and-commits in between (`clr_seq` moved). False
retries are possible; false acceptance is not.

Three qualifications, each of which is work:

- **(B) "committed" must mean MAY-HAVE-CHANGED, not DEFINITELY-CHANGED.** An
  ambiguous CAW outcome (I/O timeout, transport error — "may have reached the
  target") must NOT end the window with `committed=false`. Only a definite
  compare-miscompare/no-write may stay noncommitted. Otherwise a destructive
  change happens invisibly to validation.
- **(C) registry-entry ABA.** `clr_seq` is monotone only over the entry's
  lifetime. GPT rejects keeping "entry absent at validation ⇒ true" as a
  general rule — it is safe only if disappearance is provably impossible.
  Required: either pin the entry in the snapshot token, or (preferred, "much
  easier to audit") **treat disappearance as validation FAILURE**.
- **(A)** the read-sees-completed-CAW property is a platform prerequisite of the
  whole disk DLM, not a flaw in this ordering. FUA alone is not the proof.

## Q2 — the residual post-validation window: DIAGNOSIS RIGHT, SCOPE RULING WRONG

My (a)–(d) were all accepted as technically correct: it is not shortcut-
specific; atomic tenure publication does not help (unlock ignores tenure);
waiting for `attempts == 0` is the wrong lifetime boundary (attempts covers
ACQUISITION, not USE); only the layer that knows dependent-use lifetime can
quiesce it.

**But the conclusion "therefore out of scope" is REJECTED.** It may be
unfixable inside `dlm_caw.c` with the current API, but it remains a system
correctness requirement and a release blocker. Exactly three acceptable
dispositions:

1. land the XFS-layer demotion/admission/quiescence work before enabling this;
2. redesign the DLM interface to carry an **active-user reference released
   after actual use** (`use_begin`/`use_end` around the grant, demoter sets
   `demoting`, blocks new users, waits for `active_users == 0`, THEN clears);
3. prove that every caller of normal unlock AND force-release has already
   performed equivalent resource-wide quiescence.

RULE-0 does not buy an exemption: "If quiescence regularly takes too long, the
design has a performance failure, but clearing early turns it into corruption."
The BAST handler may hand the demotion to an async worker; the on-disk clear
still may not precede quiescence.

`mxfs_dlm_caw_force_release_self` needs an EXPLICIT precondition — same defect
across more slots if it can run while this mount still issues dependent I/O.

## Q3(a) — the bounded 50ms fail-forward wait: NOT ACCEPTABLE

"The next attempt will collect the owed state" is insufficient — **there may be
no next attempt from this mount**. A stranded waiter bit then blocks another
node for the rest of the mount, turning a rare 50ms race into an unbounded
cluster stall. 50ms is also not a meaningful upper bound for shared storage
under error recovery, queueing, path failover or 32-node load.

Required remedy — owed work needs a GUARANTEED-PROGRESS EXECUTOR: a pinned
per-resource cleanup work item queued immediately, persistent rescheduling,
entry retained until the cleanup succeeds or the mount is terminally
fenced/shutdown, and the worker must NOT depend on another acquisition of that
resource.

**Better still (GPT's preferred restructure): have the clearer record its
cleanup intent/owed state under the registry mutex BEFORE entering the long
disk-I/O portion.** Then `lreq_finish` need only synchronize with the short
intent-publication phase instead of waiting out the whole clear window — the
wait shrinks to nothing and the orphan case disappears.

## Q3(b) — per-iteration plan re-derivation: CORRECT, with one condition

Right and necessary for a single-slot failed-CAS retry loop: a miscompared
iteration changed nothing, so only the successful iteration's plan takes
effect. Becomes UNSAFE if any iteration takes a side effect before the final
successful CAS — specifically including **"recording or consuming owed state
irreversibly"**, modifying another slot, updating local tenure as if committed,
or clearing one bitmap in a separate successful operation and then retrying
another. If one logical give-up is several independently successful disk
transitions, per-iteration freshness does NOT make the aggregate transactional.

(Note for MXFS: `lreq_plan` DOES record owed state as a side effect on every
derivation. Monotone OR-ing, but a later successful CAS does not retract the
owed flags an earlier iteration set — audit item.)

## Q4 — additional checks

- **(i) two separate mutex acquisitions**: fine, that is the point of an
  optimistic sequence protocol. Invariants to hold: `clr_active++` under the
  mutex before any destructive I/O is submitted; `clr_active--`/`clr_seq++`
  atomically after the op is complete-or-possibly-complete; no destructive path
  bypasses begin/end; validation after the read; entry identity cannot vanish
  and be recreated unnoticed; counters must not wrap into an accepted state.
- **(ii) allocation**: alloc-outside-lock/recheck/free-loser is deadlock-safe,
  BUT — allocation must not happen with a lock held whose reclaim path re-enters
  MXFS/DLM; **`lreq_clr_begin` allocation failure MUST fail closed** (a
  destructive clear may not proceed without registering `clr_active`); and a
  join/snapshot alloc failure must not silently select the "legacy"
  unregistered path. Prefers a mempool/reserve or guaranteed async retry. "An
  ENOMEM fallback that proceeds without registry coverage is a correctness
  defect." Needs lockdep + allocation-flag inspection.
- **(iii) shortcut livelock**: starvation is possible but not unbounded IF every
  retry path shares the ORIGINAL ABSOLUTE DEADLINE, the retry count is not reset
  by an outer state, expiry returns failure (never accepts an unvalidated
  shortcut), and the 1ms sleep is shutdown-compatible. Audit for nested loops
  with separately initialised deadlines.
- **(iv) tenure[] increments but is only cleared en masse: POTENTIAL BLOCKER.**
  With no per-acquire release, repeated cached acquisitions are not
  independently releasable tenures. Make it a **latch/boolean or saturating**
  value — an ordinary wrapping counter can wrap to zero and produce a false "no
  tenure" decision. `lreq_release_all(pub_seq0)` retaining tenure is a correct
  fail-closed immediate action but NOT a complete reconciliation policy: name
  the operation that eventually retires retained tenure, and guarantee it runs
  without requiring another acquisition of the resource.

## The checklist GPT requires before a rig cycle

1. post-validation demotion race — XFS quiescence or equivalent must be present
2. fail-forward owed cleanup — guaranteed async progress, not "next access"
3. ambiguous CAW result — must advance/invalidate `clr_seq`
4. registry epoch — fail validation on entry disappearance
5. allocation failure — destructive ops cannot bypass registration under ENOMEM
6. tenure wrap/staleness — latch/saturate + guaranteed reconciliation
7. force-release precondition — prove it runs only after dependent activity
   stopped, except in a terminal fenced state
8. multi-step clears — every successful sub-operation must be reflected in the
   clear sequence and stay safe if later steps use a different plan
