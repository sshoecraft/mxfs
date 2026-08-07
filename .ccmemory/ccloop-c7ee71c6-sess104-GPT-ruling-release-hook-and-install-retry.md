---
name: ccloop-c7ee71c6-sess104-GPT-ruling-release-hook-and-install-retry
description: sess104 RULE-5 ruling: the dead release-begin hook IS a defect (i_dlm_mode is a local summary, not the release linearization point); auth_line is the…
metadata:
  type: reference
tags: [mxfs, gpt-ruling, authority, step5.3, rule5]
---

# sess104 RULE-5 ruling — release-hook discipline + the right probe

Evidence put to GPT: the sess104 P240 measurement, FINDING A (dead
`mxfs_inode_authority_begin_release_locked`, release_begin=0 / backstop=2486)
and FINDING B (`notvalid` conflating two opposite meanings). Full context in
`ccloop-c7ee71c6-sess104-authcap-MEASURED-two-findings`.

## 1. The dead release hook IS a defect

The mode-lowering backstop is sufficient ONLY if this holds:

> No event that permits another node to acquire or act on the relinquished
> tenure can become visible before the local `i_dlm_mode` transition that
> invokes the backstop.

**That is not generally true for a DLM.** `i_dlm_mode` is a LOCAL SUMMARY, not
the distributed release linearization point, and memory ordering around its
store cannot repair ordering against a peer-visible disk update. These
routinely precede local cached-mode cleanup: marking a slot releasing;
publishing an unlock/downgrade/handoff; sending a release or conversion
request; changing route or owner; allowing a waiter to advance; recovery
deciding the old grant is no longer authoritative.

MXFS's own comment on the dead function documents exactly this ordering, which
is strong evidence the design knew it. Classify as a real invariant violation.

### The boundary is publication, not a function name

A token is not false merely because release processing entered some local
function. The boundary is the first point after which EITHER the local node
may no longer initiate protected mutations under the old epoch, OR a peer can
observe progress toward acquiring it. If release preparation is private,
abortable and unobservable, the old tenure is still valid.

### Required order

1. Close the local mutation gate for the old tenure.
2. Drain/serialize against in-flight protected mutations, INCLUDING their
   first-dirty capture.
3. Under the authority serialization, set RELEASING; old epoch unavailable to
   new captures.
4. ONLY THEN any peer-visible release/handoff/downgrade/slot update/route change.
5. Lower `i_dlm_mode` last. The backstop verifies cleanup; it is not the
   revocation point.

**Hooking too EARLY is the opposite bug**: an already-authorized in-flight
mutation reaches `xfs_trans_dirty_buf` after authority was cleared and gets
stamped NONE. The hook must be after local mutation exclusion/drain and before
external publication.

### Site-class rule (do NOT enumerate functions)

> Every operation that can make the current durable write epoch unavailable to
> new local mutations, or can make relinquishment of that epoch externally
> observable, must pass through ONE centralized release-publication primitive,
> which requires authority state RELEASING/non-durable before publication.

Semantic classes: voluntary unlock from a write-capable mode; downgrade or
conversion out of the write class; remote recall / blocking-callback surrender;
direct handoff to a waiter; cancellation paths relinquishing a published grant;
forced demotion, lease expiry, withdrawal, fencing; resource routing/ownership
migration; reclaim/eviction/teardown releasing clustered authority; recovery or
epoch-namespace reset invalidating a tenure.

Ideally all converge on one primitive. Put ASSERTIONS at peer-visible
publication points (e.g. no live DURABLE_EX epoch remains).

If release is aborted after RELEASING, restoring the old epoch is safe only if
nothing was published. Once publication may have happened, require a FRESH
durable acquisition — never resurrect the old epoch.

Keep the backstop, but as a diagnostic: revoke defensively, count a "late
revoke" invariant violation, warn when a write-capable mode is lowered while
still DURABLE_EX. Healthy systems reach mode-lowering already RELEASING/NONE.

**Note:** Finding A does not by itself explain the NONE population — late
revocation permits stale DURABLE captures, the opposite symptom. It contributes
only indirectly (backstop revokes, then the next acquire fails to reinstall).

## 2. FINDING B — split at snapshot construction

The split (non-writing mode) vs (writing mode + zero epoch) is the correct
first discriminator. `valid` collapsed "not applicable" with "broken/incomplete
authorization record". The unreachable `shared` bucket confirms the ordering
problem; reading its 0 as a measurement is wrong.

Classify where `gres` is CONSTRUCTED, while `held` and `ex_grant_epoch` are one
coherent snapshot. Prefer a TAGGED STATUS over another boolean — it prevents
impossible combinations and extends cleanly:

    enum mxfs_grant_auth_status {
        MXFS_GAUTH_WRITE_EPOCH, MXFS_GAUTH_NONWRITE_MODE,
        MXFS_GAUTH_WRITE_ZERO_EPOCH, MXFS_GAUTH_NO_RESOURCE,
        MXFS_GAUTH_UNPUBLISHED, MXFS_GAUTH_STALE_GENERATION, ...
    };

Two cautions: use ONE helper `mxfs_mode_can_write()` everywhere (do not mix
`>= PW` with exact `EX || PW` unless enum ordering is part of the contract);
and do NOT zero/discard the mode just because the result is invalid.

"Write mode with zero epoch" proves an incomplete snapshot, NOT necessarily a
permanent namespace failure. Candidates: real tombstone/restart; write mode
published before the epoch; acquisition observed between publication steps; a
snapshot coherence bug; install attempted too early with no retry.

## 3. The NONE population — hypothesis and the right probe

Leading mechanism:

> Authority installation is attempted during a read→write acquisition or
> conversion BEFORE the durable write epoch is visible, returns `notvalid`, and
> nothing retries at the event that finally publishes the epoch. A previous
> backstop revoke left the inode NONE, so it stays NONE while `i_dlm_mode` is
> later observed PW/EX.

Explains all three facts: dirty-time mode write-capable; state NONE; large
notvalid population. Related possibility: `i_dlm_mode` and the durable grant
snapshot updated in opposite order / under different serialization.

**`i_mxfs_auth_line` is NOT decisive** — it records the last SUCCESSFUL
transition; a failed install does not transition, so it reports only where NONE
was established (probably the backstop). Cheap to histogram, but it will not
say why the next write grant failed to install.

**Do not overinterpret the one-node concentration.** Image counts are
workload-weighted; one missed transition on one hot directory can produce
thousands of directory-buffer images. Group failures by owning inode, by
authority generation, by contiguous NONE episode, and by acquisition episode.

**The decisive instrument**: a rate-limited trace at the FIRST
`NONE && write-mode` dirty per inode/authority episode, capturing one coherent
snapshot — owner identity; `i_dlm_mode`; auth state/epoch/generation/line; the
DLM slot's actual held mode and `ex_grant_epoch`; publication/releasing/routing
state; last install-attempt status + line + sequence.

Classification table:

| dirty-time diagnostic | conclusion |
|---|---|
| slot: write mode, nonzero epoch | authority exists NOW; an install/reinstall event was missed |
| slot: write mode, zero epoch | epoch publication/restart gap |
| slot: non-write while i_dlm_mode says PW/EX | snapshot coherence / mode-publication ordering bug |
| slot: releasing | dirty/release serialization failure |
| no install attempt since last revoke | missing call/event |
| install attempted before epoch publication, none after | missing post-publication retry |

If adding only ONE piece of persistent instrumentation: record the LAST INSTALL
ATTEMPT (reason, line, monotonic grant/publication sequence). More informative
than the last successful state-transition line.
