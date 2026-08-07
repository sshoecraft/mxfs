---
name: ccloop-c7ee71c6-sess23-gpt-cluster-inode-identity-protocol
description: GPT (RULE 5) architectural verdict: MXFS's 3 critical defects share ONE root — no cluster-wide publication+incarnation protocol; invariants, enforcem…
metadata:
  type: reference
tags: [ccloop-c7ee71c6, sess23, gpt, architecture, inode-identity, release-barrier, RULE5]
---

# GPT (RULE 5) verdict — the three critical defects are ONE defect

Consulted with full evidence for D-SILENT-MKDIR-LOSS (a),
D-RELEASE-BARRIER-OPEN (b), D-DIRENT-INODE-TYPE-MISMATCH (c).

## The diagnosis

My read ("no cluster-wide inode identity/lifetime fence") is **directionally
correct but too narrow**. Correct statement:

> MXFS lacks a linearizable cluster-wide **ownership, publication and
> incarnation** protocol for metadata resources.

- (c) IS an inode identity/lifetime reuse failure.
- (a) and (b) are **lock-handoff and publication-coherence** failures:
  - (a) a grant does not guarantee the grantee adopted state at least as new as
    the state the grant represents;
  - (b) release is permitted before all mutations committed under that tenure
    have ENTERED the release barrier.

A lifetime fence alone would NOT fix (a) or (b). Fixing only lookup retries or
only inode reuse leaves both intact.

## The three invariants, precisely

**1. Inode incarnation.** Identity is `(inode number, incarnation)`, never the
number alone. For every published dirent `(parent,name) -> (ino,incarnation)`
there is exactly one live incarnation, and all resolvers see that same
initialized incarnation and a compatible type. Before `ino` may be reused for
incarnation G+1: no new refs to G; all remote cached/open holders of G recalled
or excluded; G's operations unable to publish further; unlink/inactive/truncate/
free durable; stale G state invalidated or distinguishable; only then publish
G+1. Node failure must not bypass this — a failed owner must be FENCED and its
lifetime locks recovered before reuse.

**2. Lock handoff.** If tenure B is granted after tenure A, no operation under B
may use cached state unless it proves that state corresponds exactly to A's
final published state or later — proven BEFORE the tenure is exposed to any
operation.

**3. Release/publication.** A tenure may not become grantable until every
mutation committed under it has been **REGISTERED WITH the resource's
publication barrier** and reached the visibility point future owners expect.
"Registered with" is the load-bearing phrase: a drain cannot see work that was
never entered into the queue — which is exactly MXFS's measured
`cls=UNCOPIED drain_ran=1 drain_flushed=1`.

## Where to enforce

- **Inode alloc:** serialize under the AG lock; take exclusive ownership of the
  inode-number resource; assign a new incarnation that cannot be confused with
  the prior occupant; initialize; make it VISIBLE before publishing any dirent
  to it; tag the local cache with that exact incarnation.
- **Dirent publish:** ideally the dirent records the incarnation (GFS2 does this
  via its formal inode number). If the on-disk format cannot carry it, lookup
  must validate incarnation under a protocol that prevents reuse DURING
  resolution — substantially more fragile. Ordering: new incarnation visible
  BEFORE the dirent naming it.
- **Unlink/free:** remove last dirent under parent+inode locks; persist orphan
  state; acquire the LIFETIME/open resource exclusively (this proves remote
  opens are gone/fenced); inactive+truncate+durable free; advance incarnation;
  only then return the number to the allocator.
- **Lock acquire:** compare local cache tag against the authoritative
  publication identity; mismatch -> invalidate and re-read BEFORE exposing.
  **A dirty local image must NOT silently "keep our dirty image" on mismatch** —
  that means the previous release protocol ALREADY failed; flush under the old
  tenure, reconcile, or fail/fence.
- **Commit + release:** `resource dirty_seq++` and associate the publication
  work with it AS PART OF COMMIT, ordered so release cannot drain between
  "committed" and "staged". Then: close to new mutations -> `target=dirty_seq`
  -> force through target -> wait `durable_seq >= target` -> publish new token
  -> unlock. On I/O failure do NOT hand off as if publication succeeded.

## GFS2 / OCFS2 — what is load-bearing

Not the data structures. The SEPARATION OF ROLES:
1. a metadata coherence lock;
2. a **separate open/lifetime lock** preventing final dealloc while another node
   still has the inode open/instantiated (GFS2 `iopen`);
3. a generation/formal identity that detects reuse;
4. demotion tied to flush/invalidation;
5. allocation/free serialized by resource-group locks;
6. durable orphan state + recovery/fencing of failed owners BEFORE reuse.
MXFS needs an equivalent of ALL SIX. "There is an inode DLM lock" is not enough.

## The 200-round lookup resolver is not a correctness mechanism

A type mismatch means one of: stale dir image / stale-or-old-incarnation inode
image / durably inconsistent on-disk mapping. Sleeping and re-reading without
holding a lock or waiting on a sequence guaranteed to change cannot distinguish
them. Both terminal outcomes are unacceptable as normal operation (publish =
silent corruption; permanent ESTALE = visible breakage).
Correct bounded form: acquire/convert parent lock -> stable dirent + incarnation
token -> acquire target inode metadata/lifetime lock -> invalidate stale state
-> verify number+incarnation+type -> if a known transition was observed, wait on
its completion and RESTART FROM THE PARENT -> if a stable authoritative mismatch
remains, report **-EFSCORRUPTED** and withdraw/remount-ro. A retry count bounds
waiting; it cannot repair a durable mismatch. Keep "never publish the mismatch"
as the immediate safety measure, but replace polling with lock/sequence restart.

## Freshness when the epoch can REGRESS (MXFS's CAW epoch does)

A regressing/cleared token permits ABA and cannot serve as a validity version.
Two correct choices:
- **Conservative (best first fix):** invalidate on EVERY new grant and re-read
  authoritative state before exposing the tenure. Expensive but correct.
- **Better:** an opaque NON-REPEATING publication identity —
  `(incarnation, publication UUID or boot-id/slot-generation, sequence/LSN)`.
  It need not be numerically monotonic, only guaranteed not to repeat. It must
  be generated by the authoritative publisher, stored durably WITH the published
  image, survive slot reclamation, NOT be cleared merely because the inode was
  freed, change across reuse, be discoverable at lock acquisition, and be
  updated only AFTER the image reaches the visibility point.
For a newly allocated inode, create incarnation + initial token AT ALLOCATION
and tag the creator's image — **do not leave a valid new dirty inode at an
ambiguous "epoch zero"** (that is exactly MXFS's `valid_epoch=0` creator case).

## Implementation order (GPT's priority)

1. **Make lock handoff fail-safe** — biggest immediate win for (a) and (b).
   Invalidate/adopt before exposing any newly granted tenure; until an ABA-safe
   token exists, re-read unconditionally on every new grant; never let dirty
   unmatched state bypass adoption; fail closed on impossible state.
2. **Couple transaction staging to the release barrier** — mark the resource
   dirty as part of commit so release cannot observe zero-pending in the window
   between commit and staging. Essential: a better drain cannot see unregistered
   work.
3. **Real inode incarnation + lifetime protocol** (the six roles above).
   *Cheap diagnostic first:* **quarantine freed inode numbers from reuse for the
   lifetime of the cluster mount.** If type flips disappear, the lifetime
   diagnosis is confirmed. Not a permanent design — a decisive experiment.
4. **Replace the lookup polling** with lock+incarnation restart; stable mismatch
   becomes -EFSCORRUPTED, not a sleep loop.
5. **Assertions:** no grant exposed while cache state is UNKNOWN; no unlock while
   `durable_seq < dirty_seq`; no inode-number reuse while old-incarnation
   lifetime locks exist; no dirent published before target incarnation is
   visible; no lookup publishes a type mismatch; no active inode stably on the
   inode LRU.
