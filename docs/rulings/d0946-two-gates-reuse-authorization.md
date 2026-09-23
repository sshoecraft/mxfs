<!-- RULE-5 ruling (sess571, D-0946): naive shape A is unsafe; use shape B as transient publication-block with a progress path; long term proof-carrying r… -->
# RULE-5 ruling — D-0946, the two gates that disagree about reuse

Question put: gate 1 (`mxfs_dialloc_validate_candidate`, xfs_ialloc.c) allows an
inode whose platter dinode is live, on the grounds that this node holds an open
publication obligation for it (its own committed-but-unpublished free). Gate 2
(the recycle gate, xfs_icache.c:1101) has no access to that obligation, calls
the live image corruption, returns `-EFSCORRUPTED` on a DIRTY transaction, and
the filesystem shuts down. Shapes offered: (A) teach gate 2 the exemption;
(B) remove gate 1's exemption.

## The framing that decides it

> A live dinode plus matching generations is evidence consistent with a local
> unpublished free, but it is **not proof of ownership** of that state.

## 1. Naive A is UNSAFE — do not ship it

`pubob_lookup() && kind != UNLINK && ogen == i_generation && di_gen == ogen-1 &&
epoch == current_epoch` is still a second independent inference from mutable
state: stale entries, ABA, obligation-lifecycle bugs, and lookup/publication/
revocation races all survive it. False acceptance **silently overwrites a live
inode**, which is strictly worse than the shutdown it replaces.

**The most dangerous failure mode, which I had not listed:** an old
free-publication action surviving reuse and *later writing the freed image over
the new incarnation*. Sequence: obligation schedules "write freed dinode" → the
allocator reuses the inode → create initializes and logs the new inode → the old
publication worker writes its stale free image on top. On reuse the obligation
must atomically transition (`FREE_PENDING -> REUSED_PENDING`) and the old action
must be cancelled/retargeted/subsumed — never left runnable keyed only on `ino`.
Also watch inode-CLUSTER granularity: publishing one dinode must not write a
stale whole-cluster snapshot over newer neighbours.

Other named hazards: use a **positive whitelist** (`FREE_PENDING_HOME`), never
`okind != UNLINK` — a negative test breaks the moment a kind is added. `oepoch ==
current_epoch` is weaker than proving the grant was *continuously held*; prefer
`{cluster session UUID, node boot UUID, DLM grant sequence}` over a per-mount
integer. AG EX excludes peers but **not other local threads**. A bare xarray
lookup followed by an unlocked recycle is a TOCTOU.

On generation arithmetic: `ogen - 1U` is well-defined and wrap is fine — the real
risk is **aliasing**, the same generation pair recurring after enough reuse so a
stale obligation matches by accident. Record the actual old generation at
obligation creation instead of deriving it, and still treat generations as
corroboration, never as the ownership proof.

## 2. B is the right immediate containment — but not the naive version

**Do not put these inodes in the corruption quarantine.** An inode whose only
problem is "publication pending" is not corrupt; the permanent per-AG xarray
would leak inode space until unmount, force needless chunk allocation, unbalance
AGs, and produce **false ENOSPC**.

Use a distinct transient state (`PENDING_PUBLICATION`) cleared on publication.
And B needs an explicit **progress rule** or it starves/livelocks — inobt says
free, every candidate is rejected, nothing drives publication:

1. skip inodes with known local pending obligations *without* reading disk;
2. after a bounded number of skips, queue or synchronously drive publication;
3. release the locks the publication path needs before waiting;
4. wait for completion / force the log as required;
5. retry;
6. quarantine permanently only if still live with no valid pending-free reason.

Do not wait for publication while holding AGI/inobt/buffer locks the publisher
needs, and do not hold the cluster AG grant across a synchronous flush — that is
cluster-wide head-of-line blocking. Worst-affected workload is exactly rapid
unlink/create churn in a small inode population, which is this rig's.

## 3. Long term — proof-carrying reuse

Gate 1 returns a refcounted, transaction-bound **token** binding fs identity, AG
+ agino, mount/session/boot incarnation, a non-repeating grant incarnation, free
transaction identity/LSN, chain sequence, recorded prior and resulting
generations, and exact obligation kind/state. Gate 2 **consumes** it rather than
rediscovering the obligation by inode number. Grant release drains outstanding
tokens.

## 4. The dirty cancel — errno changes nothing

The shutdown comes from cancelling a **dirty** transaction, not from
`-EFSCORRUPTED`. Once `xfs_dialloc` has logged AGI/inobt/finobt/counters there is
no general rollback, so the shutdown is the conservative and expected response.
The only clean fix is to **make the decisive refusal happen before the
transaction is dirtied** (or reserve the candidate before dirtying). Explicit
undo is highly invasive (btree splits, freelist, quota, counters, and the
rollback itself must be crash-safe). `EEXIST` would be a lie — it makes a
namespace claim that is not true.

## 5. Also owed regardless

Enforce obligation drain at AG-grant handoff ("no pending local reuse
authorization or unpublished free may cross AG EX ownership transfer"). The
prior FREE-PUBLISH ruling is necessary but **not sufficient** — this failure
happens with no handoff at all, same tenure. Both rules are needed.

Note on the tempting "just publish the dinode before committing the inobt free":
a two-transaction implementation creates a crash window where home looks free
while the inobt still says allocated, and a single logged transaction does not
imply home-write ordering between its buffers. The practical form is: commit the
logical free, keep the inode excluded from reuse in memory, publish, then drop
the exclusion — with defined recovery/remount semantics for that exclusion,
which is why the handoff drain matters.
