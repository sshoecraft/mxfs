---
name: ccloop-c7ee71c6-sess102-GPT-ruling-capture-at-first-dirty-NOT-format
description: sess102 RULE-5 ruling: format-time authority lookup is UNSOUND (stamps a later epoch than authorized the mutation). Capture at first protected dirty.…
metadata:
  type: reference
tags: [mxfs, foreign-replay, authority, step5.3, rule5, release-blocker]
---

# sess102 RULE-5 ruling — step 5.3 capture point

Brought: the MEASURED P239-OWNAUTH histogram (below) + a structural proof that
the refusal classifier is broken. Both changed the design.

## What I measured first (0.11.435, all 32 nodes)

`P239-OWNAUTH` samples every logged buffer image on the non-AG arm, derives the
owner, and RCU-looks-up the owning inode's authority state at **format time**.

rsync-heavy window, 40777 images / 32 nodes:
  durable 40758 (99.95%) - none 19 (0.05%) - **unpub 0** - **uncached 0** -
  stale/noowner/badag/nopag/durnoep 0.  Non-durable BLFT: all t10 dir_block.

dir/dirent-heavy window (8 criteria), 1052 images (only 1 node crossed the
8192-token report modulus):
  durable 973 (92.49%) - **none 75 (7.13%)** - noowner 4 (0.38%) - unpub 0 -
  uncached 0.  Non-durable BLFT: dir_data 27, dir_leaf1 26, dir_block 22,
  dino 4 (the DINO 4 == the noowner 4).

So the sess101 premise — that this population is dominated by UNPUBLISHED_EX —
is **not what the rig shows**. unpub is ZERO in both windows.

Collector: `tests/ownauth_counters.sh <n> [snapshot]` (RULE 3, new this
session). Reads the dmesg P239/P228 lines, aggregates, decodes BLFT names,
diffs against a snapshot.

## THE RULING — the histogram does NOT license the obvious shortcut

**P0, RELEASE BLOCKER: do NOT stamp authority from a format-time lookup.**
The token must name *the grant that authorized the mutation*, not whatever
grant is installed when the formatter runs. Legal history:

    modify under epoch E1 -> release E1 -> reacquire under E2 -> format stamps E2

My histogram scores that `durable`; the emitted token is **false**. Symmetric
error on the other side: `NONE` at format time may just mean authority was
released *after* a perfectly authorized mutation. Format-time state can
classify neither. Therefore "99.95% durable" is NOT evidence that stamping
from that lookup is safe, and unpub==0 is NOT evidence that unpublished
authority was never involved — promotion may simply happen before formatting.

**P1, RELEASE BLOCKER: capture at first protected dirty, serialize at format.**
Capture the proof at the earliest point the mutation is attributable to a
tenure — the `xfs_trans_dirty_buf`/join seam or the first `xfs_trans_log_buf`,
provided the transaction necessarily still holds the authorizing tenure there.
Store it in the buf log item / transaction sidecar. The formatter ONLY
serializes what was captured. Required invariants:
 - proof immutable after first protected dirtying;
 - re-logging the same buffer in one transaction must match the same
   authority object AND epoch (assert on mismatch);
 - authority cannot be released before the transaction captured the proof;
 - a buffer carrying changes authorized by *different* objects/epochs cannot
   be represented by one whole-buffer token — prevent it or split.

NOTE: this is the SAME requirement as the still-owed "RULING ITEM (b)" already
written in the comment at pal/linux/xfs_buf_item.c (~line 880). Two independent
consults have now converged on it. It is the work.

**P2: producer-owned outcome enum for grant results.** Reject option (1a)
(filling proof fields on a refused result) — a nonzero proving field with
valid==0 is a future correctness trap. Reject bare (1b) too: only the PRODUCER
knows why it refused. Use `enum mxfs_grant_outcome { PROVED, OBS_SHARED,
EX_NO_EPOCH, NO_TENURE, STALE, RELEASING, OTHER_REFUSAL }` plus optional
never-proof diagnostics (observed_epoch/observed_mode), an accessor
`mxfs_grant_result_get_proof()` instead of consumers reading fields, and the
enforced invariant `outcome==PROVED => mode in {EX,PW} && grant_epoch!=0`,
`outcome!=PROVED => grant_epoch==0`. **Keep PRODUCER outcome and INSTALLER
rejection as separate enums/counters** — otherwise a valid proof rejected by
the installer is conflated with a producer that never produced one.
Caveat: do NOT map every non-EX mode to "shared" — producer B leaves mode==0
on its early return, and 0 means "not observed", not "shared".

**P3, RELEASE BLOCKER: resolve every NONE at the capture point.** "Rare" is
not a disposition; one unproven image can block recovery of the whole replay
range.

**P4, RELEASE BLOCKER: replay gating must be transaction-atomic.** Never apply
a transaction's authorized images while skipping its unproven ones — that
manufactures states no node ever created (dir data without its leaf/node
index, half a rename, bmbt root without children). And "reject this
transaction, continue with later ones" is also unsafe: later transactions may
depend on it. Correct default for an unproven image: apply none of that
transaction, do NOT skip forward, **stop foreign replay and fail closed**.
`UNPROVEN` must mean "automatic foreign replay cannot establish safety", NOT
"skip this image". Preferred design is a two-pass recovery: validate the whole
replay range without writing, then replay only if admissible. Per-image tokens
remain the right *evidence* granularity; the *decision* is transaction-wide.

**P5: decide the unpublished-child delegation from first-dirty evidence only.**
DEFER the delegation mechanism (the sess101 prescription) rather than
implementing it. If first-dirty instrumentation proves durable inode authority
is always installed before the first inode-owned dirty, delegation is
unnecessary and that ordering should be asserted as an invariant instead.

**P6: DINO/inode-cluster stays a separate blocker.** A DINO buffer holds many
inodes and must never fall through owner derivation to an invented
single-inode token (that is D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY).

## The structural bug I proved on the way in (independent of the ruling)

`struct mxfs_grant_result` has exactly two producers and both hold
`valid==1 => mode in {EX,PW} && grant_epoch != 0`:
 - `caw_grant_result_fill` (dlm/dlm_caw.c:975)
 - `mxfs_iclus_auth_snapshot_locked` (xfs/xfs_mxfs_dlm.c:~43812)

The consumer `mxfs_inode_authority_install_durable_ex_locked`
(xfs/xfs_mxfs_dlm.c:~960) tests `!valid || grant_epoch==0` FIRST and only then
tests mode. Therefore **`mxfs_auth_ref_shared_n` and `mxfs_auth_ref_noepoch_n`
are structurally UNREACHABLE** — every benign shared-grant refusal AND every
real zero-epoch refusal both land in `notvalid`.

That is why sess101 read "judged 62 / installs 12 / refused 50 / notvalid 50 of
50 / shared 0 / noepoch 0" as "caw_grant_result_fill is declining to mark
cluster-routed acquires valid, i.e. a plumbing hole". **That reading is not
supported by those numbers** — they are equally consistent with "50 of those
were ordinary shared-mode grants", which is benign and expected on read-heavy
work. GPT confirmed the unreachability independently. Do not re-derive a
conclusion from `notvalid` until P2 lands.

## Order of work

P0/P1 first (they are the same edit), then P3 falls out of P1's instrument,
then P2, then P4, then P5/P6.
