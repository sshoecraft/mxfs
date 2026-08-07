---
name: ccloop-c7ee71c6-sess22-silent-mkdir-loss-full-chain-proven
description: sess22: silent mkdir loss chain closed byte-exact — P34J defers the epoch adopt, P32E then fences every flush of the committed dirent, drain exits UN…
metadata:
  type: project
tags: [mxfs, dlm, silent-loss, rule4, p32e, p34j]
---

## The chain, every link named by a probe (ccloop c7ee71c6 sess22)

Two independent captures, identical shape:
- `sfstorm_20260729_003736` round 32, ino 44040321, test31, `node31_1`
- `sfstorm_20260729_005540` round 39, ino 56623307, test27, `node27_1`

Both: `nlink=33 visible=31 expected=32`, identical on ALL 32 nodes, zero nonzero
mkdir(2) return codes cluster-wide.

### The trace (test27, ino 56623307, all inside 58 ms)

    .638680 P194-EPOCH-STALE-OP op=lookup grant_epoch=2 valid_epoch=0 dirty_here=1 name=node27_1 comm=mkdir
    .638687 P195-STALE-BASE-ALREADY-DIRTY grant_gen=7044 cached_gen=0 gen_moved=1 dirty_seq=1281 ex_grant_seq=1281
    .638696 P65-EPOCH-CONVGATE  -- peer converted; reload+adopt
    .638699 P34J-RELOAD-DEMOTE-BAIL demoter_pid=329248 -- release drain active; DEFERRING RELOAD   <<< THE ESCAPE
    .638894 P51-HANDOFF-UNDERFIRE hgg=2 cached_gg=0 -- lock changed hands, handoff bit FALSE
    .640655 P32E-DIREPOCH-FENCE valid_epoch=0 cur_epoch=2 comm=mkdir -- skip stale dir flush
    .640954 P56-DIRWRITE nl=2 sz=6 write=[]            -- publishes the EMPTY dir
    .674580 P146V-UNLANDED incore[nlink=3 size=22] disk[nlink=2 size=6]
    .683896 P32E-DIREPOCH-FENCE comm=xfsaild            -- fenced again
    .694960 P32E-DIREPOCH-FENCE comm=kworker            -- and again
    .696591 P188-REL-OBLIGATION-AT-UNLOCK pending=17 durable=12 flush=12
    .696598 P196-UNLOCK-OBLIGATION-CLASS cls=UNCOPIED drain_ran=1 drain_flushed=1
    (5 s later)
    P177-OBLIGATION-DROPPED-AT-ADOPT pending=17 durable=12 -- reload adopted the platter
                                     over an UNLANDED committed change

### Root, stated exactly

A directory tenure commits a change (pending 12 -> 17).  EVERY flush path for
that change is then fenced by `P32E-DIREPOCH-FENCE` because the in-core
`i_dlm_dir_valid_epoch` (0) is behind the DLM `dir_epoch` (2).  The one
mechanism that would advance `valid_epoch` -- the reload+adopt that
`P65-EPOCH-CONVGATE` requests -- is bailed by `P34J-RELOAD-DEMOTE-BAIL`
whenever a release drain is concurrently active.  The drain then declares
`flushed=1` with `pending != durable`, hands the grant off (P188), and the
eventual adopt discards the change (P177).  `mkdir(2)` already returned 0.

P32E's own comment asserts the premise that fails here: "Our own real changes
were landed by our release drain before the peer could acquire, so nothing of
ours is lost by skipping."  The obligation counters (pending vs durable) are
exactly the test for that premise and it is FALSE at the fence.

### P196 (built sess22) answered the barrier question definitively

`cls=UNCOPIED drain_ran=1 drain_flushed=1 dr_pend=17 dr_dur=12 dr_flush=12`.
Not INFLIGHT (nothing to wait for) and not REDIRTY (nothing raced in after the
drain).  The drain returned success on an inode whose committed change was
never staged into any outgoing image.  So D-RELEASE-BARRIER-OPEN at this site
is not a timing/ordering problem -- it is the P32E fence suppressing the copy.
Enforcing at the drain (`pub_obligation_enforce`) cannot win: the retry re-runs
a flush that is fenced deeper down.  That is the sess20 livelock's real reason.

### P197 (built sess22) REFUTED the tenure-identity hypothesis

`premise=ok` in 60/60 and again in the loss captures (`dirty_age_ms=6
tenure_age_ms=6`).  `i_mxfs_ex_grant_seq` IS re-stamped correctly; the dirtying
really is inside the current tenure.  Do not re-chase "the stamp was carried
over".  The staleness is real and is about the EPOCH, not the tenure stamp.

### Reproducer that works (and one that does not)

WORKS: `tests/sf_mkdir_storm.sh 60 32 2 1` immediately after a fresh prep.
30 rounds is NOT enough on current builds -- both captures were round >30.
DOES NOT: `tests/creator_stale_base.sh` (written sess22).  It constructs the
epoch-stale precondition en masse (3000+ P65 per run) but the adopt always
succeeds, so it never loses an entry.  Its designated-creator + quiet-window
shape gives the creator time to re-acquire cleanly.  The loss needs the
CONCURRENT release drain (P34J) that only the full 32-way race produces.

### Paired A/B, 60-round storm, one prep, alternating

    B  p6_epoch_override=0,create_baseline_trackers=0 : 4 and 5 durable rounds
    A  p6_epoch_override=1,create_baseline_trackers=1 : 0 and 1 durable rounds

Direction consistent, but A is NOT zero -- the sess21 fixes reduce, they do not
resolve.  Durable losses track `P32E` count closely (B: p32e=9 loss=5;
A: p32e=3 loss=1), which is what identifies P32E as the drop site.
