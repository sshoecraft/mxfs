---
name: ccloop3e02-sess2-INPROGRESS-r18undercount-instrumented-repro-launched
description: sess2 continuation: instrumented (instr=1 dirwr=1, NFILES=10 ROUNDS=40) 32/caw repro LAUNCHED to catch the round-18 single-dirent-loss with full data…
metadata:
  type: project
---

## Where this picks up from `ccloop3e02-sess2-WEDGE2A-FIXED-full24round-clean-new-r18-undercount`

That memory has the wedge2a fix details (KEEP, proven) and the initial r18 undercount
discovery. This note adds the DEEPER historical context found afterward, and records
a live instrumented run IN PROGRESS when this session hit the relay boundary.

## The bug: single-dirent loss during dir_reuse_coherency (NOT wedge2a, a different bug)

Confirmed via test9's `/root/drc_fail_r18_rank9.dmesg` (still on test9, may get
overwritten by later runs) precisely scoped to round 18's real time window
(create-start=2295.46s test9-uptime, create-done=2319.71s): directory ino=131
started round 18 in SHORTFORM format with `node9_f1` as its ONLY entry (`P-DIRFLUSH
count=1 first=[node9_f1]`, `P56-RELOAD-MERGE post_cnt=1 disk_cnt=1 ours_cnt=1
resurrect=0` — no conflict at that instant). The directory then grew through many
concurrent creates from the other 31 nodes (fmt 2->3, ndb 4->92 by end of round) as
expected. By verify time, ALL 32 nodes independently found `readdir count
exp=3200 got=3199`, and rank9's own diagnostic block confirmed via full scan
(`P26-DSCAN-MISS ndb=92 scanned=3201 name="node9_f1" not in any data block`) plus
lookup (`P21H-LEAFHOLE`/`P26-LKERR err=-2`) that `node9_f1` — the directory's FIRST,
shortform-born entry — was GENUINELY, DURABLY gone (LOOKUP_ENOENT, REREAD_MISS, not
a transient/stale-cache view — all 32 nodes agree it's gone).

## This matches a well-known, extensively-investigated bug class from ~19 days ago

Search `compiled-dirreuse-node1f1-double-block0-orphan` (sess65, 8 source memories) —
on 4/tcp and intermittently 2/tcp, `node1_f1` (rank1's first, shortform-born file)
was durably lost via a TWO-STAGE mechanism:
1. **Extent[0]/block0 divergence**: under concurrent creates from fresh shortform,
   multiple nodes each independently run `xfs_dir2_sf_to_block`, each allocating its
   OWN physical block0 in its node-affine AG. The dir inode's data-fork extent[0]
   then flip-flops depending on whichever node's iflush lands last — a reader whose
   cold-read dinode has extent[0] pointing at a DIFFERENT physical block never sees
   the entry that lives in the other one.
2. **Block0 content clobber** (residual even with a single converged block0): a peer
   RMWs the block from a stale base lacking the entry and writes it durably.

Sess65 tried ~8 different mitigations (epoch-gated convert prelock, lowest-block0-
wins iflush fence, pending-dirent replay, allocator AG affinity, etc.) — ALL either
0-fired (didn't align with the actual race timing) or were partial/harmful. They
converged on a DESIGNED BUT NEVER IMPLEMENTED fix: a durable, cluster-visible,
write-once "canonical block0" record published via the DLM master (mirroring the
existing `dir_epoch` grant-stamping plumbing) — full plan at
`docs/canonical_block0_fix_plan.md` (still in the tree, unimplemented — only the
diagnostic infra landed: `dir_iflush_fence`, `dir_epoch_adopt`, `dir_pending`,
`dir_merge`, `dir_force_block`, `dir_adopt_block` module params, ALL default-OFF
currently). NOTE `mxfs_dir_iflush_owner_fence` (a DIFFERENT, later sess67 fence) is
ALSO default-0 with comment "reverted to 0 (inert: NL dir-inode flushes are all
legit RELFLUSH; extent map converged)" — implying the extent-map divergence got
BETTER via some other change between sess65 and sess67, but clearly not fully
closed given what I just observed at 32/caw.

`sess58-CRITERION-MET-2tcp-17of17-8consecutive` (a DIFFERENT, separate criterion,
2-node TCP, ~20 days ago) fixed a DIFFERENT pair of bugs (create/remove AG<->dir
ABBA deadlock + `xfs_ilock_nowait` skipping the DLM grant causing dirent
resurrection) — NOT the node1_f1/block0 bug. Do not conflate the two.

## Why this wasn't caught by earlier N=2/4/8/16 validations today

The bug is "contention-scaled" (sess13: "Loss 1-26/round" at 4-node/50-file scale)
— more concurrent creators = higher chance per round. It plausibly threatens N=16
too, just at lower odds per run; N=32 hit it at round 18/24 in one run. **Getting
N=32 to genuinely pass requires fixing this, not just getting a lucky run** — a
lucky N=32 PASS would not give real confidence for "100%" either.

## Action taken this session, IN PROGRESS at relay boundary

1. Raised 5 diagnostic probe caps that were exhausting in the first ~90s of a run
   (too low to survive to round 18+): `P-DIRIFLUSH` (xfs_inode.c, 3000->500000),
   `P-DIRFLUSH` (xfs_inode_buf.c, 40->20000), `P62-SF2BLK-CALLED`/`P42-SFCONV`/
   `P60-SFCONV-BASE` (xfs_dir2_block.c, 3000-4000->300000 each). Pure diagnostic
   additions, no behavior change. VERSION bumped 0.10.61->0.10.62.
2. Rebuilt (`make modules`): new srcversion `F3605E04F868F43B15C432F`.
3. Launched: `MXFS_DEV=/dev/mapper/mpatha MXFS_EXTRA_MODARGS='instr=1 dirwr=1'
   DRC_NFILES=10 DRC_ROUNDS=40 /src/mxfs/run.sh 32 caw dir_reuse_coherency`
   (nohup+disown, pid 1791175 at relay time), log at
   `/tmp/claude-1000/-src-mxfs/02011108-e4b0-4018-ab43-aa114400c57f/scratchpad/run32_instrumented.log`
   (THIS session's scratchpad — may not exist for a fresh session; check first,
   relaunch if gone, cheap: NFILES=10 rounds take ~90-120s each, much faster than
   the default-50 ~160s/round). Rationale: smaller NFILES=10 (640 total entries
   instead of 3200) for faster round cycling, MORE rounds (40 instead of 24) to
   increase odds of catching the race, with instr/dirwr diagnostics enabled and
   caps raised so the P-DIRIFLUSH/P42-SFCONV/P62-SF2BLK cross-node block0 data
   survives to whatever round the loss occurs at this time.
4. Prep confirmed clean (build F3605E04F868F43B15C432F on all 32 nodes, converged).
   Run reached at least round 8 cleanly (00:41:42Z) with 0 FAILs so far when this
   session ended — NOT yet reproduced with the new instrumentation; whoever
   continues must keep watching (up to round 40) or re-launch if it already
   finished/died.
5. IMPORTANT GOTCHA hit this session: `dmesg -Tw` on first invocation dumps the
   ENTIRE EXISTING kernel ring buffer before following — a "fresh" capture file can
   contain STALE data from a PREVIOUS run/build mixed in with new content, corrupting
   round-number greps. Fix: `dmesg -c > /dev/null` (clear the ring) on the target
   node BEFORE starting a new `dmesg -Tw` stream, which this session did partway
   through (new clean stream started, pid 1814784, same log path, right before the
   relay boundary — the file was truncated+recleared so it should be clean going
   forward, but double check for a stale-data mix if picking this up).

## Next steps (in order)
1. Check if pid 1791175 (run.sh) / the dmesg stream are still alive; if the run
   finished, check `criteria.json`'s `32/caw` `dir_reuse_coherency` entry and the
   run log for a FAIL with a `readdir count` mismatch — get the round number,
   victim name, and rank via the same method as sess2's first catch (`grep
   mxfs-drc-FAIL`, `mxfs-drc-RDMISS0`, `mxfs-drc-CLASS` on the victim's OWN
   rank's `/root/drc_fail_r${N}_rank${R}.dmesg`).
2. Once caught, pull `P42-SFCONV` (shows EVERY sf->block conversion for ino=131:
   sf_count, the name triggering it, comm) and `P62-SF2BLK-CALLED` (shows the FULL
   list of names in the shortform base being frozen, `names=[...]`, GENERICALLY —
   no hardcoded name, unlike `P60-SFCONV-BASE`/`P64-N1F1` which are hardcoded to
   node1_f1/node2_f1 and won't fire meaningfully for a different victim) — check:
   did the victim name appear in EVERY conversion's frozen base (content-clobber
   downstream of conversion) or was it ABSENT from some conversion's base
   (extent-split / stale-base-adopted-by-converter, matching sess65's Stage 1)?
   Also pull `P-DIRIFLUSH` across ALL 32 nodes (not just one) for ino=131 around
   the failing round, looking for DIFFERENT `incore_blk0_fsb` values reported by
   different nodes for the SAME `dir_gen`/incarnation — that would directly
   confirm/refute the extent[0]-divergence mechanism for this build.
3. Based on which mechanism is confirmed, either implement
   `docs/canonical_block0_fix_plan.md`'s DLM-record design (adapting it for CAW —
   CAW's on-disk slot struct already has a `dir_epoch@128` field per the compiled
   dlm awareness notes; would need a similar `dir_block0_fsb`/`gen` field added,
   checking available space in the fixed 512-byte slot layout) or a simpler fix if
   the mechanism turns out different at CAW/32-node scale than the TCP/4-node case
   sess65 characterized.
4. After a fix: multiple (2-3) consecutive clean full 24-round (default NFILES=50)
   32/caw runs, THEN re-verify N=1/2/4/8/16 (both transports per the full suite,
   not just dir_reuse_coherency) since core xfs_buf.c completion routing AND
   whatever dir2_block/sf/inode code the eventual fix touches both changed this
   session. Only then write YES to
   `/src/mxfs/.ccloop/runs/3e02e7dd-de32-4f91-a7c5-61eddb630e4a/criteria-met`.

## Cluster state at relay boundary
All 32 test VMs up. mxfs.ko build F3605E04F868F43B15C432F loaded cluster-wide
(includes wedge2a fix + raised diagnostic caps, NOT yet any block0/conversion fix).
run.sh pid 1791175 (or check if it finished) running the instrumented repro.
