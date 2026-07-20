---
name: sess35-HEAD-handoff
description: sess35 HEAD: dir_reuse 8/tcp round-1 loss = sole criteria blocker. Keeper=4703FA18 (==2EAA0090 4/5, all exp params OFF). ALL param levers refuted cat…
metadata:
  type: project
---

## sess35 HEAD — dir_reuse 8/tcp round-1 durable dirent loss. CRITERIA NOT MET.

### Criteria: 1/tcp=16/16, 4/tcp=17/17, 8/tcp=16/17 (dir_reuse only fail), 2/tcp=needs-run. dir_reuse 8/tcp ~80% (rare round-1 loss). **KEEPER = 4703FA18** (== sess34 2EAA0090, 4/5; + harmless EVDECIDE epoch-field diag; P37 instr-gated). All experimental params DEFAULT-OFF. On-disk + restored clean.

### THE LOSS (well-characterized): round-1 ONLY (fresh empty dir growing shortform→block→leaf→node under 8-way concurrent create), ~20%/round-1, durable, ALL-nodes-coherent, 1-10 dirents, REREAD_MISS, lookup_fail=0. Steady rounds 2-24 ~clean. sess11 SMOKING GUN: lost dirent's bytes ARE logged to the data block then VANISH from the same daddr w/o evict/reload = WRITE-side ABA reflush (a stale image of the daddr written over the logged one).

### EVERY PARAM-LEVEL LEVER REFUTED THIS SESSION (all catastrophic/wedge — do NOT re-enable):
- dir_newtenure_evict=1 (KEEPER, default-on): the 4/5 baseline. Keep.
- epoch-never-0 (dlm.c): readdir=0 (spurious new_tenure retires this-tenure un-landed BLIs). REVERTED.
- dir_addname_epoch_refresh=1: readdir=0 (zombie reflush, no retire).
- dir_addname_coherent=1: insufficient alone (sess28) — read at addname is coherent (P28-PLATTER MATCH).
- dir_subset_guard=1: WEDGE round-2 create (suppresses a write the create depends on).
- dir_reflush_skip=1: readdir=0/2 catastrophe (skips writes of blocks legitimately DONE=0 during round-1 format churn).
- dir_release_stale (release demote-invalidate): tried sess33, buffer re-enters next tenure, insufficient.
LESSON: blind write-skip/suppress + read-refresh + epoch-tracking-tweaks ALL fail — during round-1 format churn they can't distinguish a stale zombie reflush from a legit re-write of an evicted-then-refilled block → drop needed content.

### REFUTED root hypotheses (instrumented): read-side kept-stale-base (staleprt=0), stale in-core bmap (P37=0 all nodes), addname stale read (P28-PLATTER MATCH), use_free live-slot overwrite (xfs_dir2_data_check_free guards it, no corruption shutdowns).

### Release fence (sess97, xfs_mxfs_dlm.c:8495-8585) ALREADY enforces Invariant 1: loops until data_durable (all dir-fork blocks xfs_bwrite'd) + inode out-of-AIL (dinode durable) before release. So at a clean release the image IS durable+consistent. => the ABA must be a POST-release stale reflush, OR the loss enters at a transition the fence doesn't cover (format conversion shortform↔block where mxfs_dir_data_durable returns-early for LOCAL/shortform fmt — xfs_mxfs_dlm.c:1120).

### NEXT SESSION (RULE 4 — re-confirm entry BEFORE coding):
1. Deploy an always-on **P11-DATALOG**-style write-trace: for dir ino, log every dir3 data-block WRITE submit (daddr + a cheap dirent-count or a specific victim-name presence). Reproduce round-1; find the write that drops the victim (which node, daddr, was it post-release? was the block DONE=1 legit or DONE=0 zombie? what fmt?). This disambiguates: post-release ABA vs format-conversion-window loss.
2. If format-conversion window: mxfs_dir_data_durable/flush return-early on LOCAL/shortform (line 1120) — a node releasing mid-conversion (shortform in-core, block on disk, or vice-versa) skips the drain → stale handoff. FIX: cover the shortform↔block conversion in the release drain (flush the just-allocated block-0 + the dinode literal area together, ordered).
3. If post-release ABA: the durable fix is NOT write-skip (all refuted) — it's ensuring the stale buffer is genuinely GONE and any re-read is FUA-fresh; or a fenced/generation-checked write. Consider GPT's ordered release-publish ONLY if step-1 shows an ordering gap.
See [[sess35-REFUTED-addname-epoch-refresh-causes-readdir0]] [[sess35-write-side-subset-guard-test-plan]] [[sess35-GPT-consult-round1-epoch0-disables-staleevict-fix]] [[sess35-dir_reuse-two-residual-faces-round1-and-799]].
</body>
