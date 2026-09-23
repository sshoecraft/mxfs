---
name: trap-the-board-prep-row-resets-mxfs-extra-modargs-so-a-knob-off-board-runs-knob-on
description: TRAP (sess565): a knob set by a standalone MXFS_EXTRA_MODARGS prep does NOT survive into a following board run — proven by probe timestamps; mechanis…
metadata:
  type: feedback
tags: [trap, board, modargs, vacuity, d0496, run.sh]
---

# A knob set by a standalone prep does NOT survive into the board

sess565, running the two-node version of the sess498 "heal off" experiment.

    env MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS='dir_datascan_heal=0' ./run.sh 2 tcp prep_cluster
    # heal=0 VERIFIED on both nodes right here
    ./run.sh 2 tcp        # the board

**The knob was back ON by row 5.** Proven, not inferred: `P26-DSCAN` prints
only inside `mxfs_dir2_datascan_lookup`, and every call site of that function is
gated `if (error == -ENOENT && mxfs_dir_datascan_heal && ...)`
(`xfs_dir2_leaf.c:2257,2518`, `xfs_dir2_node.c:2520,2581`). So the probe cannot
fire with the knob at 0. It fired at 00:51:50–00:51:55, inside the
`cache_coherency` row that failed at 00:52:09Z.

## The mechanism is NOT established — do not repeat my first guess

I initially wrote that "row 1 of the board is `prep_cluster`, which reloads the
module without the extra modargs." **That is wrong as stated**: the board's own
results table showed `ran=27` and did not include a `prep_cluster` row at all,
because the standalone prep had already satisfied it. Something between the prep
and row 5 restored the default and I have not identified what. Candidates not yet
checked: `precond_readiness` remounting, `run.sh` re-prepping on a stale marker,
or the modarg never being persisted for later module loads in the first place.

What is certain is the OBSERVATION, and that is what the trap is:
**a verified-before-the-run knob is not evidence about the run.**

## The check that actually works

Record the knob in the SAME window as the verdict, from the nodes:

    tools/mxfs_sshpass.sh test1 'cat /sys/module/mxfs/parameters/<knob>'

`tests/sess493_d0492_crash_durability.sh` does this correctly — it writes
`persig_<node>.txt` holding `persig/heal` per node at lap start, which is why its
s598b lap could be trusted as genuinely non-vacuous. Better still, prefer a probe
whose presence/absence *implies* the knob state, the way `P26-DSCAN` does here.

## Two related counting traps from the same session

- **`P21H-LEAFHOLE` is not a hole count.** The ledger's own `detector` field says
  it fires on EVERY ENOENT in a leaf-format lookup and is a census line; only
  `hv_in_leaf` separates a missing hash (0) from a wrong address (>0). And
  `hv_in_leaf=0` for a name that legitimately does not exist yet (a pre-create
  existence check) is the CORRECT result. Read `detector` before counting.
- **A run directory's `kernlog_*.gz` is the WHOLE BOOT JOURNAL**, not the row's
  window (already recorded as the sess495 trap, and it bit again here). Counting
  a probe over it attributes earlier activity to the row. Use timestamps.
