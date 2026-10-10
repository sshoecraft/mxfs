---
name: compiled-rig-prep-traps-nologin-banner-as-srcversion-and-knob-state-lost-before-the-board
description: Rig prep traps: pam nologin banner read/persisted as srcversion poisons marker; MXFS_EXTRA_MODARGS knob set by standalone prep not trusted in board.
metadata:
  type: feedback
tags: [compiled, rig, prep, cluster-marker, modargs, harness]
---

# Rig prep trusts a value it never validated: boot banner as srcversion, and knob state asserted before the run

Three traps share one shape: the prep or the experimenter records a state (node build, cluster identity, module knob) from a single early read, reports success, and the later run consumes something different. None is an MXFS defect; each makes a row fail or run vacuously for harness reasons.

## 1. A prep during node boot reads pam_nologin's banner as the srcversion

- Original form, tests/tcp_2node_death_chain.sh and tests/concurrent_create_race_2node.sh (with prep) failed 40-44 s after a death lap restarted the victim test2: `PREP FAIL: bad nodes: test2(build="Systemisbootingup.Unprivileged..." != CDD0B14B...)`. The VM answered ssh, was still in early boot, `cat /sys/module/mxfs/srcversion` returned the banner, and the build check compared the banner to the expected build. Chain-timing trap, not a rig fault. [[trap-death-lap-victim-still-booting-prep-build-check-reads-nologin-banner-as-srcversion-mismatch]]
- Rule from that: before any prep that follows a death/restart lap, wait (bounded, about 120 s) until `test ! -e /run/nologin` on every node, or `systemctl is-system-running` is not `starting`. The death-chain script does this at the top of each lap. A NOPREP lap about 60 s later showed the restarted victim had rejoined on its own, so the failed preps did not leave the rig unusable.

## 2. The worse half: the banner is persisted as the cluster marker's srcver

- A rig job started while test1 was still booting. `prep_cluster` printed `prep OK ... build 9C998A5A...` and `marker updated`, but the ssh read of srcversion had returned the banner, and that string was written to `.cluster_marker.json` as the cluster's identity. [[trap-nologin-banner-gets-persisted-into-cluster-marker-srcver-and-poisons-every-later-row]]
- Every later row then died at the marker comparison (`cluster is prepped for 2/tcp (srcver="Systemisbootingup...") , you requested ... srcver=9C99...`) and emitted nothing for the row: no PASS, no FAIL, no verdict line. That silence reads as a broken harness rather than a stale marker. Recognise it instantly: a `run.sh <N> <dlm> <row>` that prints nothing.
- It differs from case 1 in three ways: the prep reports OK and shows the correct build on its own line; the bad value outlives the transient boot; the failure surfaces rows later.
- Fix: re-prep once both nodes genuinely answer. Gate on readiness first, not a single poll and not `/run/nologin` alone: `test -e /run/nologin && echo BOOTING || cat /sys/module/mxfs/srcversion`, and require a hex srcversion before proceeding.
- Underlying harness defect: the marker write should reject anything that is not a hex srcversion instead of storing whatever the shell returned. A prep that writes an unvalidated string as cluster identity and reports OK is the recurring family of a mechanism reporting success while quietly not working.

## 3. A knob verified in a standalone prep is not evidence about the board that follows

- Setup: `env MXFS_FORCE_PREP=1 MXFS_EXTRA_MODARGS='dir_datascan_heal=0' ./run.sh 2 tcp prep_cluster` (heal=0 verified on both nodes), then `./run.sh 2 tcp`. By row 5 the knob was back ON. Proven by the `P26-DSCAN` probe, which prints only inside `mxfs_dir2_datascan_lookup`, whose call sites are all gated on `mxfs_dir_datascan_heal` (`xfs_dir2_leaf.c:2257,2518`, `xfs_dir2_node.c:2520,2581`); it fired 00:51:50-00:51:55 inside the failing `cache_coherency` row. [[trap-the-board-prep-row-resets-mxfs-extra-modargs-so-a-knob-off-board-runs-knob-on]]
- The mechanism is NOT established. The first guess (board row 1 is `prep_cluster`, reloading the module without the modargs) is wrong: the board showed `ran=27` with no prep row because the standalone prep had satisfied it. Unchecked candidates: `precond_readiness` remounting, `run.sh` re-prepping on a stale marker, the modarg never persisted for later module loads.
- Check that works: record the knob in the SAME window as the verdict, from the nodes: `tools/mxfs_sshpass.sh test1 'cat /sys/module/mxfs/parameters/<knob>'`. `tests/sess493_d0492_crash_durability.sh` writes `persig_<node>.txt` per node at lap start, which is why its s598b lap was trustworthy. Better, use a probe whose presence or absence implies the knob state, as `P26-DSCAN` does.
- Counting traps from the same session: `P21H-LEAFHOLE` is a census of every ENOENT in a leaf-format lookup, not a hole count; only `hv_in_leaf` separates a missing hash (0) from a wrong address (>0), and 0 for a name that legitimately does not exist yet is correct, so read the ledger's `detector` field before counting. A run directory's `kernlog_*.gz` is the whole boot journal, not the row's window; attribute probe counts by timestamp.

## Common rule

A state read once, early, from a source that can answer with something else (boot banner, pre-run verification) is a claim, not evidence. Validate the shape of what was read (hex srcversion), gate on readiness, and capture the state in the same window as the verdict.
