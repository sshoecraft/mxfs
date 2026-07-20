---
name: sess46-caveat-p46grow-ratelimited-and-single-mode-is-intrablock-loser
description: sess46 CAVEAT: P46-GROW uses pr_warn_ratelimited → drops most grows → the double-grow-vs-ABA correlation is INCOMPLETE. SINGLE-mode loss is the loser…
metadata:
  type: project
---

## sess46 — caveats + SINGLE-mode detail (read with the main sess46 reframe)

### CAVEAT on the "double-grow is just ABA" conclusion:
P46-GROW (xfs_dir2_node.c add_datablk) logs via `pr_warn_ratelimited`, which DROPS
most messages under the 8-node create storm. So the per-failing-round cross-node
grow correlation was INCOMPLETE — I only saw a handful of grows per round (e.g.
only test4 in round 24). I therefore CANNOT definitively rule out a same-round
cross-node DOUBLE-GROW (two nodes grow the same logical block N → one block's
dirents orphaned). The next session should change P46-GROW to a CAPPED counter
(`static atomic_t n; if (atomic_inc_return(&n) <= 4000) pr_warn(...)`, like the
P28E probe) so EVERY grow in a round is logged, then re-run the FAILROUND
cross-node correlation in tests/drc_detail8.sh ([P46-GROW failround newdbno->daddr]).

### SINGLE-mode loss is the LOSER's OWN entry:
Captured SINGLE fails: node8_f49.md5 (round 19), node8_f8.md5, node7_f1, node4_f27.
The lost entry belongs to a node whose block lost the race — e.g. node8 added
node8_f49.md5 to ITS block, but the entry is durably gone ⇒ node8's block was the
LOSER (its logical-block-N mapping was overwritten by a peer's block N, orphaning
node8's dirents). Consistent with a same-round double-grow where the loser's
freshly-grown block (bufgen=0, dirty=1) is orphaned. node7_f1 = the classic
FIRST-dirent loss (sess62 sf->block double-conversion family).

### Build/harness state for next session:
- On-disk build: **A00D8CFE** = sess45 keeper FB296422 + PROBE-ONLY (keeper-equiv).
  All sess45 fix defaults intact (dir_release_fua_write=1, dir_addname_coherent=1,
  memb_settle_ms=20000, tcp_death_grace_ms=40000, dir_epoch_adopt=1,
  dir_epoch_convert_gate=1).
- tests/drc_detail8.sh now: sets `hung_task_timeout_secs=18` per node in
  reboot_clean (catches a >18s D-state wedge BEFORE the 25s TCP_USER_TIMEOUT
  kills it), captures [FAILROUND]+per-node failing-round grows+[MEMBERSHIP]+
  [DEATH/FLAP]+[HUNG-TASK]. NOTE: hung-task only catches UNINTERRUPTIBLE (D) tasks;
  if the wedge is interruptible/a busy-loop it won't fire — then add an explicit
  in-mxfs "drain spinning >15s" probe in mxfs_ail_drain_inode_to (xfs_mxfs_dlm.c
  ~3164) logging the blocked op + iter count.
- Two fail modes confirmed roughly equal: SINGLE (intra-block, 1 entry, every run)
  and MASS (node-isolation/death, intermittent, many entries). 8/tcp keeper pass
  rate ~20-50%.

See [[sess46-REFRAME-8tcp-dominant-failure-is-node-isolation-wedge-not-doublegrow]]
[[sess46-death-timing-chain-and-wedge-is-root-of-MASS-isolation]].
</body>
