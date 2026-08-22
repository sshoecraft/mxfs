---
name: ccloop-c7ee71c6-sess389-publication-durability-gate-landed-0.19.40-5laps-green
description: sess389: publication durability gate (F1-F4) LANDED 0.19.40; 8 aged 32/caw laps green; fault-injected launders 3/3 repaired (0.19.41 knob); D-FOSSIL-…
metadata:
  type: project
tags: [sess389, 0.19.40, 0.19.41, 0.19.42, publication-obligation, PUBOB, P119, dirent_durability, fossil-next-unlinked, agcount, board]
---

# sess389 state (build 0.19.39 -> 0.19.42)

TREE = 0.19.42 sv 4411027355A6F7FDD3BAF6F (mount-side P-AGCOUNT-COLLISION warn + mkfs agcount warn + injection-gate tightening); RIG at session end: see below (last deployed 0.19.41 sv 5A119882CE76FB102F59A91 @64 AGs unless the 25-AG retest prep ran). Rig LUN 128 GiB.

## Proven + fixed (RULE 4, one chain on two nodes) — ccmemory ccloop-c7ee71c6-sess389-GPT-ruling-publication-durability-gate-F1-F4
P82-ADD at PR (mid-drain re-acquire) -> P244 defer -> xfsaild P119 LAUNDERS the nlink=0 conversion (clean, no write) -> P245 converter rc=0 on xfs_inode_clean -> reldefer reload P3-REFUSE kept newer in-core but discharged ledger + cleared LOCAL_UNLINK -> INACT B3 torn-live skip -> AGI entry names LINKED dinode forever -> P88-PUBOB-UNREPAIRED x60/node, P87-PUBLISH-DEFER-EXHAUSTED 4s/AG release -> dirent_durability aged-lap FAIL (late publication) + fossil next_unlinked family.
Fix 0.19.40: F1 xfs_iflush P55B-PUBOB-PR-FLUSH (owned PUBOB+nlink0+PR+same incarnation+live same-type+in AIL => write); F2 mxfs_iflush_agino_target: clean+PUBOB => mxfs_pubob_relog_core (tr_ichange, pipe_relog=1, ILOCK EXCL nowait+deadline, raw un-take) + self-sanction RELFLUSH when PUBOB, -ENOMSG on second clean sighting (P245-RELOG/P245-CLEAN-MISMATCH); F3 reload_kept_ahead (P3/P34F/P184) => no ledger discharge (P177-KEPT-AHEAD-OBLIGATION-OPEN), P-RELOAD-IDENTICAL needs di_nlink equality, different-incarnation adopt cancels PUBOB (P177-PUBOB-SUPERSEDED); F4 LOCAL_UNLINK|ADOPTED_UNLINK cleared only in the real-adopt branch.

## Verification
- d385 laps @32/caw 64AG: 0.19.40 laps 1-5 + 0.19.41 laps 1-3 ALL PASS (posix_multi, rsync_paired 15-30s, dir_reuse_coherency, dirent_durability durable_loss=0). 0.19.39 lap 3 was FAIL (durable_loss=8).
- tests/fleet_pubob_counters.sh (NEW one-pass sweep; 24 serial dmesg greps x32 blew a 40s cap): P88u=0 P87x=0 torn-live=0 reclaim-refused=0 LOGSAME=0 P82-ADD-FAIL=0 P217=0 shutdowns=0 wedges=0; P55B fired (F1 exercised); ka each closed by own P82-REM within ms; P86 totals heads=245 joint_ok=245 SPLIT=0 BADHEAD=0 (sess386 584/580 SPLIT=2 BADHEAD=2).
- FAULT INJECTION 0.19.41 knob pubob_launder_inject (module param; decrements): 3 injected P119 launders (test2 92274871, test10 109052307, test13 104857913) each repaired by one P245-RELOG -> sanctioned flush -> P245 rc=0 pend=1 dur=1 -> P82-REM/ifree. F2 verified. (Injection gate tightened in 0.19.42: only counts when !RELFLUSH && no demoter — the repair's own flush had consumed a count.)
- Full 28-row 32/caw board: 27 PASS + open_defects POLICY (crash_consistency 80s PASS, dlm_lock_correctness, node_responsive, kernel_health, ag_strand_repair, sustained_load, dirent_publish/type_integrity all PASS this session).
- LEDGER: D-FOSSIL-NEXT-UNLINKED-IGET-LOGSAME-388 -> FIXED AND VERIFIED (52 open). AGI (#1) and 361 updated with the evidence; not yet closed (closure = on-disk AGI chain-walk audit per ruling + more aged laps).

## D-RSYNC-LAP-PACE-AG-SHARING-388 (0.19.42)
mkfs_mxfs warns agcount<nodes with collision count + minimum device size (verified test1 loop dev: 50GiB -n32 -> 'agcount 25 < node count 32 ... needs 65219 MB'; 128GiB silent); mount xfs_warn P-AGCOUNT-COLLISION when node_slot >= sb_agcount. Remaining: 25-AG correctness retest (MXFS_LOG_SLICES=80 MXFS_FORCE_PREP=1 prep on the 128GiB LUN -> 5GiB log -> agcount 25), assert warning on slots 25-31 + no shutdown/wedge; then restore MXFS_LOG_SLICES=32 (64 AGs) and re-run board rows.

## Residuals (pre-existing, noted)
- P119 at NL on unlinked inodes followed by own-node P82-REM within ms (harmless end state); ifree FINAL mode=0 write at NL skipped (freed-shell family, P-CR63-SHELL at reuse).
- GPT hazard: whole inode-cluster buffer sibling lost-update = ledger D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY (#20 open).
- mkfs_mxfs has only pr_err (no pr_warn) — the warning uses pr_err. mkfs requires a block device (use losetup in a VM to test).

CRITERIA NOT MET (52 open).
