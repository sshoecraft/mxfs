---
name: ccloop-c7ee71c6-sess19-A-sfstorm-reproducer-and-three-defects
description: sess19: 32/caw fdw dirent-loss ROOT captured byte-exact; new tests/sf_mkdir_storm.sh reproduces 3 shortform-dir defects at ~25%/round.
metadata:
  type: project
tags: [ccloop, c7ee71c6, sess19, 32caw, shortform, dirent-loss, nlink, sf_verify, reproducer]
---

# sess19 — 32/caw shortform-directory defect family

Cluster state at session start: all 32 VMs shut off, SCST not loaded,
tests/logs wiped by the history reset. Bring-up that works:
`for i in $(seq 1 32); do virsh -c qemu:///system start test$i & done` →
`scripts/mpath_up.sh up 32` (does host SCST + both portals + guest logins) →
`make modules && make tools` (tools were UNBUILT — prep dies with
"mkfs tool not found") → `MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster`
(~65s).

Matrix at entry (./mkstatus): 478/480 rows PASS. Only 32/caw had FAILs —
`dir_reuse_coherency` (now passes) and `fence_during_write`.

## DEFECT A — fence_during_write @32/caw: durable dirent loss. ROOT CAPTURED.

Parent `.fence_during_write` ino=56623232 ended with **nlink=35 (⇒33
subdirs) but only 30 names**, identical on all 32 nodes. node1, node24,
node25 lost permanently; their child inodes orphaned.

Reconstructed the publish ledger by ordering every `P56-DIRWRITE` for that
inode across all 32 kernlogs by its `vep=` field:

    vep=4 test25 dgen=3 [.. hot node25]
    vep=5 test1  dgen=3 [.. hot node25 node1]
    vep=6 test24 dgen=3 [.. hot node25 node1 node24]
    vep=7 test27 dgen=4 [node29 node30 node10 node20 hot node27]  <== DROPS 3

test27's own log, four prints inside 4ms, comm=mkdir:

    P174-STALEGEN-ADOPT dir_gen=4 loaded_gen=3      (force disk adopt)
    P9-SFREFRESH incore_bytes=114 disk_size=73
    P3-REFUSE-OLDER-DISK disk_chg=8 incore_chg=10 — keeping fork   (x2)
    P21-RB own_work=0 incore_cnt=8 disk_cnt=5 incore_bytes=114 disk_sz=73
    P61-ADOPT-CHK incore_sz=73                     <-- fork replaced anyway
    P56-DIRWRITE vep=7 write=[6 names]

So the reload path CORRECTLY refused the older platter image (P3
time-travel guard: same incarnation, di_changecount 8 < in-core i_version
10) and then `mxfs_dir_rebase_shortform` adopted that same image regardless
— its wholesale-adopt arm (`own_work==0`) has NO test that the disk is not
older. Evidence: tests/logs/fdw_32caw_20260728_120403.

FIX LANDED v0.11.140 `P178-REBASE-OLDER-DISK` + param
`mxfs.dir_rebase_verguard` (default 1): refuse the rebase when
`di_changecount < i_version` for the same incarnation. NOT a content union —
a clean fork legitimately differs from a NEWER disk image by entries a peer
REMOVED, and unioning those back is the sess56 durable resurrection.
Fires 2-18x per storm run. **Attribution still incomplete** — fdw passed
after the fix but P178 fired 0x in that run, so the pass is not yet
attributable (the sess14-J trap).

## THE REPRODUCER — tests/sf_mkdir_storm.sh (NEW, keep)

`tests/sf_mkdir_storm.sh <rounds> [nodes] [slot] [per_node]`, e.g.
`tests/sf_mkdir_storm.sh 40 32 2 1` → ~110s, **11 of 40 rounds fail**.
N nodes mkdir into ONE shared parent on a shared wall-clock slot; each node
verifies round K-2 at the top of round K (before teardown); rank 1 tears
down round K-4 in the BACKGROUND to drive inode/daddr reuse.

Oracle: `nlink == 2 + subdirs`, plus every rank's name present, checked on
EVERY node. Analysis helper: `tests/sf_storm_ledger.py <run_dir> [round]`
orders that round's parent's publishes by vep and flags the shrinking write.

Harness traps that cost real time — do not reintroduce:
- rank 1's `rm -rf` on the critical path outran a slot, so test1 silently
  missed every later round and the verifier reported "missing node1",
  indistinguishable from real loss. Now backgrounded + a STORM_DONE
  assertion exits 2 (INFRA-FAIL), never a loss verdict.
- per-name `[ -d ]` verification = 32 cluster lookups/round ≈ 25s/round,
  so nodes fell behind their slots and the storm stopped being concurrent.
  One `ls -1` + shell match instead.
- a fixed $BASE inherits the previous run's rounds (creates EEXIST,
  visible=160 expected=32). $BASE is now per-run.

## DEFECT B — lost nlink bumps ⇒ UNDELETABLE DIRECTORIES

Shapes seen: `nlink=29 visible=32` (5 bumps lost, all names present) and
whole lost mkdirs (`missing=[node14_1]` with NO mkdir error — the create
returned success and both dirent and bump vanished cluster-wide).

Consequence is not cosmetic: later rmdirs underflow the count, so
`/mnt/shared/.sfstorm/d4` settled at **nlink=4294967295** and d10 at
**nlink=1**, both listing only `.` and `..`, both returning ENOTEMPTY on
rmdir forever. `rm -rf` of the tree fails permanently.

Serialized cross-node mkdir propagates nlink perfectly (2→6 over 4 nodes),
so this is a true concurrency race, not a missing propagation.
REFUTED: torn core-vs-fork adopt at the rebase (probe P179-REBASE-CORE-TEAR,
0 fires — at every rebase adopt disk_nlink == incore_nlink).

## DEFECT C — torn LOCAL fork ⇒ sf_verify corruption ⇒ MOUNT SHUTDOWN

test6 during a storm: **34,711** identical
`P171-SFNULL ino=60817544 if_bytes=148 ... rd_held=1` +
`Metadata corruption detected at xfs_dir2_sf_verify` pairs, then permanent
EIO on /mnt/shared. State is `if_format=LOCAL && if_data==NULL &&
if_bytes=148`, with xfsaild holding ILOCK_SHARED and NO writer in flight —
so it is a COMMITTED PERSISTENT state, not a destroy/repopulate window.
This is state.md's D4 (sf_verify) with the trap finally firing.

`xfs_idestroy_fork` frees a LOCAL fork's if_data and NULLs it but leaves
if_bytes/if_format (same class as the v0.10.31 if_broot_bytes fix in that
very function). Any path that destroys without completing the repopulate
leaves the inode unflushable forever.

REFUTED as the producer: `xfs_inode_from_disk` failure after the reload's
destroy — "DLM inode from_disk FAILED" appears **0 times** on any node.
`wr_last` is useless here: it always shows the drain's P146V re-log arm
(`xfs_mxfs_dlm.c:14427`, addr2line of `mxfs_dlm_bast_process+0x4a22`),
which re-logs every 2ms and overwrites the stamp.

NEXT INSTRUMENT (built, v0.11.143 srcver 9C2E432B7C1891A19D9FB81, not yet
run): `mxfs_note_fork_tear()` tripwire called from `xfs_trans_log_inode` —
the step that turns the torn fork into a dirty AIL item — printing
`P181-FORK-TORN` + `dump_stack()`, capped at 20. That names the producer.

## Build/version trail
0.11.139 entry → .140 P178 guard → .141 P179 probe → .142 nlink ledger
(`mxfs.nlink_ledger`, P180-NLB/NLR/NLW; default 0) → .143 P181 tripwire.
