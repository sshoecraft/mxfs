---
name: sess34 lessons (parallel mkdir bug isolation)
description: sess34 isolated the long-standing Mode A peer-coherency bug to a sharp repro using tests/cluster/test_concurrent_mkdir.sh; identified the dir3-buf-not-iflushed-before-DLM-unlock root cause; falsified H1/H2/H4; F2 H7 H8 H8b H8c H9 fixes all reverted (none worked, lock-inversion against xfsaild). Bug not yet fixed.
type: project
originSessionId: f7dd1ff0-af04-45e5-9863-9ac20999ea10
---
# sess34 — parallel mkdir bug isolation

## Date: 2026-05-08

## Net result
- Bug NOT fixed yet.
- Bug PROPERLY ISOLATED with sharp reproducible signature.
- Multiple attempted fixes all reverted (H7-H9). Each failure narrowed the search.
- Sess35 prescription captured in state.md.

## Critical discovery — RULE 4 added

`/src/mxfs/CLAUDE.md` got a new RULE 4 codifying the
hypothesis→instrument→prove→patch→loop methodology. Past sessions
were patching from code reading without instrumented proof, leading to
multiple iterations of the same bug surfacing in different ways.

## Core finding: clean repro with a sharp signature

`tests/cluster/test_concurrent_mkdir.sh` (the proper test framework, NOT
the ad-hoc rsync bench) at 2 nodes on v0.4.1 baseline:
- ~99/100 dirs visible to node1 in ~18s wall on first iter.
- The MISSING entries are ALWAYS a contiguous range starting from
  `node2_dir1` or near it (e.g., `node2_dir1`, or `node2_dir4..6`).
- node2's view is FULL PASS (sees its own + all of node1's).
- Subsequent iters on the same mkfs degrade catastrophically (must
  virsh-destroy+start+remkfs every iter).

This is the actual sess20-onwards Mode A bug, finally with a sharp
isolated repro.

## Smoking-gun dmesg signature

In test2 dmesg at the moment test1 BAST'd `concurrent_mkdir`:
```
P56-INSTR ino=8388736 BAST-MEM-PRE vfs_size=6 disk_size=4096 i_dlm_state=3
P59-INSTR ino=8388736 BAST-LOGITEM in_ail=0 pinned=0 ili_fields=0x0
P55-INSTR ino=8388736 BAST-DISK disk_fmt=2 disk_size=4096 disk_nlink=52 first=""
P36-INSTR ino=8388736 BAST-DIR-STALE ext=1 dirblks=1 cached=1 staled=0 skip_locked=1
P70-INSTR ino=8388736 PRE-UNLOCK-BARRIER flags=0x80020 realns=...
```

Critical reads:
- `staled=0 skip_locked=1`: the dir3 buf was LOCKED when BAST-DIR-STALE
  trylock'd it. Skipped.
- `flags=0x80020` = `_XBF_DELWRI_Q | XBF_DONE`: the dir3 buf is
  delwri-queued (queued for delayed write) but not yet on disk.
- `BAST-LOGITEM in_ail=0 pinned=0`: the inode's own log item is clean
  — the issue is at the BUF log item layer (separate item).

The dir3 buf with the just-mkdir'd entries is **queued in delwri but NOT
yet on disk** at the moment of `mxfs_v5_dlm_inode_unlock`. Peer's
FUA-read goes to disk, gets pre-mkdir content, CAS-overwrites entries.

## Falsified hypotheses

| H | Description | Status |
|---|---|---|
| H1 | Phase-3 forced-release after 2s timeout (`xfs/xfs_mxfs_dlm.c:2966-2981`) | Real code path but doesn't fire as dominant cause |
| H2 | LIO target serves stale-LBA bytes from prior FS | Falsified by direct dd from all 16 initiators after fresh mkfs (all-zero) |
| H3 | CAS retry tight-loop livelock | Partial — moderate rate (~14 miscompare/sec/node), not pathological |
| H4 | SCSI READ FUA returns rc=0 with NO buffer fill | Falsified by 0xCD pre-fill experiment |
| H5 | Partial buffer fill (some bytes unwritten) | False positive — pre-fill values matched legitimate disk data |

## Reverted fix attempts

| Fix | Approach | Why it failed |
|---|---|---|
| F2 | `memset(0)` before `read_slot` | Drove SCSI MISCOMPARE rate up — zeros mismatched disk in CAS VERIFY |
| H7 | Push extra AGs that hold dir-extent blocks | No-op — test workload has dir in inode's own AG |
| H8 | Blocking `xfs_buf_lock` + `xfs_bwrite` on dir3 bufs | 6m/50% regression — lock inversion vs xfsaild |
| H8b | Trylock + `xfs_bwrite` only when buf unlocked | No correctness change (bug surface IS the locked buf) |
| H8c | Move delwri-q dir3 bufs to local list + `xfs_buf_delwri_submit` | No correctness change (list_move racy with ail_buf_list) |
| H9 | `XFS_ILOCK_EXCL` across whole bast drain | 6m/50% regression — same lock inversion as H8 |

## Root cause analysis

The dir3 buf IS dirty (has un-iflushed mkdir entries) and IS locked
(by some XFS internal — likely the BLI lock held by transaction commit
or xfsaild's iop_push). The bast handler runs concurrently with
xfsaild and transaction commit on the same inode. Any lock the bast
handler takes that overlaps with what xfsaild needs causes deadlock
(H8/H9). Any lock it skips (trylock) misses the very buf with the bug.

The fix needs to coordinate WITHOUT taking the BLI lock or ILOCK during
the drain. Options for sess35:
1. Direct AIL walk that pulls dir3-buf BLI and submits its buf without
   the BLI lock (XFS internal API study needed).
2. Add inode-level `i_dlm_demoting` flag that user-process commit path
   honors as a barrier (state machine change in ilock_begin).
3. Different write path — instead of waiting for delwri-queue, force
   the transaction commit's BLI directly to disk via `xfs_log_force`
   targeted at the BLI's LSN, then wait for that LSN to reach disk
   for the buffer.

## Project lifecycle observation

Sess20 onwards has been chasing variations of this same Mode A bug.
Various sessions added partial mitigations (BAST-DIR-STALE walk in
sess24-25, FUA-read in sess21-22, etc.). The bug never went away
because none of those addressed the actual race: dir3 buf
delwri-queued but not iflushed at the moment of DLM unlock.

The sess33 deadlock fix (`_XBF_MXFS_ALLOC_QUEUED` flag) was REAL fix
for cluster bufs (newly-allocated inode chunks). But the analogous
fix for dir3 bufs hasn't landed yet. That's sess35's task.

## Pre-conditions for sess35

- v0.4.1 baseline restored, srcversion `F1F98A5087D510F83EF32D5`.
- 16 libvirt VMs prepped with `/dev/sdc` shared LUN.
- `tests/cluster/test_concurrent_mkdir.sh` is the right test.
- Reproducible at 2 nodes in 18s — fast iteration loop.
- See state.md for full handoff details + recipe.
