---
name: ccloop-c7ee71c6-sess380-summary-target-deadlock-and-pace-attribution
description: sess380 final: SCST wait-for-cycle found+fixed (120.5s->0.25s), 2 critical defects DISPROVED, pace defect fully attributed, 2 new criticals filed; op…
metadata:
  type: project
tags: [sess380, summary, handoff, scst, pace, 380, ledger]
---

# sess380 final state

Build: **VERSION 0.15.5**, `mxfs.ko` srcversion **D53B37C75EB04C2565798AD**,
deployed and mounted on all 32 nodes. Target: **SCST 3.11.0-pre+caw-abort-reclaim.3**
(patched this session). Full 32/caw board **27/27 PASS, 0 FAIL** — only the
RULE-6 `open_defects` policy cell red. Ledger: **open=50 of 111**, 36 critical.

## The headline: the 60s quantum was NOT MXFS

Root-caused a genuine wait-for **cycle** in the SCST target's SCSI-atomic
(COMPARE AND WRITE overlap) blocker graph and fixed it. Full detail in
`sess380-scst-atomic-wait-cycle-ROOT-CAUSE-AND-FIX`. One-variable A/B, MXFS
byte-identical across both columns: **28-of-32 simultaneous unmount went
120.48s -> 0.37s; 32-of-32 went 60.65s -> 0.25s**; worst command on the hot
slot 60,426ms -> 59ms; ABORT_TASK 12 -> 0.

Two critical defects **DISPROVED** on that evidence:
- `D-MASS-UMOUNT-ROOT-EX-SERIALIZE-100S-526B`
- `D-HOT-SLOT-CAW-SERIALIZES-LUN-PER-LBA-379` (its own 2x acceptance bar now
  scores **1.6x** — worst `stat` of the contended root 13ms vs 8ms for an
  uncontended file, 1417 pairs)

## D-32NODE-SHARED-DIR-CREATE-PACE is now fully attributed

Three tools were lying, all three fixed:
1. **P138-WAIT** times ONE `wait_for_grant` call (>5ms). A contended acquire is
   many sub-5ms waits with retries between them: a run with p95 424ms produced
   **4 lines fleet-wide**.
2. **P139-LOCKTOTAL** is the right probe (whole acquire, all retries) but its
   floor was hardcoded at **800ms — above the entire distribution**, so it
   produced **zero**. Now `mxfs.caw_locktotal_ms` (default unchanged 800). At a
   50ms floor the same workload yields 118 acquires totalling **57.1s**, which
   matches the workload's own total create time.
3. **`create_scale_curve.sh`'s "private" arm was not a control** — every node
   ran `mkdir -p $dirbase/r$i` INSIDE the measured window, so both arms
   contended on one parent inode. That is almost certainly why this entry
   carried two irreconcilable private-arm numbers for a month. Fixed; the same
   bug was in `caw_grant_wait_anatomy.sh`, which additionally only ever ran the
   PRIVATE shape (now `SHAPE=shared|private`, default shared).

**Clean ladder** (8 creates/node, fresh fs, 32 healthy nodes):
```
participants        1     2     4     8    16    32
PRIVATE wall_p50   37   170   104   125   220   222 ms   <- 6.0x
SHARED  wall_p50   37    87   160   385  1000  1842 ms   <- 49.8x
SHARED  p50         3     7     7     8    10    10 ms   <- FLAT; all cost is tail
```
8.3x shared-vs-private on wall, 34x on p95.

**Mechanism, counted on both sides of the same slot.** One 512B CAW slot holds
a directory's entire lock state, so a waiter REGISTERING its bit and the holder
CLEARING its bit CAW the same word and invalidate each other:
- release side (new probe **P381-UNLK-CONTEND**): 112 contended unlocks, mean
  **1.96 miscompares**, mean backoff sleep 10.1ms, **mean unlock wall 27.9ms**
  (max 77ms); sleep is 36% of it, the other 64% is the extra find_slot READ +
  CAW each losing retry issues.
- acquire side: **109 of 121 retries are `ea_regwait`** — lost the
  WAITER-REGISTER CAS. Zero `ea_claim`.
- holder cost split (**P138-BAST**): `sx` (the wire unlock proper) is
  **95-98%** of a 26-48ms release; the mandatory drain pipeline is 2-4ms.
- blocking census: 74.5% `mxfs_pal_cond_timedwait` under `caw_lock_body`,
  **7.0%** transport (was 14.2% before the target fix).

Positive feedback: more waiters -> longer hold -> longer queue -> more waiters.
This is exactly what the sess379 RULE-5 ruling predicted for this format, and
its prescribed fix applies: **writer GATE record + incarnation-tagged per-node
reader records**, so registering interest writes the node's OWN sector.

## Two new critical defects filed

- **`D-RELOG-BEHIND-DISK-OBLIGATION-DEADLOCK-WEDGE-380`** — 3 of 32 nodes
  force-shut-down on the SAME inode, identical `causes=0x1 badness=4`, tries
  979/999/1014, each after 122 `P189-RELOG-BEHIND-DISK` refusals. The refusal
  is correct (don't overwrite a peer's newer image) but it maps onto
  MXFS_RELCAUSE_OBLIG_OPEN, badness can never fall, and `mxfs_inode_wedge`
  escalates a *recoverable* condition as an *unprovable release*.
  **I corrected my own first mechanism**: the refusal is COMMON and normally
  recovers (77 in one clean PASS run, zero wedges). The open question is what
  distinguishes those from the ones that never recover.
- **`D-DLMSCALING-DSCAN-MISS-CR3-EUCLEAN-SHUTDOWN-380`** — test11 took a
  P26-DSCAN-MISS storm then `P-CR3-CANCEL error=-117 (EUCLEAN) trans_dirty=1`
  and withdrew; did not reproduce on an immediate re-run.

## Standing traps learned the hard way

- **`prep_cluster` CLEARS every node's dmesg.** Both new defects nearly lost
  their forensics. Dump every ring to a file BEFORE re-prepping.
- **A single node self-shutdown blocks the whole board**: the next `./run.sh`
  refuses with "marker stale: testN live='<sv>' want='<sv> MOUNTED'" — the
  srcversions match, the node just is not mounted.
- The node device is **`/dev/mapper/mpatha`**, not `/dev/sda`.
- Board chunk 4 needs **more than 400s** now; it was cut mid-`ag_strand_repair`.
- clyde's kernel ring holds only ~10s of SCST block tracing under a 32-node
  storm — stream it with `sudo dmesg -w > file &` around the whole run.

## Next

Ledger order. The pace defect is the one with a complete attribution and a
specified fix; it needs a RULE-5 consult on the concrete on-disk layout before
any code, because it changes the CAW slot format and
`MXFS_CAW_MAX_SLOTS=65536` is an on-disk invariant. A cheaper interim worth
A/B-ing first (no format change): drop the 1-15ms nap when the only difference
in the losing read is foreign WAITER bits — those commute with our clear, and
the nap is 36% of the unlock wall.
