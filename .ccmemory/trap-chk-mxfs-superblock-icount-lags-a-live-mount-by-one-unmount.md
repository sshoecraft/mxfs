---
name: trap-chk-mxfs-superblock-icount-lags-a-live-mount-by-one-unmount
description: TRAP (sess574): chk_mxfs's "Superblock icount" reads the PLATTER sb, which MXFS only writes at unmount — three mid-flight samples missed 187 carves.
metadata:
  type: feedback
---

# TRAP: `chk_mxfs -v <dev>` reads the platter superblock, which lags a live mount

## What happened (sess574, 0.75.125, 2-node TCP)

`tests/d0949_sole_survivor_chunkfree.sh` used

```sh
icount() { rs 90 "$1" "sync; chk_mxfs -v $DEV | sed -n 's/.*Superblock icount: *//p' | tail -1"; }
```

as its carve gate, sampled three times: before the creates, after the creates,
after the removes. All three returned **64**. The harness therefore computed
`chunk_inodes_carved=0` and printed `verdict=VACUOUS ... this run measured
NOTHING about the defect`.

The run had in fact carved **187 chunks**. The cold `chk_mxfs` taken in step 4,
*after both nodes unmounted*, said `Superblock icount: 12032` — 11968 more
inodes than the three live samples had reported, in the same run, from the same
tool, against the same device.

## Why

MXFS keeps `sb_icount` (and `sb_ifree`, `sb_fdblocks`) **lazily** and only
writes them to the platter at unmount; they are recomputed from AGF/AGI at
mount. `sync` does not push them. So a `chk_mxfs` sample taken while a workload
is in flight reports the value from **the previous unmount**, not the current
state — and it does so silently, with no staleness marker of any kind.

## The rule

- A live-mount `chk_mxfs` superblock counter is a **historical** number. Never
  gate a verdict on one, and never subtract two of them to get a delta.
- The only trustworthy `icount` in a lap is the **cold** read with every node
  unmounted.
- A gate wants a number the workload itself produced: the count of files
  actually created, an unbudgeted probe, or the cold read. `d0949` now gates on
  `CREATED / 64` and measures the post-state from the step-4 cold `chk.txt`.

## The wider pattern this belongs to

This is the third distinct instrument in this campaign that produced a
confident *null* result by measuring something adjacent to the question:

- `df --output=itotal` reports `maxicount`, not `sb_icount` — unchanged across
  12000 creates.
- `P133-ICLUSTER-SYNCINIT` / `P45-INIT` are print budgets (first 20 / first 40),
  not counts.
- `chk_mxfs`'s `Superblock icount` on a live mount is the last unmount's value.

Before trusting any carve/free counter, ask what writes it and when.
