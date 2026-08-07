---
name: ccloop-c7ee71c6-sess26-P6-MIDTENURE-differential-nominates-producer
description: D-SILENT-MKDIR-LOSS: token-frequency differential nominates P6-MIDTENURE-RELOAD-SKIP (loser 661 vs peer median 37). Always-reload is a RULE 0 fail (2…
metadata:
  type: project
tags: [silent-mkdir-loss, P6, differential, rule4, rule0, dirent_durability]
---

# sess26 — the differential method, and what it nominated

## Why differencing instead of another marker hypothesis

By sess26 EVERY documented marker of the loss chain had been measured to zero
in a window where dirents were durably lost (test19, `durable_loss=8`):
P32E, P195, P188, P177, P146V, P51, P65, P194, P34J-RELOAD-DEMOTE-BAIL — all 0,
with all 11 probes first confirmed present in the built module via
`strings mxfs.ko`. Race bails resolve 623/623 and never overlap the P6 skip
(`p6skip_after_rb=0` of 1689 skips). So the producer had NO probe, and five
sessions of nominating the next marker by intuition had failed.

**New harness `tests/dd_loss_differential.sh`**: loop `dirent_durability` until
FAIL, then for every node harvest the window-scoped kernel log, reduce it to
`mxfs: <TOKEN>` frequencies, and report tokens where the LOSING node departs
from the 31-peer distribution. The data nominates the probe instead of me.

## What it nominated — one clear outlier

Second capture, test4, `durable_loss=8 late_ok=14 mkdir_err=0`, all 32 nodes
scoped to the same window:

    TOKEN                          loser  peer_med  peer_range  flag
    P6-MIDTENURE-RELOAD-SKIP         661        37      25-215   x17.4
    P197-P6-PREMISE                  661        37      25-215   x17.4  (co-printed)
    P72-ORPHAN-WAIT                   28         4        0-16   x5.8
    P72-SWALLOW-DEAD                  38         6        0-36   x5.6
    P126-DEMOTE-RACE                  38         6        0-36   x5.6
    P-SFDIR-STALE-RMW                  3         0         0-7   x4.0
    P58-STALE-BASE-ADD                 3         0         0-7   x4.0
    (depressed x0.3: P-CCREGRESS, P128-REARM-UNPUB, P139-RECYCLE-UNLINKED,
     P71-UNDERFLOW, P9-NLEDGE — all 4 vs median 17)

661 is **3x above the highest peer (215)**, not merely above the median. The
x5.x entries are plausibly downstream of the same stall. The DEPRESSED group is
notable too: the loser did FEWER of the ordinary per-round operations, i.e. it
was starved/slow, consistent with it churning this one path.

## The path itself

`mxfs_dlm_reload_inode`, guard:

    S_ISDIR && i_dlm_mode == EX && i_mxfs_dirty_seq != 0 &&
    i_mxfs_dirty_seq == i_mxfs_ex_grant_seq
        -> print P6-MIDTENURE-RELOAD-SKIP; ip->i_dlm_stale = false; return;

It clears staleness and returns WITHOUT reloading, premise: "the dir was
modified under the CURRENT EX tenure, so in-core is authoritative and the
platter has nothing to teach us."

`mxfs.p6_epoch_override` (default 1) already overrules this — but ONLY when
`i_dlm_stale_src == 3` (the epoch gate asked). Every losing window shows
`epoch == entry_epoch` throughout, so that override **cannot engage** here.

## New lever, and the RULE 0 result that constrains the fix

`mxfs.p6_midtenure_skip` (default 1; 0 = always reload) added in
`pal/linux/xfs_aops.c`.

Armed 0 on all 32 nodes:

| criterion | skip=0 |
|---|---|
| cache_coherency | PASS 32/32 654/654 28s |
| strong_consistency | PASS 32/32 4s |
| dir_reuse_coherency | PASS 32/32 65/65 105s |
| **dirent_durability** | **FAIL — 240s/240s TIMEOUT (was 120s), NO_TERMINAL_RECORD=32** |

So correctness is unharmed but the wall **more than doubles and blows the
budget**. The skip is a hot-path optimization. **"Always reload" is not an
available fix (RULE 0).** The fix must be "reload only when the premise is
actually violated".

## H4 — the next hypothesis, and the one measurement that tests it

In a (differently-scoped) sample of 44 skips on a losing node, ONE inode
accounted for 19 of them. So the loser may be in a **staleness livelock**: a
peer's BAST sets `i_dlm_stale`, this path clears it without reloading, repeat —
so the node never re-reads the peer's published state, and its own later
publish omits the peer's entry.

`P197-P6-PREMISE` already prints `src=%u` (`i_dlm_stale_src`) and fires at the
same 661. **The decisive measurement is the `src=` distribution and the
per-inode concentration at the P6 skip in a captured losing window.** If the
sources are peer-publication sources, the fix is narrow: honour those sources
in the skip guard, the way src==3 is already honoured by p6_epoch_override.

Note `P197` premise itself read `ok` in every sample — P6's *stated* premise
(dirtied under this tenure) is TRUE. It is the INFERENCE from that premise
("therefore the platter has nothing to teach us") that is wrong when a peer has
published since.

## Harness traps fixed while building this

- **`dmesg` is shorter than the run.** 1824 lines / 112 s retained vs a 120 s
  run; `journalctl -k` holds 59067 lines / ~50 min. Fixed here and in
  `tests/dd_loss_capture.sh`.
- **Capture at failure time, and STOP.** The census read P6=661; a follow-up
  query minutes later re-scoped "the last window" and read 44 — because the
  next iteration had stamped a new `MXFS_DIRENT_WINDOW`. The harness now saves
  the full scoped journal per node and exits 10 on the first capture.
- **A blocked run is not a pass.** A killed harness left an orphaned `run.sh`
  holding `/tmp/mxfs_run.lock`; three iterations then produced no verdict line
  and the loop treated them as non-failures. It now aborts loudly.
- **`pkill -f <harness-name>` kills your own wrapper shell** (its command line
  contains the pattern). Use `pgrep -f` + explicit kill.
