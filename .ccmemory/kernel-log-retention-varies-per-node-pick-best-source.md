---
name: kernel-log-retention-varies-per-node-pick-best-source
description: CORRECTION: neither dmesg nor journalctl -k is reliably longer — retention varies ~60x ACROSS NODES. Pick the source that still holds the window mark…
metadata:
  type: reference
tags: [measurement, dmesg, journalctl, scoping, correction, harness]
---

# Kernel-log retention varies per NODE — choose the source per node

## Correction to an earlier sess26 claim

I earlier recorded "dmesg retains ~112 s, journalctl -k retains ~50 min, so
always harvest with journalctl -k." **That generalisation is wrong** and the
harnesses have been corrected. It came from a single node.

Measured on ONE build, minutes apart:

| node | `dmesg` | `journalctl -k` |
|---|---|---|
| test19 | 1824 lines / **112 s** | 59067 lines / ~50 min |
| test5 | 95460 lines / **1407 s** / 17 MB | 73686 lines |

So dmesg was ~30x SHORTER than journalctl on one node and LONGER on the other.
`log_buf_len=16M` IS set on these nodes (`/proc/cmdline`), and prep configures
journald with `RuntimeMaxUse=400M RateLimitBurst=0 RateLimitIntervalSec=0`.
Both sources are size-capped rings, and nodes log at wildly different rates —
state.md already noted dmesg retention varying ~60x across the cluster
(test19 1964 lines/109 s vs test25 136966 lines/1107 s).

This also resolves an apparent contradiction with run.sh's own comment
("journald rotates in ~85 s under probe volume ... the 16M dmesg ring retains
everything"). That comment predates prep's journald config; with
`RateLimitBurst=0` and `RuntimeMaxUse=400M`, journald no longer rate-limits or
rotates as fast. Both statements were true at different times.

## The rule

A `dirent_durability` run is 116-124 s. On a heavy-logging node the dmesg window
is SHORTER than the run being measured, so a dmesg census silently undercounts.
Hardcoding journalctl instead loses data on quiet nodes.

**Per node, choose the source that still has the most lines AFTER the last
`MXFS_DIRENT_WINDOW` marker, and report which one was used (`win_src=`).**
`tests/dd_loss_differential.sh` and `tests/dd_loss_capture.sh` both do this now;
`lib.sh::dirent_window_scope` already reported `win_src=`/`win_trunc=` for the
criterion itself.

**Never concatenate the two sources into one stream to scope them.** The last
marker may be found in one source while the tail is then taken from both, which
silently mixes windows. (I wrote that bug and caught it before running it.)

## Related trap, same session

Derive every view of a window from ONE captured text. An earlier cut of the
differential harness saved the full scoped journal from the best source but
re-queried the node with journalctl for the token COUNTS — two different windows
presented as one measurement. Capture once, count locally.
