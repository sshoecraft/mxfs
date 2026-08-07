---
name: ccloop-c7ee71c6-sess26-P6-swallows-peer-dir-reload-notification
description: MECHANISM FOUND: P6 mid-tenure skip swallows peer DIR_RELOAD notifications (src 2/8) after the flag is already consumed; fix is pace-neutral and kill…
metadata:
  type: project
tags: [silent-mkdir-loss, P6, peer-notification, rule4, rule0, fix, livelock]
---

# sess26 — the P6 mid-tenure skip destroys peer directory-reload notifications

## How this was found (method matters — five sessions of marker-guessing failed)

1. Every documented loss-chain marker read ZERO in a losing window (P32E, P195,
   P188, P177, P146V, P51, P65, P194), all probes first confirmed present in the
   module. So the producer had no probe.
2. `tests/dd_loss_differential.sh` differenced per-token probe frequencies
   between the losing node and its 31 peers in the same scoped window. It
   nominated `P6-MIDTENURE-RELOAD-SKIP`: **loser 661 vs peer median 37**, range
   25-215 — 3x above the highest peer, nothing else comparable.
3. New `P81-P6-SRC` histogram counts skips by `i_dlm_stale_src`, so no losing
   window needs to be caught to read it. Only THREE sources appear: 1, 2, 8.
4. Read those sites. Both 2 and 8 are explicit PEER notifications.

## The mechanism

`mxfs_dlm_reload_inode`, the P6 branch:

    S_ISDIR && i_dlm_mode == EX && i_mxfs_dirty_seq == i_mxfs_ex_grant_seq
        -> P6-MIDTENURE-RELOAD-SKIP; ip->i_dlm_stale = false; return;

premise: "dirtied under the CURRENT EX tenure, so in-core is authoritative and
the platter has nothing to teach us."

`P197-P6-PREMISE` shows the stated premise is literally TRUE (`premise=ok`
always). **It is the INFERENCE that is false** when a peer published since.

The two swallowed sources:

- **src=2** (`xfs_mxfs_dlm.c` ~7997): `MXFS_IF_DIR_RELOAD` set, or
  `dir_gen > dir_loaded_gen`. Its own comment: *"reader consuming a peer's
  DIR_MODIFY: get the peer's full image"*.
- **src=8** (`xfs_mxfs_dlm.c` ~25243): EX-acquire fast path, *"a different node
  held EX since our last grant"*. **It does
  `xfs_iflags_clear(ip, MXFS_IF_DIR_RELOAD)` BEFORE calling the reload.**

So at src=8 the sequence is: consume the peer's notification flag → set
`i_dlm_stale` → P6 skips → clear `i_dlm_stale` → return **without reloading**.
The notification is now destroyed on both channels. Our in-core image never
contains the peer's entry, and our next publish from that image omits it.
`mkdir(2)` returned 0 on the peer. That is silent mkdir loss.

Why no existing lever caught it: `mxfs.p6_epoch_override` overrules the skip
ONLY for `src==3`, and every losing window shows `epoch == entry_epoch`
throughout, so it can never engage for srcs 2/8.

**It repeats.** New per-inode `i_dlm_p6skip_n` counts consecutive skips with no
real reload between: measured `repeat_max = 10, 19, 10` on three nodes in a
single PASSING run, with `repeat_ge8` = 3, 12, 3. So one directory can have its
peer notifications swallowed ~19 times in a row.

## The fix — and why the obvious one is forbidden

**NOT `p6_midtenure_skip=0` (always reload).** Measured: correctness fine
(cache_coherency 654/654 28s, dir_reuse 65/65 105s) but `dirent_durability`
goes **120s -> 240s/240s TIMEOUT**. RULE 0 failure. The skip is a hot path.

**Shipped: `mxfs.p6_honor_src_mask`, default `0x104`** (bits 2 and 8) in
`pal/linux/xfs_aops.c`. The P6 skip does not apply when the staleness came from
a source in the mask. Bitmask so alternatives (e.g. adding src 1 = 0x106) are
testable without a rebuild; `0` = pre-fix, for same-build A/B.

## Measured result of the fix (v0.11.227, `E97264C13556C43D19CE0E6`)

| | before | after |
|---|---|---|
| skip hist test1 | `1:47, 2:2, 8:45` | `1:47` |
| skip hist test5 | `1:29, 2:4, 8:12` | `1:27` |
| skip hist test19 | `1:28, 2:2, 8:6` | `1:26` |
| repeat_ge8 | 3, 12, 3 | **0, 0, 0** |
| repeat_max | 10, 19, 10 | **0, 0, 0** |
| dirent_durability | 115-120s | **119s (no RULE 0 cost)** |
| cache_coherency | 654/654 26s | 654/654 26s |
| strong_consistency | PASS | PASS |

srcs 2 and 8 are entirely absent from the skip afterwards — every peer
notification now forces a real reload — while src=1 is unchanged and never
produced a streak. **The livelock signature is eliminated at zero pace cost.**

## Honest status — D-SILENT-MKDIR-LOSS stays OPEN

Proven: the skip swallows peer notifications, with the flag already consumed;
it repeats up to 19x on one inode; the fix removes it, is exercised, and costs
nothing.

NOT yet proven: that this is what produced the specific 8-dirent losses. The
differential (17.4x) is strong correlation, not the byte-exact chain sess22 built
for the P34J/P32E family. Observed loss rate is ~2 in 12 runs, so a clean
post-fix streak needs many paired runs to mean anything. Keep OPEN until the
rate is measured with `p6_honor_src_mask` alternated 0x104 / 0 across many runs.
