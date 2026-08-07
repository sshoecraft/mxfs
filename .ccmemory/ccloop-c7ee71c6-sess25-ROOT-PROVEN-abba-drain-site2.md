---
name: ccloop-c7ee71c6-sess25-ROOT-PROVEN-abba-drain-site2
description: D-BAST-WRITEBACK-ABBA-DEADLOCK root PROVEN + deterministic reproducer + same-build A/B: drain site 2 (mode==NL) is the ABBA site; FIX-27 default ON.
metadata:
  type: project
tags: [abba, deadlock, writeback, bast, fix27, rule4, reproducer]
---

# sess25: D-BAST-WRITEBACK-ABBA-DEADLOCK — ROOT PROVEN, REPRODUCED ON DEMAND, FIXED

## The thing three sessions missed: bast_process flushes TWICE

`mxfs_dlm_bast_process` (xfs/xfs_mxfs_dlm.c) calls `filemap_write_and_wait` at
**two** places, and they are NOT equivalent:

- **site 1** — "Flush dirty pages to disk", runs while `i_dlm_mode` is still the
  granted mode. A colliding writeback submitter asking for ILOCK_SHARED is
  satisfied by `mxfs_dlm_ilock_begin`'s nest-admit fast path
  (`i_dlm_mode >= request`) and **never parks**. This site cannot deadlock.
- **site 2** — the `S_ISREG` durability flush, runs AFTER
  `ip->i_dlm_mode = MXFS_LOCK_NL` and BEFORE the wire unlock. mode==NL fails
  every nest-admit, so the submitter parks in the demote-wait **still holding
  its folio**, and this flush walks into `folio_lock()` on it.
  **This is the ABBA site.**

`i_dlm_drain_site` (new, xfs_inode.h) records which one the drain is in;
P47-FILEBLOCK prints it as `dsite=`. P28-DRAINSITE2 counts site-2 entries with
`dirty=`.

## Why sess24's exerciser got 200/200 "collisions" with 0 P47

Its injection broke out of its window on `state == BAST|DEMOTING`. That state is
reached at **site 1**. The parking precondition is **mode==NL**, not the state.
Predicate corrected to `(state BAST|DEMOTING) && i_dlm_mode == 0`.

## The missing half — synchronise on the DRAIN

`mxfs.fix28_drain_stall_ms` (new, pal/linux/xfs_aops.c, inside `xfs_map_blocks`,
demoter-ONLY + site-2-only + once per drain) stalls the drain mid-batch, after
`write_cache_pages` fetched a dirty-tagged folio batch and locked its first
folio. A submitter arriving during the stall locks a LATER folio of that batch
and parks holding it; when the stall ends the drain blocks on exactly that
folio. Key kernel fact: `writeback_get_folio()` (mm/page-writeback.c) calls
`folio_lock()` **unconditionally** and works off the already-fetched batch, so
the submitter having cleared the dirty bit is not a reprieve.

## Harness: tests/abba_wedge_ab.sh <drainhost> <peerhost> <0|1> [secs] [stall_ms]

Two workload facts, both MEASURED — do not "improve" them:
- Peer must **READ**, not write. A peer write loop gave 2572 P7B-BASTNOTIFY and
  **ZERO** P28-DRAINSITE2 over 100 s: constant EX ping-pong keeps the drain
  node re-acquiring and the release never reaches the post-mode-clear flush.
- Needs **N independent files** (NF=6). One file reached site 2 in only 3 of 4
  runs; a run with P28-DRAINSITE2=0 is NOT a control, it is an absent hazard.
  The script exits 3 INCONCLUSIVE in that case rather than scoring a pass.
- Liveness probe must be a stamp file, not `timeout 25 sync`: a sync blocked in
  D state ignores SIGTERM, so the ssh hangs and the result is an ambiguous
  empty string.

## Same-build paired A/B (v0.11.207, srcver A797C0480729E0D96999C88, 2/caw)

|                              | arm 0 (fix off) | arm 1 (fix on) |
|------------------------------|-----------------|----------------|
| P28-DRAINSITE2 total         | 21              | 21             |
| ... with dirty=1             | 17              | 16             |
| P28-DRAINHOLD (hazards built)| 17              | 16             |
| P47-FILEBLOCK (blocked subs) | 10              | 10             |
| P25-IOEND-ADMIT src=writepages | **0**         | **2**          |
| P73-WAITSTALL                | 1               | 0              |
| sync                         | **SYNC_WEDGED** | **SYNC_OK**    |

Arm 0 captured both legs from /proc/PID/stack, byte-identical to the test27
live capture (mxfs-ino-bast in folio_wait_bit_common under
mxfs_dlm_bast_process+0x5d8; flush-252:1 in mxfs_dlm_ilock_begin under
xfs_map_blocks). Identical exposure, opposite outcome, ONE build, no re-prep.

## Runtime recovery is real and is itself the proof

The demote-wait re-evaluates `mxfs_ilock_admit_ioend` every 3 s (FIX-24 poll),
so `echo 1 > /sys/module/mxfs/parameters/fix27_shared_admit` **un-wedges an
already-deadlocked node**. Doing that on the arm-0 wedge produced exactly ONE
probe line and the node came back:

    P25-IOEND-ADMIT ino=132 state=3 g2=5 req=3 src=writepages

state=3 DEMOTING, g2=5 mirror still EX, **req=3 SHARED** — precisely the case
FIX-26's EX-only gate cannot cover and FIX-27 can. Single-event causal proof.

## Fix shipped

- `mxfs_fix27_shared_admit` default **1** (was 0). sess24 shipped it off because
  it "never engaged" under a healthy workload — correct measurement, wrong
  question: those 4380 blocks are stat/cat/md5sum, which MUST keep waiting.
  Not firing under health is what a rare-cycle deadlock breaker looks like.
- `wake_up_all(&ip->i_dlm_wait)` before the site-2 flush, so a submitter that
  parked earlier (P47 showed `state=4 ACQUIRING g2=0`, when the admit had to
  refuse) re-evaluates immediately instead of after up to 3 s.
  **This alone does NOT fix it** — arm 0 on the build that contains it still
  wedged (17 hazards). Attribution stays with fix27.

## Safety argument (structural, not just reasoning)

The admit sets `i_dlm_mode = EX` when the mirror is EX, and the release
pipeline's pre-unlock check treats `i_dlm_mode != MXFS_LOCK_NL` as `stranded`
and SKIPS the wire unlock — so an admitted submitter cannot have the grant
released out from under it. The anchored release path is protected by its own
gen-anchored unlock returning -ESTALE.

## Regression at 2/caw, all PASS

cache_coherency 534 checks, strong_consistency, posix_multi, mmap_coherency,
zero_silent_loss, rsync_paired, crash_consistency, dir_reuse_coherency 156,
fence_during_write, dirent_durability (30 rounds, durable_loss=0),
dirent_type_integrity, dirent_publish_integrity, kernel_health hits=0,
dlm_fairness, dlm_membership, fault_netpartition, soak, node_responsive.
