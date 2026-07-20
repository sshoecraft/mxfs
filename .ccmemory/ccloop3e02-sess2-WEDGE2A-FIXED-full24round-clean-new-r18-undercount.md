---
name: ccloop3e02-sess2-WEDGE2A-FIXED-full24round-clean-new-r18-undercount
description: sess2(3e02e7dd): wedge#2a lost-wakeup FIXED+PROVEN (full 24rd 32/caw run, 0 hangs). NEW: r18 readdir undercount (exp=3200 got=3199, ALL 32 nodes).
metadata:
  type: project
---

## CRITERIA: "get 1/2/4/8/16/32 node caw dlm multipath test working 100%" (run 3e02e7dd)

### PART 1 — ROOT FIX PROVEN AND SHIPPED: wedge#2a (lost b_iowait wakeup)

**Root cause** (proven via LIVE /proc/kcore inspection, not guesswork): the stuck
buffer's `b_sema.count` read **83** instead of the correct 0/1 on the live-wedged
repro (daddr=8373016, ino=131's shared test dir). The sess6/8/9 fixes all patched
*which branch* a completion takes (`b_mxfs_sync_wait`, a single overwritable
per-buffer bool), but none fixed that the routing lets an unrelated concurrent
submitter (xfsaild's async delwri racing `mxfs_dir_data_owner_scan`'s synchronous
durable flush on the SAME `xfs_buf`) overwrite the flag between the sync
submitter's snapshot and its own completion. Once that happens, BOTH completions
take the async/relse branch → a double `xfs_buf_relse()` → the very b_sema leak
that lets the NEXT occurrence race even more easily (self-reinforcing — explains
why this was "residual"/non-deterministic across ~9 prior sessions' fix attempts
in ccloopa864).

**How I got the proof**: computed `struct xfs_buf` field offsets via `gdb` against
the deployed `mxfs.ko`'s DWARF debug info (`gdb -batch -ex 'print (long)&((struct
xfs_buf*)0)->b_sema' mxfs.ko`, etc — no source changes needed), wrote a small
`/proc/kcore` ELF-segment reader (`/tmp/claude-*/scratchpad/kcore_read_xfsbuf.py`,
not committed — recreate from this description if needed: parse kcore's PT_LOAD
program headers for vaddr->file_offset, then pread the target struct's bytes),
and read the live stuck buffer's `b_sema.count`, `b_flags`, `b_lock_ip`, event
ring etc. directly out of the running kernel on test1 — confirmed b_sema.count=83.

**Fix** (pal/linux/xfs_buf.c + xfs/xfs_buf.h, build srcversion 8939B8AF106B3160C309E13,
VERSION 0.10.61 — bump the patch version on next edit if continuing 0.10.x):
- Replaced `bool b_mxfs_sync_wait` with `atomic_t b_mxfs_sync_waiters` — an
  ADDITIVE credit incremented once per genuinely-synchronous `xfs_buf_submit`
  (in the new `xfs_buf_submit_ex(bp, fresh)`, `fresh=true` from the public
  `xfs_buf_submit()` wrapper), consumed by exactly one completion event via
  `mxfs_buf_completion_wake_sync()` (`atomic_add_unless(&waiters, -1, 0)` then
  `complete()`). A completion that finds no credit falls back to the pre-existing
  flags-based (XBF_ASYNC) relse/complete decision — normal single-submitter path
  unchanged.
- Updated both completion routers (`xfs_buf_ioend`, `xfs_buf_bio_end_io`) to use
  the helper; the P-SYNCWAIT-OVERRIDE diagnostic print now only fires when the
  live XBF_ASYNC flag is ALSO set (i.e. only logs when the race actually
  happened, since consuming the credit is now the NORMAL path, not exceptional).
- Fixed a SECOND, related bug in `xfs_buf_ioend_handle_error`'s "permanent
  error" branch: it called `xfs_buf_relse()` UNCONDITIONALLY, which would also
  double-relse out from under a pending sync waiter on ANY repeated I/O error
  (independent of the 2-submitter race) — now routes through the same helper.
- The `handle_error` RESUBMIT branch must NOT register a second credit (the
  original submission's credit is still outstanding, since the error path
  bypasses normal completion routing entirely) — it calls the new
  `xfs_buf_submit_ex(bp, false)` (fresh=false) instead of `xfs_buf_submit()`.
- `xfs_buf_submit()` is now a thin wrapper: `xfs_buf_submit_ex(bp, true)`. All 7
  other call sites (`_xfs_buf_read`, `xfs_buf_readahead_map`,
  `xfs_buf_read_uncached`, `xfs_buf_delwri_submit{,_nowait,_nopinwait}`)
  go through the wrapper unchanged.
- `mxfs_buf_ev()` ring packing bit 43 now sources from
  `atomic_read(&b_mxfs_sync_waiters) != 0` (same wire format, decode_bufev.py
  needs no changes). P-IOWAIT-STUCK print field renamed `sync_wait=` ->
  `sync_waiters=` (now prints the live counter value, not a bool).

**Validation**: full 32-node/caw `dir_reuse_coherency` run, 24/24 rounds, `grep -c
P-IOWAIT-STUCK` = 0, `has been shut down` = 0, `EFSCORRUPTED` = 0, `BUG:` = 0
across the ENTIRE run (one unrelated, pre-existing, one-off `WARNING: ...
xfs_assert_ilocked` at rwsem.h:85 during `xfs_iread_extents` fired ONCE — NOT
correlated with this fix, different code path entirely, did not recur, treated
as pre-existing noise not yet root-caused). This is the FURTHEST any session in
this entire multi-week investigation has gotten — every prior attempt wedged by
r7-r14 at the latest. **KEEP THIS FIX — do not revert any part of it.**

### PART 2 — NOT YET FIXED: new failure surfaced at r18 (readdir undercount)

The same run's FINAL verdict: `FAIL nodes_pass=0/32 states:FAIL=32`, reason:
`test1:FAIL:drc r18 r1 readdir count(exp=3200 got=3199)` — and EVERY node
(test1..test32, sampled test1-8 in the truncated criteria.json reason string)
reports the IDENTICAL `exp=3200 got=3199` at round 18. This is NOT a hang (test
ran cleanly through all 24 rounds, wedge#2a did not fire) and NOT a per-node
COHERENCY divergence (all nodes agree on the same, lower count) — it looks like
a genuine missing/lost dirent: one create's directory entry did not durably
land (or got reverted) during round 18's create phase, and every node's readdir
of the shared, durable, post-round state correctly (consistently) sees only
3199.

This is almost certainly a bug that was PREVIOUSLY MASKED by wedge#2a always
hanging the test before round 18 could ever be reached in ANY prior session —
i.e. the "whack-a-mole" pattern GPT-5.6's architectural review warned about
(see `gpt-consult-dir_reuse32-architectural-review`): fixing one layer's bug
exposes the next layer down. Do NOT be discouraged that criteria are still not
met — wedge#2a was THE blocker for weeks; this is new, different, and shallower
in the stack (a lost-write/count bug, not a lock/completion-routing hang).

**NOT YET INVESTIGATED THIS SESSION** (ran out of turn before diagnosing) — next
steps for whoever continues:
1. Pull test1's (and a couple of peers') full dmesg around round 18's CREATE
   phase (timestamp correlate via `DRCph r=18 rank=1 PHASE=create-start` /
   `create-done` markers) — look for P-COUNTREGRESS, P-WRCNT-*, P-DIRWR,
   ENOSPC/EEXIST/error returns from the create syscall itself, or any
   create-side retry/skip logic that might silently drop one file.
2. Check `tests/suite/dir_reuse_coherency.sh` for exactly what "3200" means
   (likely files-per-round × nodes, e.g. 100×32) and how the create phase
   detects/handles a failed create (does it retry? does a failure get counted
   as "created" optimistically before confirming?).
2b. Given ALL nodes see the SAME undercount (not divergent), check whether
   this could be the SB summary-counter drift mechanism flagged in
   `sb-counter-recheck-2026-07-11-live-drift-confirmed` / GPT's consult (a
   wrong in-core free/inode view driving a bad allocation decision that's
   durably wrong) rather than a pure lost-write.
3. Full dmesg from this run is at
   `/tmp/claude-1000/-src-mxfs/02011108-e4b0-4018-ab43-aa114400c57f/scratchpad/test1_dmesg_run32fix.log`
   (this session's scratchpad — may not survive to a fresh session; if gone,
   re-run is cheap now that wedge#2a doesn't block it, ~55min for 24 rounds).
   run.sh's own log: `.../scratchpad/run32_wedge2a_fix.log`. criteria.json
   already has the FAIL recorded with the r18 reason string (full, untruncated
   version needs `jq` on the live file, this note only quotes the first ~8
   nodes' worth).
4. Once r18 undercount is root-caused+fixed, re-run N=32/caw fresh (full clean
   mkfs) for at least 2-3 consecutive clean 24-round passes before considering
   32/caw settled (project convention), THEN re-verify N=1/2/4/8/16/caw (and
   maybe /tcp) still pass since core xfs_buf completion-routing changed — those
   were last validated by ccloop3e02-sess1 under the corrected harness
   thresholds, but that was BEFORE this session's xfs_buf.c changes.
5. Only then write YES to
   `/src/mxfs/.ccloop/runs/3e02e7dd-de32-4f91-a7c5-61eddb630e4a/criteria-met`.

### Process notes
- Cluster prep (`run.sh`'s `prep_cluster`) auto-detects nodes with a stale/dirty
  mxfs mount from a prior ungraceful session end and power-cycles them
  automatically (virsh destroy+start) — do NOT manually pre-clean every node;
  just power-cycle any node with a KNOWN unkillable D-state (this session did
  test1 for the wedged rm) and launch `run.sh`, it handles the rest, including
  verifying the loaded srcversion matches the freshly-built local `mxfs.ko` on
  every node before proceeding (PREP FAIL if mismatched).
- `/src/mxfs` is NFS-shared to all test nodes from the dev host — a rebuilt
  `mxfs.ko` is instantly visible cluster-wide, no manual scp/deploy needed.
- Safe long-test pattern (confirmed working this session): `nohup env
  MXFS_DEV=/dev/mapper/mpatha ./run.sh 32 caw dir_reuse_coherency > LOG 2>&1 &
  disown`, then poll with repeated foreground Bash calls each doing `end=$((SECONDS+480));
  while kill -0 $PID 2>/dev/null && [ $SECONDS -lt $end ]; do sleep 10; done`
  (NO external `timeout` wrapper near the total duration — it can kill the
  whole backgrounded process group).
