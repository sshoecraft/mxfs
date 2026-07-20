---
name: ccloop3e02-sess1-THRESHOLD-FIX-DONE-plus-REAL-wedge2a-residual-live-repro
description: sess1(3e02e7dd): harness false-positive threshold FIXED+VALIDATED (2/4/8/16 full 24rd PASS). N=32 hit REAL xfs_buf_iowait wedge2a residual, live repr…
metadata:
  type: project
---

## Criteria: "get 1/2/4/8/16/32 node caw dlm multipath test working 100%" (ccloop run 3e02e7dd)

### PART 1 — DONE, VALIDATED, KEEP: harness false-positive fix

**Original criteria.json gap**: `dir_reuse_coherency@32/caw` FAIL, `nodes_pass=0/32
states:ABORTED_BY_PEER=31,SYSCALL_HANG=1`. Root-caused via RULE-4 (measured, not
guessed): the `run_bounded` hang-watchdog added TODAY (2026-07-11, the "Harness
failure-state protocol") wraps rank1's mkdir/rm-rf in a flat 20s timeout. Proved
via nanosecond `realns` fields in captured dmesg that the "hung" rm PID kept
making forward progress 9+ seconds past the declared hang — it was NOT stuck,
just legitimately slow (O(N) CAW coherence cost). Confirmed by live measurement
at N=32 (build 1BAFC14435BA2FFEBEF0742): create 15-28s, verify 42-48s, **rm
32-38s** — already exceeding the 20s threshold, and even at N=8 historical data
(run.sh's own case-arm comment) showed rm~21s, already over 20s. One false
"hang" on rank1 cascades via `coord_signal_abort` to ALL 31 peers reporting
ABORTED_BY_PEER = nodes_pass=0/32 (NOT 31 independent failures — one thing
tripped, protocol working as designed, just the threshold was wrong).

**Fix applied** (both files, syntax-checked, NOT yet committed to git — user
controls git per CLAUDE.md):
- `tests/suite/dir_reuse_coherency.sh`: `DRC_HANG_THRESHOLD_S` now
  `max(20, 10*T)` where T=$NODES (was flat 20).
- `run.sh`'s `run_coord()`: added `ct` local (was using global `$COORD_TIMEOUT`
  directly), set to `max(150, 12*N)` for `dir_reuse_coherency` in the existing
  per-test case-arm (same place `tt`/TEST_TIMEOUT already gets special-cased),
  used instead of `$COORD_TIMEOUT` when building the remote ssh env-var string.
  Margin: ct always ≥40-70s above the threshold formula at every N tested.

**Validated with FULL 24-round runs (not just the 2-round diagnostic)**:
N=2 PASS(2/2), N=4 PASS(4/4), N=8 PASS(8/8), N=16 PASS(16/16) — all under the
NEW harness code (their prior criteria.json PASS records predated today's
run_bounded change entirely and had never been exercised against it before
this session). **N=32 full-24-round validation is what's IN PROGRESS** when
this session hit the relay boundary — see Part 2, it hit a REAL bug instead.

**IMPORTANT PROCESS LESSON for whoever continues**: launching a long test via
`nohup ... & ` then waiting with a SINGLE foreground Bash call that has its OWN
`timeout` parameter set close to or above ~9-10 min IS UNSAFE — when the tool's
own external timeout fires, it kills the WHOLE process group including the
nohup'd child (confirmed: this happened once, killed a live N=8 run, produced a
spurious `"status":"FAIL","measured":"aborted","reason":"run aborted before
this test recorded (wedge/timeout/kill)"` entry in criteria.json — had to
relaunch). Safe pattern: launch with `nohup env ... > log 2>&1 & disown` in a
quick command (returns instantly), THEN wait using a SELF-bounded loop like
`end=$((SECONDS+540)); while kill -0 $PID 2>/dev/null && [ $SECONDS -lt $end ];
do sleep 5; done` with NO external `timeout` param anywhere near that duration
(or one comfortably longer than the internal bound) — the shell returns
CLEANLY on its own before any external kill mechanism could fire, so repeated
calls of this pattern is how to wait out a 20-45 minute test safely. The Stop
hook in this harness also actively blocks ending a turn while a background
task is tracked as running ("Wait. Background command still running.") — use
the self-bounded foreground loop, not `ScheduleWakeup`+yield, to satisfy it.
(Also: `ScheduleWakeup` with `stop:true` CANCELS the dynamic loop entirely —
do not pass `stop:true` unless truly done; I fat-fingered this twice.)

### PART 2 — IN PROGRESS: a REAL kernel bug, live-reproduced, NOT a false positive

While running N=32 full-24-round validation, **test1 (rank1) silently
self-rebooted mid-test** (confirmed via `uptime`/dmesg SCSI-reenum timestamp,
NOT triggered by me, NOT a libvirt-level destroy — libvirt's own domain
lifecycle log shows no destroy/start event near that time, so this was an
IN-GUEST reboot, cause unconfirmed — evidence was wiped because journald here
runs on VOLATILE/RuntimeMaxUse storage per run.sh's own prep_cluster(), so the
immediately-prior boot's log is gone). Killed the wedged run (external
`timeout` mistake, see above), set up a **continuous `dmesg -Tw` stream to a
local file BEFORE relaunching** (critical — this is what let me catch the next
one), relaunched N=32 attempt 2.

**Confirmed LIVE, genuine, sustained D-state hang** (NOT a false positive this
time — directly checked `ps -p PID -o stat,wchan`, D-state on `xfs_buf_iowait`,
climbing continuously, 877s+ and counting when this session ended):

```
xfs_buf_iowait+0x68/0x320 [mxfs]
xfs_bwrite+0x33/0x80 [mxfs]
mxfs_dir_data_owner_scan+0x39d/0x530 [mxfs]
mxfs_dir_flush_data_blocks+0xa5/0x1f0 [mxfs]
mxfs_dlm_dir_durable_signal+0x136/0x1e0 [mxfs]
xfs_remove+0x416/0x4f0 [mxfs]
xfs_vn_unlink+0x53/0xb0 [mxfs]
vfs_unlink → do_unlinkat → __x64_sys_unlinkat
```
(clean single-shot `cat /proc/$pid/stack > file` capture — avoids the known
kmsg line-interleaving corruption that garbled earlier sessions' captures;
USE THIS METHOD, not line-by-line `/dev/kmsg` echoes, for any future stack
dump.) This is **THE SAME bug family as "wedge#2a"** that ccloopa864 sessions
5-8 investigated extensively (see those memories: `AAA-ccloopa864-sess5-WEDGE2-FRESH-bmbt-inflight0-lostwakeup`,
`sess6-ROOT-wedge2a-async-completion-routing`, `sess6-END-wedge2a-FIXED...`,
`sess8-END-CRCfix-WORKS-wedge2-fix-built`) — sess6 claimed ROOT PROVEN + FIXED
(the `b_mxfs_sync_wait`/`b_mxfs_force_sync` latch in `pal/linux/xfs_buf.c`,
currently at ~line 5840: `bp->b_mxfs_sync_wait = bp->b_mxfs_force_sync ||
!(bp->b_flags & XBF_ASYNC);`), sess8 found a RESIDUAL variant and built
v0.10.58's force_sync latch (also already in current tree, build
1BAFC14435BA2FFEBEF0742/VERSION 0.10.61) — **but I've now proven THIS specific
build still has a live, reproducible residual wedge**, via the decoded event
ring (`scripts/decode_bufev.py` — already exists, use it, don't
hand-decode hex).

### ROOT MECHANISM — proven via decoded event ring, NOT yet fixed

Decoded ring for the stuck buffer (daddr=8373016, a dir3_data block of ino=131,
the shared test directory) showed, in order:
```
SUBMIT pid=2575(rm)          sw=1 fs=1   <- rm's sync xfs_bwrite, correctly latched
SUBMIT pid=1556(xfsaild/dm-1) sw=0 fs=0  <- xfsaild's CONCURRENT async delwri submit
                                            on the SAME buffer OVERWRITES sync_wait
                                            0<-1 (line ~5840 is an UNCONDITIONAL
                                            overwrite on every xfs_buf_submit call,
                                            not gated by "is a sync wait already
                                            pending")
BIO pid=2575, BIO pid=1556    <- both bios dispatched
BIOEND(pid=0), WORKER(pid=1388)  flags=WRITE|ASYNC        <- 1st completion
BIOEND(pid=0), WORKER(pid=1284)  flags=ASYNC|DONE          <- 2nd completion
```
NO `IOWAIT` (type 9) event ever appears — `complete(&bp->b_iowait)` was never
called for rm's own bio. Live buffer state confirmed `sync_wait=0` (already
clobbered) at the time of the P-IOWAIT-STUCK dump. **Both completions route
through the ASYNC/`xfs_buf_ioend_work`/`xfs_buf_relse` path** (pal/linux/xfs_buf.c
~2027-2032 for `xfs_buf_ioend`, ~2194-2198 for `xfs_buf_bio_end_io`) because by
the time EITHER completion runs, `bp->b_mxfs_sync_wait` already reads 0
(clobbered by xfsaild's LATER submit, which ran before either completion in
this specific interleaving).

**This means xfsaild (pid 1556, `xfsaild/dm-1` — the standard upstream AIL
pusher kthread) is submitting the SAME xfs_buf object concurrently/overlapping
with `mxfs_dir_data_owner_scan`'s own synchronous `xfs_bwrite` on it.** Likely
mechanism (not 100% proven, but consistent with all evidence): owner_scan's
first pass (RCU-walk, non-sleeping) only bumps a refcount
(`spin_lock(&bp->b_lock); bp->b_hold++; spin_unlock`) — it does NOT take the
real buffer lock (`xfs_buf_lock`, a sleeping semaphore) until a SECOND,
separate pass. In the window between those two passes, xfsaild can
legitimately (via its own trylock) grab the buffer, dispatch an async write,
and — critically — apparently release the lock before that bio completes
(standard for async submission), letting owner_scan's second-pass
`xfs_buf_lock()` succeed and dispatch ITS OWN (sync) write WHILE xfsaild's
earlier bio is still in flight. Two overlapping bios, one shared
completion-routing flag → the clobber.

### Also found: this is likely NOT JUST a hang — probable double-relse/UAF risk

Traced the reference-counting implications: `xfs_buf_ioend_work` (the async
path both misrouted completions take) unconditionally calls `xfs_buf_relse(bp)`
after `__xfs_buf_ioend(bp)` returns true (which it always does barring an I/O
error — confirmed by reading the function body, no multi-bio
remaining-count gate found in this fork's `__xfs_buf_ioend`). So BOTH
completions call `xfs_buf_relse()` — xfsaild's own (correct, releases its own
ref) AND rm's misrouted one (WRONG — releases a ref belonging to
`mxfs_dir_data_owner_scan`'s `held[]` array, which will ALSO call
`xfs_buf_relse(bp)` itself once `xfs_bwrite` finally returns). **This means
even completely independent of the hang, there is likely a live reference-count
UAF-class bug** — plausibly explains the FIRST test1 crash/reboot (before
dmesg streaming was set up) as a consequence of this same race, not a separate
issue. Do NOT add a naive "just escape xfs_buf_iowait's wait loop after N
retries and proceed" fix (which sess8's memory already flagged as risky,
"beware double-relse") without ALSO fixing this — it would let owner_scan's
caller-side `xfs_buf_relse()` fire a SECOND time on an already-decremented
ref, making the corruption worse, not better.

### Candidate fixes considered, both have real correctness risks (not yet applied):
1. Escape hatch in `xfs_buf_iowait`'s retry loop (proceed if `ioend_seen>0` +
   `XBF_DONE` after bounded retries) — **UNSAFE ALONE** per the double-relse
   finding above; would need pairing with a refcount fix.
2. Make `b_mxfs_sync_wait` "sticky" (don't let a later submit clobber it to 0)
   — trades the hang for a DIFFERENT bug: xfsaild's own (unrelated) bio
   completion would then incorrectly trigger the override (`complete()` +
   early return WITHOUT calling relse — both override branches at
   xfs_buf.c ~2016-2025 and ~2182-2191 `return` before reaching the relse
   code), causing (a) owner_scan's sync wait to be satisfied PREMATURELY
   (before its OWN write actually lands — a durability/correctness bug, not
   just a perf one) AND (b) xfsaild's own reference to LEAK (never relse'd).

**Neither is safe as a quick patch. This needs either: (a) a real per-submission
(not per-buffer) way to correlate a completion with its OWN submitter's
sync-intent, or (b) closing the locking gap so xfsaild cannot start an
overlapping submission while owner_scan's flush is in flight for the same
buffer.** This is genuinely architectural, not a "where's the bug" question —
I have full instrumented proof of the mechanism (stack, ring, refcount
consequences) and have identified concrete flaws in two distinct fix
approaches. **This meets the project's own RULE 5 bar for a Fable consult**
(CLAUDE.md: complete proven diagnosis + genuinely exhausted own distinct fix
ideas + architectural, not "where's the bug") — next session should consider
`mcp__ask_fable__query` with this full mechanism write-up if its own further
analysis doesn't turn up a clean answer first. Do not re-derive the above from
scratch — it's already fully proven.

### Live state when this session ended (relay boundary, NOT a stopping point I chose):
- `test1` is up, N=32 attempt-2 run.sh (pid varies, was 1685769) may still be
  running or may have hit the outer 4480s (140*32) test timeout / another
  crash by the time the next session picks up — CHECK FIRST rather than
  assume.
- Continuous dmesg stream from test1 was running at
  `/tmp/claude-1000/-src-mxfs/7fbd6785-e4e0-4d78-aa03-fc4146a7e990/scratchpad/test1_dmesg_stream.log`
  — that scratchpad dir is THIS session's, may not persist/be visible to a
  fresh session's own scratchpad path; if picking this up, start a FRESH
  stream (same one-liner, cheap) rather than assuming the old file exists:
  `nohup tools/mxfs_sshpass.sh test1 /tmp/.mxfs_pass "dmesg -Tw" > FILE 2>&1 &
  disown`.
- `scripts/decode_bufev.py` — USE THIS for any `ev=[...]` ring hex, don't
  hand-decode.
- Precond_xinit_coherency (empty runs in criteria.json) has NO backing test
  script (`find tests -iname "*xinit*"` → nothing) — confirmed NOT a blocker,
  `run.sh`'s own applicability check skips tests without a script.
- Fix files touched, NOT committed (git is user-controlled per CLAUDE.md):
  `tests/suite/dir_reuse_coherency.sh`, `run.sh`. Both `bash -n` clean.

### NEXT STEPS for whoever continues:
1. Check current cluster/test state first (don't assume anything survived).
2. Decide: keep chasing the root fix (locking-gap closure or per-submission
   completion correlation) vs. Fable consult now (bar is met, see above).
3. Once the wedge2a-residual is genuinely fixed (not just threshold-masked),
   re-run N=32 full 24 rounds (and probably 16 too, to make sure the same
   race doesn't lurk there just less frequently) to reconfirm 100%.
4. Only THEN write YES to
   `/src/mxfs/.ccloop/runs/3e02e7dd-de32-4f91-a7c5-61eddb630e4a/criteria-met`
   — do NOT write YES based on the threshold fix alone; the criteria is NOT
   met yet, a real kernel bug is live and reproducible at N=32.
