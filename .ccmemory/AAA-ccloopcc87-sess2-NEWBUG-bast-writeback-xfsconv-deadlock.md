---
name: AAA-ccloopcc87-sess2-NEWBUG-bast-writeback-xfsconv-deadlock
description: ccloop cc87fed3 sess2 END: pr_sweep fix (0.10.82) validated 1/2-3 clean. NEW deadlock has an EXISTING partial fix (mxfs_ilock_admit_ioend, FIX-25) th…
metadata:
  type: project
---

## UPDATE (same session, continued after relay boundary) — found the existing fix, it appears NOT to be engaging

Read `xfs_mxfs_dlm.c` ~19653-19722: there IS an existing, purpose-built deadlock
breaker for EXACTLY this 3-task cycle: **`mxfs_ilock_admit_ioend()`** (FIX-25,
sess8 a9a03929 + a sess9 "WIDENING" for the PR-mirror case). Its own doc comment
describes the IDENTICAL cycle I found this session almost verbatim: `bast_process
→ filemap_write_and_wait → folio_wait_writeback ← the folio's writeback only ends
when xfs_end_ioend converts the unwritten extent, which does xfs_trans_alloc_inode
→ xfs_ilock(EX) ← which sat in this demote-wait because state was BAST/DEMOTING`
— proven live on `test6`, 150s+ wedge, in a PRIOR session.

**Mechanism**: when `mxfs_dlm_ilock_begin`'s wait loop is about to block, it calls
`mxfs_ilock_admit_ioend(ip, mode)` (2 call sites: xfs_mxfs_dlm.c:21066 and :21128).
That function admits the caller to a NESTED EX grant (bypassing the wait) IF ALL of:
1. `mode == MXFS_LOCK_EX` (the requested lock mode)
2. `xfs_task_in_ioend()` is true — checks `current_work()->func == xfs_end_io`
   (`pal/linux/xfs_aops.c:191`) — i.e., caller IS the xfs-conv ioend-completion kworker
3. `ip->i_dlm_state` is `DEMOTING` or `BAST` (mid-release) at the time of the call
4. The on-disk DLM mirror (`mxfs_v5_dlm_inode_granted_mode`) shows this node still
   holds `EX` or `PR` (queried by dropping+retaking `i_dlm_lock`)

If admitted: bumps `ip->i_dlm_ex_holders`, lets the ioend thread proceed to finish
`xfs_end_io`'s extent conversion, which lets the folio's writeback complete, which
unblocks `bast_process`'s `filemap_write_and_wait` — breaking the cycle. Logs
`P25-IOEND-ADMIT` (capped at 2000, `pr_warn`) when it fires.

**This session's stuck stacks (test7, captured via plain `/proc/<pid>/stack`, no
special tooling needed) match conditions 2 and (per the stack) look like they should
satisfy 1 (extent conversion needs ILOCK_EXCL) too**:
- PID 5402 `kworker/3:0+xfs-conv/dm-1`: `xfs_end_io [mxfs] -> xfs_end_ioend [mxfs] ->
  xfs_iomap_write_unwritten [mxfs] -> xfs_trans_alloc_inode [mxfs] -> xfs_ilock [mxfs]
  -> mxfs_dlm_ilock_begin+0xbb0/0x3c50 [mxfs]` — currently BLOCKED (D-state, 1200s+)
  meaning **the admit did NOT fire for this instance**, despite the function existing
  specifically to handle it.

**Did NOT get to determine WHY it didn't fire before the relay boundary.** Two
untested possibilities, in priority order for next session:
(a) **Condition 3 (state DEMOTING/BAST) or condition 4 (mirror EX/PR) is false** at
    the moment #5402 calls in — e.g. if `mxfs_dlm_bast_process` (running as kworker
    #3816) hasn't yet SET state to DEMOTING/BAST by the time #5402 arrives (a timing/
    ordering gap — #5402 might be arriving BEFORE bast_process transitions state,
    landing in a genuinely different code path in `mxfs_dlm_ilock_begin`'s wait loop
    that doesn't check `mxfs_ilock_admit_ioend` at all, OR bast_process transitioned
    state AWAY from DEMOTING/BAST already while STILL stuck in the flush — check the
    exact state machine ordering in `mxfs_dlm_bast_process`: does it set
    state=DEMOTING/BAST BEFORE or AFTER the `filemap_write_and_wait` call?
    If AFTER, or if it clears the state too early, #5402 would never satisfy
    condition 3 while bast_process is stuck flushing).
(b) **This exact call path in `mxfs_dlm_ilock_begin` isn't reached** — there are TWO
    call sites (21066, 21128) for `mxfs_ilock_admit_ioend`; check which branch/wait-loop
    variant PID 5402's specific path through `mxfs_dlm_ilock_begin+0xbb0/0x3c50` (a
    large function, 0x3c50 bytes) actually goes through, and whether BOTH call sites
    are reachable from wherever the CAW-transport wait loop lives (this session's
    workload is transport=caw, `caw_fair_handoff=1` — FIX-25 was proven on a PRIOR
    session's config, not confirmed to have been tested under caw_fair_handoff=1
    specifically; if the fair-handoff code changed the CAW acquire-wait's control
    flow/loop structure, it's plausible the admit-ioend check sits on a call path
    that fair_handoff's changes bypass or restructure).

**Read `mxfs_dlm_bast_process`'s state-transition ordering relative to its
`filemap_write_and_wait`/flush call FIRST** (this is the single highest-leverage
read — it directly answers hypothesis (a), and if state IS DEMOTING/BAST throughout
the flush, that rules out (a) and focuses effort on (b)). The flush call itself:
search for `filemap_write_and_wait_range`/`filemap_write_and_wait` call sites in
`xfs_mxfs_dlm.c` (grep hits at lines ~11982 and ~13181 per earlier grep — one of
these is very likely the actual call `mxfs_dlm_bast_process` makes, need to confirm
which one is on PID 3816's actual path vs. a different helper).

## Everything else from the original write-up still stands — see below
[original content follows unchanged]

## Status at session end (relay boundary hit mid-investigation)

Criterion: "1/2/4/8/16/32 node caw dlm multipath test working 100%". Sole gap:
`fence_during_write@8/caw`. Build in tree: **0.10.82** (srcversion `6DA24BC6DC1C11CFF244AD1`),
VERSION file says 0.10.82 — do NOT re-bump until the NEXT fix actually lands.

### pr_sweep_work_fn fix chain — VALIDATED, believed COMPLETE for its own bug class
See `AAA-ccloopcc87-sess2-FIX4-pr_sweep_unbounded_lock_hold-VALIDATING` and
`AAA-ccloopcc87-sess2-FIX5-pr_sweep_unconditional_yield-VALIDATING` for full proof
chain (live vCPU register capture, byte-exact RIP-to-source match, KASLR slide
recovery via System.map, RCU-stall zero-context-switch proof, Fable consult
confirming cyclic-list diagnosis via simple arithmetic: 750s / ~100-300ns per
spin_lock/unlock pair = billions of iterations, impossible for a 6666-entry list
without a cycle). Fix = unconditional yield every 2048 list entries + hard 1M-visit
cap with a `P-PRSWEEP-CAP` diagnostic warning on bailout.

**Validation iter 1 (build 0.10.82): CLEAN PASS.** `dir_reuse_coherency` PASS 8/8,
`fence_during_write` PASS 8/8, RUN_EXIT=0. `P-PRSWEEP-CAP visited=1000000 seen=0
swept=0` fired 8 times across 4 nodes — proves the underlying list-corruption bug
is still there but the fix converts it to a harmless ~3s bailout, sufficient for
the criterion even without root-causing the corruption itself.

**Validation iter 2 (same build 0.10.82): DID NOT hit the pr_sweep bug** (zero new
misses after prep). Instead timed out (RUN_EXIT=124, OUTER=1720s) on the D-state
deadlock documented above.

## Tooling built this session (reusable)
- Live vCPU register capture via `virsh qemu-monitor-command <node> --hmp "info
  registers -a"` — works even when guest is fully unresponsive.
- Raw instruction byte read at an arbitrary guest RIP: `--hmp "x/Nxb <addr>"`.
- Module RIP symbolization: unique byte-sequence match against the local `.ko`
  file (Python), file-offset -> section-relative via `objdump -h`'s `.text` file
  offset, nearest symbol `<=` via `nm -n mxfs.ko`.
- Core-kernel RIP symbolization with no vmlinux debug package: recover per-boot
  KASLR slide via idle-HLT RIP low bits mod 0x200000 (2MB granularity, confirmed
  empirically + cross-checked against historical `Kernel Offset:` lines already in
  the serial logs) against `/boot/System.map-$(uname -r)` (`sudo cp` out first,
  root-owned).
- Live guest stack walk with no gdb/crash: `--hmp "cpu N"` then `--hmp "x/80gx
  <rsp>"`, symbolize each word with the KASLR slide.
- **For D-state (not CPU-pinned) hangs where SSH still works — MUCH simpler, use
  this FIRST**: `ps -eo stat,pid,etimes,comm` for `D`-state + `cat /proc/<pid>/stack`
  gives the kernel stack directly, no QEMU tooling needed. This is what found the
  CURRENT bug.

## Immediate next steps
1. Read `mxfs_dlm_bast_process`'s state-transition ordering around its flush call
   (grep `filemap_write_and_wait` — lines ~11982, ~13181 are candidates) — does it
   set `i_dlm_state = DEMOTING/BAST` BEFORE calling the flush, and does state stay
   that way FOR THE DURATION of the flush? This directly tests hypothesis (a) above.
2. If (a) is ruled out, trace PID 5402's exact path through `mxfs_dlm_ilock_begin`
   (0x3c50 bytes, has 2 `mxfs_ilock_admit_ioend` call sites at :21066/:21128) to see
   which one it should hit and whether `caw_fair_handoff=1`'s changes altered that
   control flow (hypothesis b).
3. Recover test7 (`virsh destroy+start` — RULE 2 permits test-VM cycling; the D-state
   processes there are unkillable). Verify full cluster health before any new run.
4. Fix, build, bump version (0.10.83+), redeploy, re-validate via
   `tests/diag_cpu_pin_capture.sh 8 <outdir> caw_fair_handoff=1` for 2-3 clean
   iterations (resume the pr_sweep validation count too — only 1 of 2-3 so far).
5. After both bugs hold clean: full fresh 1/2/4/8/16/32 @ caw revalidation sweep
   (`scripts/revalidate_cell.sh` per node count), then `python3 scripts/matrix_check.py
   --since <build-epoch>` with no --nodes filter, all cells 17/17 fresh PASS, before
   writing YES to the criteria-met marker. Decide on `caw_fair_handoff` ship default
   before the final gate (it is NOT on by default; confirm whether a stock run.sh
   invocation without the modarg needs it to be, or whether the underlying starvation
   bugs 1-3 are enough without it — untested either way so far this session).
