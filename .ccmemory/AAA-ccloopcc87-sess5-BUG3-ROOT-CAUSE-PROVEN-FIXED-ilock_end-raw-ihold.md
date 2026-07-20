---
name: AAA-ccloopcc87-sess5-BUG3-ROOT-CAUSE-PROVEN-FIXED-ilock_end-raw-ihold
description: sess5: BUG3 ROOT CAUSE PROVEN + FIXED — mxfs_dlm_ilock_end's idle_arm/need_flush branches + mxfs_inode_dlm_defer_bast used raw ihold() not igrab(), r…
metadata:
  type: project
---

## Status: ROOT CAUSE PROVEN, FIX APPLIED (build 0.10.85, srcversion 8B64C04FB45CAFCB9CC714A). Validation iterations in progress when this was written — CHECK VALIDATION OUTCOME FIRST if resuming.

## The proof (RULE 4 — direct evidence, not inference)

Live-captured BUG3 on the 2nd repro iteration this session (test2, dmesg -T -w
live streaming, `tests/diag_cpu_pin_capture.sh 8 <outdir>` +
`dir_reuse_coherency`+`fence_during_write`@8/caw). Full sequence, all on
ino=14682041 (0xe007b9), all within wall-clock second 23:44:58:

1. PID 49 (kworker/u9:2, running `mxfs_dlm_bast_work_fn` for ino=14682041)
   reaches its own `xfs_irele(ip)` → last reference → SYNCHRONOUS eviction
   cascade: `iput → evict → destroy_inode → xfs_fs_destroy_inode →
   xfs_inode_mark_reclaimable → xfs_inactive → xfs_attr_inactive`.
   `xfs_attr_inactive` takes its OWN nested ilock on the attr fork, then
   releases it via `xfs_iunlock → mxfs_dlm_ilock_end`. **Inside
   `mxfs_dlm_ilock_end.part.0+0x35f`, it calls raw `ihold(VFS_I(ip))`** to arm
   ANOTHER deferred release (idle_arm or need_flush branch). Since this exact
   inode is CURRENTLY mid-eviction (I_FREEING already set — that's why we're
   inside evict()/xfs_inactive() at all), i_count is 0. `ihold()` does NOT
   check I_FREEING (only `igrab()` does) — it blindly bumps 0→1, and its own
   `WARN_ON(atomic_inc_return(&i_count) < 2)` fires: `WARNING: ... at
   fs/inode.c:451 ihold+0x28/0x40`, RDI=ffff8ebbc4a95490. This "resurrects" a
   phantom reference and arms a NEW work item (`i_dlm_bast_dwork`) that will
   later independently release this SAME inode — even though the CURRENT
   eviction (already in flight, already past its point of no return) owns
   the real teardown and never asked for help.
2. Shortly after, PID 1585 (kworker/u10:11, `mxfs_dlm_bast_dwork_fn` — the
   JUST-ARMED phantom work item from step 1) calls `xfs_irele`→`iput()` on
   the SAME inode. This hits iput()'s own internal WARN (`fs/inode.c:1749`)
   — a second, genuinely-extra release cycle on an inode already being torn
   down by step 1's still-in-flight cascade.
3. **PID 9268 (comm=rm, the user's OWN concurrent, LEGITIMATE unlink of this
   SAME still-linked file)** calls `do_unlinkat`'s own protective
   `ihold(inode)` at `do_unlinkat+0x272` — same struct, **RDI=ffff8ebbc4a95490,
   IDENTICAL to step 1's RDI** (direct kernel pointer match — not inference).
   i_count is wrong again (from step 2's extra drop) so THIS ihold's WARN
   fires too, blindly bumping again. rm proceeds into `vfs_unlink →
   d_delete → dentry_unlink_inode → iput()` — and BY NOW i_state has
   I_FREEING/I_CLEAR fully set from step 1's cascade completing — so THIS
   iput() hits the hard `VFS_BUG_ON_INODE` (`kernel BUG at fs/inode.c:1798`,
   `iput+0x1c5/0x250`) — the actual crash. Same RBX/RDI=ffff8ebbc4a95490 at
   the crash site too.

**This is airtight**: 3 independent live kernel stack traces (PID 49, PID
9268's ihold-WARN, PID 9268's final BUG_ON) all reference the literal same
`struct inode *` address via the ihold/iput calling-convention register
(RDI first-arg, confirmed at the crash's RBX/RDI too) — not a theory, a
directly observed shared kernel object across 3 traces in the same second.

## Root cause, precisely

`mxfs_dlm_ilock_end()`'s `idle_arm` and `need_flush` branches
(xfs_mxfs_dlm.c, was ~22207-22274) AND `mxfs_inode_dlm_defer_bast()` (was
~28414-28484, called from need_flush's first attempt) all used raw
`ihold(VFS_I(ip))` to arm a deferred release — UNLIKE every other
"arm-a-deferred-release" call site in this file (`mxfs_dlm_ilock_begin`'s
sess60 EDEADLK-FREEING/ACQBAST-FREEING sites, `mxfs_dlm_bast_notify`,
`mxfs_dlm_sf_tenure_arm`), which all correctly use `igrab()` (atomically
checks I_FREEING/I_WILL_FREE under i_lock, returns NULL instead of blindly
incrementing) — SPECIFICALLY because of this exact hazard class (see the
sess60 comments already in the code, e.g. xfs_mxfs_dlm.c ~21501-21520).

`mxfs_dlm_ilock_end` is reached via `xfs_iunlock`, which fires constantly,
including RE-ENTRANTLY from within an inode's OWN synchronous eviction
cascade whenever `xfs_attr_inactive` (or any other inactivation step) takes
and releases its own nested ilock during teardown. At that exact moment,
i_count is legitimately 0 and I_FREEING is already set — a raw `ihold()`
there is unconditionally wrong. This bug is DISTINCT from (though same
general family as) the already-fixed `ccloop703f-sess1` bug (which was about
`mxfs_dlm_ilock_begin`'s wait-loop demoter exemption, already present and
correct in this tree — confirmed by direct code read at start of this
session, all 3 of its `i_dlm_demoter=NULL` placements are correctly AFTER
their trailing ref-drops). That fix protects RE-ACQUIRING a lock during
drain; this bug is about RAW-IHOLD when RE-ARMING a new deferred release
during the SAME drain — a different code path, different mechanism, same
root family (re-entrant BAST/eviction machinery not accounting for
"currently mid-teardown" state).

## The fix (build 0.10.85, srcversion 8B64C04FB45CAFCB9CC714A)

Three sites, all in xfs_mxfs_dlm.c, all: replace raw `ihold(VFS_I(ip))` +
unconditional proceed, with `igrab(VFS_I(ip))` + proceed-only-on-success +
`pr_warn_ratelimited` (`P134-ILEND-FREEING`, site=idle_arm|need_flush) on
refusal (diagnostic, no behavior change on the refusal path beyond correctly
NOT arming a phantom release):

1. `mxfs_dlm_ilock_end`'s `idle_arm` branch — `igrab()` instead of `ihold()`,
   `xfs_irele`→ unchanged on success path, P134 log + skip on refusal.
2. `mxfs_dlm_ilock_end`'s `need_flush` inline-fallback branch (after
   `mxfs_inode_dlm_defer_bast` returns false) — same pattern.
3. `mxfs_inode_dlm_defer_bast` — moved the `igrab()` check to the front
   (right after the P130 dup-diagnostic, before setting
   `i_dlm_demoter=current` — no point claiming demoter if we're about to
   bail), frees the just-allocated `pending` and returns false on refusal
   (letting the caller's need_flush fallback — also now igrab-gated — take
   over, which will itself correctly refuse for the same reason and log
   P134 once, attributing site=need_flush).

## Two earlier diagnostics from this session, still in the tree (harmless, not the cause but not yet removed)

- `P130-DEFERBAST-DUP` (mxfs_inode_dlm_defer_bast, tests a DIFFERENT theory:
  double-defer for the same ip within one tp). Did NOT fire in the captured
  crash's log (not checked exhaustively across the whole file, but not part
  of the proven mechanism above). Left in place — harmless, diagnostic-only,
  might still catch something in a future run. Safe to remove once BUG3 is
  fully validated closed, not urgent.
- `P133-DREVAL-DYING` (xfs_mxfs_dentry.c `mxfs_drevalidate`, tests a
  DIFFERENT theory: revalidate approving a dying cached inode by
  number-only match). Also not the mechanism proven above. Also left in
  place, also harmless, also safe to remove later.
- Both were reasonable hypotheses BEFORE the live capture nailed the actual
  mechanism; keeping them costs nothing and they might surface unrelated
  latent issues in later validation runs — do not spend time chasing them
  further unless they actually fire.

## Validation status — CHECK THIS FIRST IF RESUMING

Build 0.10.85 deployed to all 8 nodes (cluster_reset_n.sh 8, ALL_OK
srcversion=8B64C04FB45CAFCB9CC714A) immediately after this fix was written,
BEFORE any validation run against the fix started. BUG3's historical hit
rate is ~20-30% — per RULE 4, need MANY clean iterations (10+, not 2-3)
of the SAME full-combo repro (`dir_reuse_coherency` immediately followed by
`fence_during_write` in ONE cluster session — isolated fence_during_write
alone never reproduces it per sess3) before trusting this fix, using the
SAME live per-node `dmesg -T -w` streaming technique (the host serial
console log is loglevel-filtered and misses pr_warn diagnostics — SSH
`dmesg -T -w` does not).

Reusable repro command:
```
SP=<scratchpad>/bug3_validate_N
mkdir -p "$SP"
for n in 1 2 3 4 5 6 7 8; do
  nohup /src/mxfs/tools/mxfs_sshpass.sh test$n /tmp/.mxfs_pass "dmesg -T -w" > "$SP/live_test${n}.log" 2>&1 &
done
disown -a
cd /src/mxfs
nohup bash tests/diag_cpu_pin_capture.sh 8 "$SP" > "$SP/harness.log" 2>&1 &
disown -a
# poll for "$SP/.done" in ~9min foreground chunks (outer timeout ~1720s for N=8)
# then grep "$SP"/live_test*.log for VFS_BUG_ON_INODE|invalid opcode|kernel BUG|P134-ILEND-FREEING
```

**Known operational gotcha hit this session**: `/tmp/mxfs_run.lock` (flock,
see run.sh:64) can be left held by orphaned host-side ssh/sshpass child
processes from a PREVIOUS session's test invocation against a node that
gets power-cycled (cluster_reset_n.sh doesn't touch host-side processes,
only the VMs) — `fuser /tmp/mxfs_run.lock` to find PIDs, verify they're
truly orphaned (`ps -p <pid>`; if the VM they were talking to has already
been power-cycled, they can never complete), kill -9 + `rm -f
/tmp/mxfs_run.lock` before retrying. run.sh's own error message already
half-documents this ("likely a stale ccloop session's leftover").

## Next steps (in priority order)

1. Check/run validation iterations (10+ clean, full-combo, build 0.10.85) —
   if this memory exists and validation hasn't been recorded as complete
   elsewhere, that's the next action.
2. If ANY iteration still hits BUG3's exact signature on 0.10.85: re-open
   RULE-4 loop — this fix may be necessary-but-not-sufficient (there could
   be a 4th raw-ihold site not yet found, e.g. `mxfs_dlm_ilock_begin`'s
   P-DEMWAIT-REDRIVE site at ~21283 or `mxfs_dlm_queue_pr_demote`'s ~26802
   site both ALSO use raw ihold for a similar "arm and maybe drop" pattern
   and were NOT part of this proof — noted but not fixed this session since
   they weren't directly implicated by the captured pointer-matched
   evidence; check these next if 0.10.85 still crashes).
3. If clean across 10+: proceed to the FULL fresh 1/2/4/8/16/32 @ caw sweep
   (`matrix_check.py --since <0.10.85-build-epoch>`, no --nodes filter) as
   the honest YES gate for the ccloop criteria — every one of 1/2/4/8/16/32
   must show fresh PASS on 0.10.85 before writing YES to criteria-met.
   criteria.json's pre-existing "100% PASS" surface reading remains STALE
   per sess3/sess4's notes — do not trust it without this fresh sweep.
