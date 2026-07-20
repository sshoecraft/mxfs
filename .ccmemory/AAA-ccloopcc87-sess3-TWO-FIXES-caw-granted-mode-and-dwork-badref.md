---
name: AAA-ccloopcc87-sess3-TWO-FIXES-caw-granted-mode-and-dwork-badref
description: ccloop cc87fed3 sess3: FIX6 (CAW granted-mode blind spot, root cause of sess2's D-state deadlock, PROVEN) + FIX7 (dwork phantom-ref crash, PROVEN via…
metadata:
  type: project
---

## Context
Criterion: "1/2/4/8/16/32 node caw dlm multipath test working 100%". Sole known gap
entering this session: `fence_during_write@8/caw` (see sess2 memory
`AAA-ccloopcc87-sess2-NEWBUG-bast-writeback-xfsconv-deadlock` for the D-state
deadlock this session root-caused and fixed).

## FIX6 (build 0.10.83, srcversion AE365A0E2D49F95A4E794D6) — PROVEN root cause of sess2's bug

**Root cause**: `mxfs_v5_dlm_inode_granted_mode()` (dlm/v5_mount.c) had NO `ctx->dlm_caw`
branch — `if (!ctx || !ctx->dlm) return MXFS_LOCK_NL;` unconditionally returns NL
whenever `ctx->dlm` is NULL, which is ALWAYS true on CAW transport (CAW uses
`ctx->dlm_caw`, a separate field). Every sibling accessor in the same file
(`mxfs_v5_dlm_inode_held_rawmode`, `_grant_handoff`, `_dir_epoch`, `_orphan_clock_get`)
correctly falls back to `ctx->dlm_caw`; this one never got that treatment (its own
comment even documented the NL-on-CAW behavior as accepted, from when it was written
for TCP-only FIX-1/P79-NESTADMIT).

**Why this caused the deadlock**: this function is THE gate for TWO existing
deadlock-breakers in `xfs_mxfs_dlm.c`:
- `mxfs_ilock_admit_ioend()` (FIX-25, ~L19672): admits the xfs-conv ioend-completion
  kworker to a nested EX during a BAST/DEMOTING drain, IF the live mirror
  (`g2 = mxfs_v5_dlm_inode_granted_mode(...)`) reads back EX or PR. On CAW, g2 was
  ALWAYS NL — `g2 != EX && g2 != PR` always true — admit_ioend ALWAYS returned false.
  Zero `P25-IOEND-ADMIT` lines ever printed despite the exact deadlock firing.
- P79-NESTADMIT (`mxfs_dlm_ilock_begin`, ~L20982/21162): same blind spot, separate
  bug class (nested BAST-state re-entrant hold) — not directly proven this session
  but the same accessor gap applies, worth re-checking if a similar CAW-only hang
  ever resurfaces there.

**Live proof (test7, sitting stuck for 20+ min across a session boundary — same PIDs
3816/5402/8698 as sess2 documented)**: `P73-WAITSTALL ino=10487698 req=5(EX) mode=3(PR)
state=3(DEMOTING) ex=0 pr=0 pin=0 bast_pend=0 work_busy=3 relflush=0` repeating every
30s for 20+ min; `addr2line` on the exact live RIP (`mxfs_dlm_ilock_begin+0xbb0`,
srcversion 6DA24BC6DC1C11CFF244AD1 matching the loaded module) resolved to
`xfs_mxfs_dlm.c:21105` — the `wait_event_timeout` in the DEMOTING/ACQUIRING/BAST wait
loop, confirming admit_ioend never fired. `mxfs_dlm_bast_process`'s own stack was
frozen at a FIXED offset (`mxfs_dlm_bast_process+0x5a3`, matching the
`filemap_write_and_wait(vip->i_mapping)` call at what's now ~L11982) for the entire
20+ minutes, meaning RELFLUSH (set 40 lines later at ~L12022) was ALSO never reached
in time — both defenses miss this exact window, but admit_ioend was designed to be
the primary/general one and it was the one silently dead on CAW.

**Fix**: added `mxfs_dlm_caw_granted_mode()` (dlm/dlm_caw.c, next to
`mxfs_dlm_caw_held()`) returning the REAL per-node mode via the same
`node_held_mode(slot, ctx->node_bit)` bitmap lookup `mxfs_dlm_caw_held()` uses
internally (do NOT reuse `mxfs_dlm_caw_held()` directly — it collapses to a boolean,
which would let a PR-only hold be misread as EX by admit_ioend's
`if (g2==EX && ip->i_dlm_mode<EX) ip->i_dlm_mode=EX;` upgrade — a real coherency
risk, not just a missed-admit risk). Wired into `mxfs_v5_dlm_inode_granted_mode()`
with an `else if (ctx->dlm_caw)` branch mirroring the sibling accessors exactly.
Declared in dlm/dlm_caw.h next to `mxfs_dlm_caw_held`.

**NOT yet independently validated this specific mechanism in isolation** — the very
next repro run (same session) hit a DIFFERENT bug (FIX7 below) before dir_reuse+fence
could complete cleanly, so admit_ioend's actual live engagement (P25-IOEND-ADMIT
firing) has not yet been confirmed in dmesg. Check for it on the next successful run.

## FIX7 (build 0.10.84, srcversion 4C015B741342F98D124D047) — dwork phantom-ref crash

**Found during the FIX6 validation run** (test6, same fence_during_write@8/caw
repro, AFTER dir_reuse_coherency PASSED 8/8): a genuine kernel BUG (invalid opcode /
UD2 trap), NOT a hang. `iput()`'s `VFS_BUG_ON_INODE(state & (I_FREEING|I_CLEAR))`
(fs/inode.c:1980, confirmed via `/src/linux/fs/inode.c` — NOTE reference kernel is at
`/src/linux`, NOT `~/src/linux`) fired inside `xfs_irele() <- mxfs_dlm_bast_dwork_fn`.
Serial log: `Workqueue: mxfs-ino-bast/dm-1 mxfs_dlm_bast_dwork_fn [mxfs]`, RIP
`iput+0x1c5/0x250`. Confirmed the crashing kworker actually died (oops, "end trace",
tainted G W OE) but the VM/kernel kept running otherwise — this is what LOOKED like
a CPU-pin-style unresponsive node to the diag_cpu_pin_capture.sh SSH poller (test6
went fully SSH-unreachable, "No route to host" — a dead/reset network stack from the
crashed kworker holding something, not a genuine softlockup).

**Root cause class (proven via addr2line, NOT fully root-caused to the exact
reference-accounting bug)**: `addr2line` on the exact crash return address
(`mxfs_dlm_bast_dwork_fn+0xa9`, against the build actually loaded on test6, confirmed
via cluster_reset_n.sh's srcversion check) resolved to `xfs_mxfs_dlm.c:14136` — the
line immediately after the MAIN release-completion path's `xfs_irele(ip)` call
(after `mxfs_dlm_bast_process(ip)` returns), i.e. NOT one of the 3 early-bailout
paths. `mxfs_dlm_bast_work_fn` (the sibling non-timer BAST handler, same file,
~L13977) ALREADY has a defensive "sess60 detector" guarding its OWN analogous
xfs_irele — checks `i_count<1 || (i_state & I_CLEAR)` and skips the irele (loud
`P60-BWFN-BADREF` warning instead) if the inode looks already-freeing.
`mxfs_dlm_bast_dwork_fn` never got the same guard on ANY of its 4 exit paths — this
is very likely an oversight (dwork_fn probably added/extended independently of when
sess60 was written for work_fn), not a newly-introduced regression from FIX6 (FIX6
never touches this function or its callers).

**Did NOT chase the exact concurrent path that double-drops/races this reference**
(would need instrumented rebuild+reproduce cycle #2 — 10 legitimate
`ihold()`-then-`queue_delayed_work()`-else-`irele()` call sites for
`i_dlm_bast_dwork` were all individually audited and look correctly balanced; the
`cancel_delayed_work_sync` call in the evict path (~L23162+27 now) also looks
defensively reasonable — self-reentrant cancel from within the dwork's own
xfs_irele-triggered eviction cascade should safely no-op). The mitigation applied
matches the codebase's OWN established precedent (bast_work_fn's sess60 detector) —
treat a rare phantom-queue race as "detect and skip (leak a ref, log loudly)" rather
than crash, exactly the tradeoff already accepted for the sibling function.

**Fix**: new `mxfs_dlm_dwork_safe_irele(ip, site)` static helper right before
`mxfs_dlm_bast_dwork_fn`, checking `i_count<1 || (i_state & (I_FREEING|I_CLEAR))`
(widened vs bast_work_fn's I_CLEAR-only check, to match iput()'s REAL assertion
condition exactly) before calling `xfs_irele`; logs `P124-DWFN-BADREF` and skips if
unsafe. Applied at all 4 exit paths (site 1=early-return/already-consumed,
2=strikeout, 3=rearm-failed/duplicate-ref, 4=main release-completion — site 4 is the
one that crashed).

## State as of this write
- Build 0.10.84 compiled clean (only pre-existing unrelated warnings: unused
  `_mxfs_ioend_bioset_compat`, two frame-size-larger-than-1024 in
  `mxfs_dir_platter_audit`/`mxfs_dir_hole_disk_probe`, `/*` in comment x2 — none new
  from this session's edits).
- test6 crashed/tainted (oops mid-run) — needs `virsh destroy/start` before reuse,
  like test7 did in sess2. test7 itself (from sess2's stuck state) WAS already
  recovered + confirmed healthy earlier this session via
  `scripts/cluster_reset_n.sh 8` (which power-cycled + reprepped + srcversion-verified
  ALL 8 nodes onto 0.10.83, before FIX7 was found — so test6's crash happened on a
  freshly-booted 0.10.83, not on stale state).
- **Next action**: `scripts/cluster_reset_n.sh 8` again (recovers test6, redeploys
  0.10.84 everywhere), then relaunch
  `tests/diag_cpu_pin_capture.sh 8 <outdir> caw_fair_handoff=1` fresh. Watch for BOTH:
  (a) `P25-IOEND-ADMIT` appearing in dmesg (proves FIX6 actually engages — has not
  been observed yet), and (b) `P124-DWFN-BADREF` (proves FIX7's guard catches the
  phantom-ref race if it recurs — should NOT crash the node even if it fires).
  Per RULE 4 need 2-3 CLEAN iterations (neither the sess2 pr_sweep bug, nor FIX6's
  deadlock, nor FIX7's crash) before moving to the full 1/2/4/8/16/32 sweep.
  Resume the clean-iteration count from scratch for THIS specific combination of
  fixes (0.10.84) — do not carry over sess2's "1 of 2-3" pr_sweep-only count, since
  the bug landscape has materially changed (2 more real bugs found+fixed since then).

## Reusable technique notes (for any future session)
- `addr2line -e mxfs.ko -f -C <absolute_addr>` where absolute_addr = function's
  objdump base address + the `+0xNN` offset from a stack trace/dmesg RIP line —
  works great for resolving BOTH live-stuck-thread RIPs (via
  `virsh qemu-monitor-command` or `/proc/pid/stack`) AND POST-CRASH oops call-trace
  offsets (`funcname+0xNN/0xMM` lines in dmesg/serial log), as long as the LOCAL
  `mxfs.ko`'s srcversion matches what's actually loaded on the node in question
  (verify via `modinfo mxfs.ko | grep srcversion` locally vs
  `cat /sys/module/mxfs/srcversion` on the node, or trust `cluster_reset_n.sh`'s own
  `ALL_OK srcversion=...` check if it just ran). Much faster and more precise than
  manual objdump+disassembly reading once you have a concrete offset.
- Reference kernel source is at `/src/linux` (absolute path) — `~/src/linux` does
  NOT resolve in the Bash tool's environment even though it's the same intended
  location; use the absolute path directly.
- A node that goes SSH-unreachable ("No route to host" specifically, not just a
  timeout) during a CAW test run is NOT necessarily the CPU-pin/softlockup bug class
  — check `sudo tail`/`grep` the node's serial log
  (`/var/log/libvirt/qemu/test<N>-serial.log`, root-owned) for "invalid opcode",
  "kernel BUG", "Oops" FIRST, before assuming it needs the heavier QEMU-monitor
  register-capture treatment. A crashed/oopsed kworker can take the network stack
  down (or otherwise wedge the node) without it being a spin/deadlock at all.
