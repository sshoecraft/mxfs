---
name: AAA-ccloopcc87-sess2-FIX4-pr_sweep_unbounded_lock_hold-VALIDATING
description: ccloop cc87fed3 sess2: 4th bug in fence_during_write@8/caw chain PROVEN+FIXED (pr_sweep_work_fn held s_inode_list_lock unbounded), build 0.10.81. Val…
metadata:
  type: project
---

## Context

Criterion: "1/2/4/8/16/32 node caw dlm multipath test working 100%". Entire matrix
PASS in criteria.json EXCEPT `fence_during_write@8/caw` — the SOLE remaining gap,
now a chain of 4 distinct bugs across sessions. Inherited from ccloop cc87fed3
sess1 (build 0.10.80, srcversion 06C2F26F678BBC77FE670AF): bugs #1-3 already fixed
+ validated (see memory `AAA-ccloopcc87-sess1-FIX3-resource-scoped-orphan-clock-VALIDATING`
for the full chain summary). sess1 found that enabling the pre-existing (default-OFF)
`caw_fair_handoff=1` module param alongside fixes #1-3 eliminated all self-fence/
shutdown events across 7/8 nodes but left node test4 CPU-pinned/unresponsive to SSH
— a NEW, uncharacterized symptom. sess1 ended there (context boundary) without
diagnosing it. **CORRECTION to sess1's memory**: `caw_fair_handoff` does NOT default
to 1 — verified by direct grep of `dlm/dlm_caw.c`: `int mxfs_caw_fair_handoff;`
(zero-initialized BSS, no initializer) + its own `MODULE_PARM_DESC` literally says
"0=off (default), 1=on". Must be explicitly set via `MXFS_EXTRA_MODARGS=caw_fair_handoff=1`
for every repro/validation run until/unless the ship default is changed.

## Bug #4 — mxfs_dlm_pr_sweep_work_fn holds s_inode_list_lock unbounded — ROOT PROVEN, FIXED

### Root cause (RULE-4 PROVEN via LIVE instrumentation, not guessed)
Reproduced the CPU-pin with `tests/diag_cpu_pin_capture.sh 8 <outdir> caw_fair_handoff=1`
(new script this session, runs `dir_reuse_coherency fence_during_write` @ 8/caw in the
background while polling SSH liveness). test8 went unresponsive ~14 min into the run
(after dir_reuse_coherency PASSED, mid fence_during_write). **Direct proof without any
guest cooperation** (SSH was fully dead): used `virsh qemu-monitor-command testN --hmp
"info registers -a"` — reads live vCPU state straight from QEMU on the HOST side, works
even when the guest scheduler is completely wedged. Two samples 54s apart showed CPU#2's
RIP **exactly identical** (`0xffffffffc0f3c993`, module address range) both times —
proof of a genuine stuck spin, not just "slow". Since SSH was dead I couldn't read
`/sys/module/mxfs/sections/.text` (module load base, needed to symbolize a RIP — module
addresses are KASLR-randomized per boot) for THIS specific node/boot. Worked around it:
pulled the raw instruction bytes at that RIP directly via `virsh ... --hmp "x/64xb <rip>"`
(HMP disassembly itself unsupported on this arch/build — "Asm output not supported" —
but raw byte reads work fine), then found the UNIQUE (single match in the whole 1.4MB
.ko) byte-for-byte offset in the local `mxfs.ko` file via a Python scan, converted
file-offset -> `.text`-section-relative address (using `objdump -h` for the section's
file offset), and looked up the nearest symbol `<=` that address in `nm -n mxfs.ko`:
**`mxfs_dlm_pr_sweep_work_fn+0x93`** (`xfs/xfs_mxfs_dlm.c:26732`), confirmed by manually
decoding the byte sequence (`movzx ax,[rbx]; and ax,0xf000; cmp ax,0x8000; jnz; cmp
word[rbx-0x170],0x103; jnz; movzx al,[rbx-0x180]; cmp al,1; ...`) and matching it
1:1 against the function's `S_ISREG(inode->i_mode)` / `ip->i_dlm_mode`/`i_dlm_state`/
`i_dlm_bast_pending` filter checks at lines 26747-26759.

This function (a `work_struct` handler queued on `m_mxfs_inode_bast_wq`, matching the
historical "kworker" stuck-task symptom from earlier serial-console evidence — see
sess1's test4-serial.log finding) walks `sb->s_inodes` (the WHOLE superblock cached-inode
list) `spin_lock`'d under `sb->s_inode_list_lock` — a GLOBAL, filesystem-wide spinlock.
**Every `continue` in the original code (non-regular-file, wrong DLM mode/state, BAST
pending) stayed under that held lock** — the lock is only ever dropped when an actual
sweep candidate is found. The function's own doc comment says it follows the
"fs/drop_caches.c iteration idiom", and it does structurally, EXCEPT it silently dropped
the one thing that idiom exists FOR: upstream's `drop_pagecache_sb` (`/src/linux/fs/drop_caches.c`
— note: NOT `~/src/linux`, the actual reference tree per RULE 1 is at `/src/linux`)
has an explicit comment: *"We may also skip inodes without pages but we deliberately
won't in case we need to reschedule to avoid softlockups"* — upstream falls through
to igrab+unlock+`cond_resched()` even on an otherwise-skippable inode whenever
`need_resched()` is true, specifically bounding how long the walk can hold
`s_inode_list_lock` (which disables preemption). MXFS's version had NO such escape —
a bare `continue`, unconditionally, on every reject path.

**Why this hit NOW (not in earlier sessions)**: `mxfs_dlm_pr_sweep_trigger` (xfs_mxfs_dlm.c
~26789) fires the sweep (rate-limited to once/3s) specifically when "a DIRECTORY this
node held in PR is being demoted [BAST-stripped] by a peer's EX request" — exactly
fence_during_write's cross-node access pattern on the shared hot directory. With bugs
#1-3 fixed AND `caw_fair_handoff=1` now rotating EX ownership fairly across all 8 nodes
(instead of the pre-fix starvation/self-fence pattern masking it), this trigger condition
now fires reliably on every node under sustained load, and the resulting walk — over
whatever the 8-node create/unlink storm has swollen the shared superblock's cached-inode
list to — runs long enough (most inodes in a dir-heavy workload are NOT regular files
mid-PR-hold, so long non-candidate runs are the COMMON case) to blow past the 20s
softlockup threshold while `preempt_disable()`'d (spin_lock's implicit effect).
Confirms the softlockup mechanism precisely: hardware timer interrupts still fire
(preempt_disable doesn't block interrupts), so the watchdog's periodic dmesg print
still fires reliably every ~28s from interrupt context — but the underlying task/CPU
genuinely never reaches a reschedule point, hence permanent hang, hence "kworker"/
"bash" (whatever task happened to be running when this kworker grabbed the CPU and
disabled preemption) reported stuck by the kernel's own softlockup detector.
(Confirmed via `sudo grep` on `/var/log/libvirt/qemu/test{4,8}-serial.log` — real
`watchdog: BUG: soft lockup` messages, reproducible across MULTIPLE separate boots/
nodes with this exact caw_fair_handoff=1 workload; lockdep is NOT compiled into this
kernel — `zcat /proc/config.gz` unavailable / no "Lock dependency validator" boot
banner — so a lock-order bug wouldn't self-report; that's why live register capture
was necessary rather than relying on kernel diagnostics.)

Also saw test3 go unresponsive in the SAME run (secondary/cascading — its capture
showed only 1 of 4 vCPUs non-idle, core-kernel RIP not module RIP, consistent with
being blocked waiting on a barrier/peer response FROM test8 rather than an independent
instance of the same bug — not chased further since the primary root cause was already
proven; revisit only if it recurs on the fixed build).

### Fix (0.10.81, srcversion 6AC96C4BB0B758DF38524A0)
`xfs/xfs_mxfs_dlm.c::mxfs_dlm_pr_sweep_work_fn` (~line 26744): restructured the reject
path to mirror upstream's escape exactly — compute `is_candidate` up front (unlocked
prefilter, same semantics as before), then `if (!is_candidate && !need_resched())
continue;` (bare fast path, ZERO added cost — this is the overwhelmingly common case
and pays nothing extra) else `igrab` + drop the lock + (`cond_resched()` if not a real
candidate, or do the real demote-queue work if it is) + `iput(toput)` of the PREVIOUS
pinned inode (never the current one — iput can recursively need `s_inode_list_lock`
via eviction, so it must never be called while the lock is held; this is why upstream
keeps a one-iteration-behind `toput` pointer instead of iput'ing immediately) + re-lock.
Unifies what were two separate paths (candidate-found vs need-resched) into the SAME
igrab/unlock/toput/relock flow so there's only one place that can get this ordering
wrong. Builds clean (`make modules`), no new warnings on the touched lines.

### Bonus fix: diag_cpu_pin_capture.sh's own polling loop bug
While debugging why my new capture script (`tests/diag_cpu_pin_capture.sh`, written
this session) never actually logged the test8 miss I found by hand: it has a bare
`wait` after backgrounding each round's 8 per-node liveness-check subshells — since
$RUNPID (the ~29min run.sh background job) is ALSO a background job of the SAME
shell, bare `wait` blocks on ALL of them, not just the 8 poll subshells. This is the
IDENTICAL bug ccmemory already had on file for `repro_fdw_instrumented.sh` (never
fixed there — "fix if convenient"). Fixed properly this time: collect poll subshell
PIDs explicitly into an array, `wait "${pollpids[@]}"` instead of bare `wait`. If you
reuse `repro_fdw_instrumented.sh` instead of `diag_cpu_pin_capture.sh`, remember IT
still has the old bug (sampler only ever captures one round).

## State AS OF THIS WRITE
- All 8 nodes healthy, build 0.10.81 (6AC96C4BB0B758DF38524A0) compiled and ready to
  deploy (deploys automatically via NFS-shared /src + run.sh's srcversion check).
- test3 and test8 (both wedged from the pre-fix repro) power-cycled and confirmed back.
- **Next action**: launch `tests/diag_cpu_pin_capture.sh 8 <outdir> caw_fair_handoff=1`
  fresh (now with the wait-bug fixed, so its own miss-detection actually works this
  time) and let it run to completion (~29 min budget). If `fence_during_write` PASSES
  with RUN_EXIT=0 and no node goes unresponsive (monitor.log stays free of "miss #2"
  entries) and dmesg across all 8 nodes shows no self-fence/shutdown/soft-lockup —
  bug #4 confirmed fixed. Run 2-3 clean iters per RULE 4 before declaring victory
  (this class of bug — depends on inode-cache size reaching a threshold — may not
  hit every single run).
- After clean: per `AAA-ccloopcc87-sess1-FIX3-...`'s own next-steps (still valid):
  full fresh single-build revalidation sweep at 1/2/4/8/16/32 via `scripts/revalidate_cell.sh`,
  then `python3 scripts/matrix_check.py --since <0.10.81-build-epoch>` (no --nodes
  filter) must show ALL of 1/2/4/8/16/32 @ caw as fresh PASS. `MXFS_DEV=/dev/mapper/mpatha`
  always. **Decide before the final ship run**: does `caw_fair_handoff` need to default
  to 1 for the criterion to hold under a STOCK (no MXFS_EXTRA_MODARGS) invocation of
  `run.sh`/the grading harness? sess1+sess2 evidence says YES (fair_handoff=1 is what
  stops the self-fence/starvation family in the first place) — if the final matrix
  sweep is run WITHOUT the modarg and fence_during_write@8/caw fails again via the
  OLD starvation symptom (not this session's lockup), flip the module's default and
  rebuild before re-testing, same way `mxfs_dir_force_block` was flipped to default-0
  in the caw-ladder-fb0 fix (see memory `caw-ladder-fb0-progress-2-4-8-green`).
