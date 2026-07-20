---
name: AAA-ccloopcc87-sess2-FIX5-pr_sweep_unconditional_yield-VALIDATING
description: ccloop cc87fed3 sess2: FIX4 (need_resched-gated yield) insufficient — proven via 2nd live capture (RCU stall, 0 csw). FIX5 adds unconditional periodi…
metadata:
  type: project
---

## Supersedes / extends
`AAA-ccloopcc87-sess2-FIX4-pr_sweep_unbounded_lock_hold-VALIDATING` (same session).
Read that memory FIRST for the original root-cause proof (byte-exact RIP match to
`mxfs_dlm_pr_sweep_work_fn`'s `S_ISREG`/`i_dlm_mode` filter, upstream `fs/drop_caches.c`
comparison). This memory documents why that fix (build 0.10.81) was NECESSARY BUT NOT
SUFFICIENT, and the follow-up fix (build 0.10.82).

## Why FIX4 (need_resched()-gated cond_resched) wasn't enough

Re-ran the SAME repro (`tests/diag_cpu_pin_capture.sh 8 <outdir> caw_fair_handoff=1`) on
build 0.10.81. `dir_reuse_coherency` PASSED again; partway into `fence_during_write`,
node **test7** went unresponsive — NOT the same instant/static-RIP signature as before
(that was CPU#2 frozen on ONE exact instruction). This time: 3 of 4 vCPUs HLT'd (idle),
CPU#3 alone busy with a MOVING RIP across samples, node totally SSH-unreachable for over
13 minutes straight (96+ consecutive missed 3s-timeout polls).

**Proved (not guessed) via live introspection, no guest cooperation needed (SSH was
dead)**:
1. `sudo grep` test7's serial console log (`/var/log/libvirt/qemu/test7-serial.log`,
   needs `sudo` — root-only perms) for the CURRENT boot's tail: real
   `watchdog: BUG: soft lockup - CPU#3 stuck for 753s! [kworker/u12:15:1290]`, PLUS —
   much more informative than a bare softlockup — `rcu: INFO: rcu_preempt
   self-detected stall on CPU 3-....: (779957 ticks this GP) ... csw/system: 0` —
   **zero context switches** for the entire stall. This is the smoking gun: a genuine
   "never yields" bug, not just "slow".
2. Symbolizing a CORE-KERNEL (not module) RIP without vmlinux debug symbols: found
   `/boot/System.map-6.8.0-101-generic` IS present on the host (root-readable only,
   `sudo cp` it out) and matches the guest's exact kernel package. Recovered the
   guest's PER-BOOT KASLR slide with NO crash needed on that boot, by exploiting that
   x86-64 kernel-text KASLR here is 2MB-granular (confirmed empirically: 4 different
   nodes' idle-HLT RIPs — `virsh qemu-monitor-command <node> --hmp "info registers
   -a"` on an otherwise-healthy node, CPU showing `HLT=1` — all shared the exact same
   `addr mod 0x200000` even though their high bits differed; separately cross-confirmed
   against several *historical* `Kernel Offset: 0x.... from 0xffffffff81000000` lines
   already sitting in the serial logs from EARLIER unrelated crashes this project's
   history — all multiples of 0x200000). So: `slide = observed_runtime_idle_RIP -
   static_address_of_the_containing_symbol_in_System.map` (found the containing
   symbol — `pv_native_safe_halt` — by searching System.map for the symbol whose OWN
   address has the same `mod 0x200000` remainder as the observed idle RIP). Apply that
   slide to any other RIP/stack-word to get its static address, look up in System.map.
3. With the slide recovered: CPU#3's two dominant hot addresses (oscillating between
   them across 3s-spaced samples) symbolized to **`_raw_spin_lock+0x17`** and
   **`__raw_callee_save___pv_queued_spin_unlock+0x10`** — genuine spinlock acquire/
   release ping-pong, NOT the earlier bug's frozen single-instruction spin.
4. Read the actual CALL STACK off CPU#3's live stack memory (`virsh qemu-monitor-command
   <node> --hmp "cpu 3"` to select context, then `--hmp "x/80gx <rsp>"` — reads guest
   virtual memory through that vCPU's own page tables, still works with the guest
   fully wedged): symbolized the stack words (same slide) to
   `ret_from_fork_asm -> ret_from_fork -> kthread -> worker_thread -> process_one_work`
   — confirms this IS a workqueue kworker (matches the historical "kworker" symptom),
   consistent with (though not 100%-conclusively pinned to, since `process_one_work`'s
   indirect call to the work function didn't leave an easily-decoded pointer in the
   captured registers) `mxfs_dlm_pr_sweep_work_fn` again, OR another loop with the same
   shape.

## Root gap in FIX4
`need_resched()` is NOT a "have I run too long" timer — it only becomes true when some
OTHER task actually wants THIS specific CPU. At capture time 3 of 4 vCPUs were idle
(HLT) — nothing was contending for CPU#3, so `need_resched()` could legitimately stay
false for the ENTIRE 750s+ stall, meaning FIX4's escape valve NEVER engaged no matter
how long the walk ran. Checked a healthy peer's actual cache size mid-run
(`cat /proc/sys/fs/inode-nr` over ssh) — only ~6666 inodes total, nowhere near enough to
explain 750s+ even paying a real `spin_lock`/`spin_unlock` pair per entry — so either
(a) `mxfs_dlm_pr_sweep_trigger` is somehow re-queueing far more aggressively than its
3s rate-limit intends (checked the trigger's CAS logic, looks correct on inspection —
NOT proven to be the cause), or (b) `sb->s_inodes` is genuinely cyclic/corrupted on this
node (unproven, not ruled out — `list_for_each_entry` has no way to bound a cycle that
doesn't include the list head). Did not chase (a)/(b) further given time cost; the fix
below is safe and sufficient regardless of which is true.

## Fix (0.10.82, srcversion 6DA24BC6DC1C11CFF244AD1)
Same function (`xfs/xfs_mxfs_dlm.c::mxfs_dlm_pr_sweep_work_fn`), two additions on top
of FIX4's structure:
1. **Unconditional periodic yield**: new `visited` counter, incremented every loop
   iteration (candidate or not). `force_yield = (visited % 2048) == 0`. The fast-path
   guard becomes `if (!is_candidate && !force_yield && !need_resched()) continue;` —
   every 2048th iteration now falls through to igrab+unlock+cond_resched+relock
   REGARDLESS of scheduler contention, bounding worst-case uninterrupted (lock-held,
   non-yielding) runtime to at most 2048 cheap field-check iterations no matter what
   else is or isn't runnable on that CPU.
2. **Hard iteration cap** (`MXFS_PRSWEEP_VISIT_CAP = 1000000`, ~150x the observed
   healthy baseline): if hit, drop the lock, `iput()` the pinned inode, log
   `P-PRSWEEP-CAP` (ratelimited-worthy if it ever fires in practice — not currently
   ratelimited since it should be extraordinarily rare) and return early — a hard
   backstop against a genuinely cyclic/corrupted list, so this best-effort background
   sweep can NEVER hang forever even in that scenario; worst case it just stops sweeping
   early (harmless — it's an optimization, not correctness-critical) and the next 3s
   trigger tries again.
   **CAUGHT A REAL BUG while writing this**: first draft called `iput(toput)` BEFORE
   `spin_unlock()` in the cap-bailout branch — violates the exact "never iput() while
   holding s_inode_list_lock" rule FIX4 was built around (iput can recursively need the
   same lock via eviction). Fixed before building: `spin_unlock()` then `iput()`.
   **If you touch this function again, grep for every `iput(` call and confirm none of
   them sit between a `spin_lock(&sb->s_inode_list_lock)` and its matching
   `spin_unlock()`.**
`mxfs_dir_ex_bast_sweep` (the enable switch for the trigger) defaults to **1 (ON)** —
this is ship config, not an opt-in modarg; the bug is real for default runs, not just
this test harness.

## State AS OF THIS WRITE
- Build 0.10.82 compiled clean (no new warnings on touched lines).
- test7 was power-cycled (was the stuck node on 0.10.81); all 8 nodes should be healthy
  after it comes back — VERIFY before relaunching, don't assume.
- **Next action**: relaunch `tests/diag_cpu_pin_capture.sh 8 <outdir> caw_fair_handoff=1`
  fresh on 0.10.82. Same watch criteria as before (RULE 4 — need 2-3 clean iters, this
  bug class doesn't hit every run). If a node stalls AGAIN: re-run the SAME live capture
  technique (register sample x2 for staleness, System.map slide recovery via the
  idle-RIP mod-2MB trick if module RIP isn't directly hit, stack walk via `cpu N` +
  `x/Ngx <rsp>`) — the toolchain now exists and works, don't rebuild it from scratch.
  If it's the SAME `_raw_spin_lock` ping-pong signature again even after this fix, that
  would be strong evidence for hypothesis (b) above (genuine list corruption) — pivot
  to instrumenting `sb->s_inodes` insert/delete under `caw_fair_handoff=1` specifically
  (a race unique to its round-robin handoff timing is plausible) rather than patching
  the sweep function a 3rd time.
- Diagnostic tooling now in the source tree (`tests/diag_cpu_pin_capture.sh`, RULE 3) —
  reusable for ANY future softlockup/hang repro, not just this bug. Its own `wait`-bug
  (bare `wait` catching the background run.sh job) is already fixed — see FIX4 memory.
- After this class of bug is confirmed clean: same next-steps as FIX4's memory — full
  fresh 1/2/4/8/16/32 @ caw revalidation sweep, decide on `caw_fair_handoff` ship
  default before the final gate.
