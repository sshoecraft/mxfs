---
name: ccloop-c7ee71c6-sess31-ROOT-FIXED-caw-yield-starvation-shutdown
description: ROOT+FIX D-CAW-YIELD-STARVATION-SHUTDOWN: compatible-yield fresh acquires never registered in waiters -> invisible to yield_to ticket -> 100-retry ex…
metadata:
  type: project
---

# sess31 — D-CAW-YIELD-STARVATION-SHUTDOWN: root proven, fixed (0.11.269)

## The event (build 0.11.267, run 20260731T042501Z, QUIET host)
dirent_durability 32/caw: 10 nodes (test3,5,7,11,20,22,23,25,27,29) each logged
`DLM inode lock unrecoverable: ino=139 mode=3(PR) rc=-110 comm=mkdir` within
1.8s (04:28:08.6–04:28:10.3Z) and force-shut-down their FS; withdrawal recovery
froze grants; 22 peers hit NO_TERMINAL_RECORD. Evidence preserved:
`tests/evidence/sess31_dd_shutdown_043430/` (full dmesg all 32 + btime).

## Root (code + measured)
`dlm_caw.c` acquire loop: a mode-COMPATIBLE fresh acquire (our_mode=NL) that
finds `yield_to` non-empty and not naming it sleeps+retries (yield_bo path)
WITHOUT CAS-registering into `slot->waiters` (registration exists only on the
INCOMPATIBLE path). Releases rebuild the ticket as `yield_to = waiters`
(dlm_caw.c ~3971) — the deferrer is INVISIBLE to the rotation it defers to.
Under continuous handoff (~13 releases/s on the shared parent), the ticket
never empties and never names it: P-CAWEXH `yield_bo=100 ea_claim=0
ea_compat=0 ea_regwait=0 last_hex=0 last_hpr=0x2088082d` uniform on all 10.
100 retries × ~26ms = 2.6s/attempt × 4 ilock_begin attempts = 7.6s → -ETIMEDOUT
→ xfs_force_shutdown (mxfs_dlm_ilock_begin policy, xfs_mxfs_dlm.c:27180 —
"Corruption of in-memory data (0x8)" is just SHUTDOWN_CORRUPT_INCORE's label).
20/32 nodes hit ≥1 full exhaustion; every node with 3 consecutive died.
Same rc=-110 class as the sess130 (conversion priority) and v0.10.41
(upgrader-yields-to-pure-PR-batch) carve-outs; fresh acquires were never covered.

## Fix (GPT-reviewed per RULE 5; option C of A/B/C/D/E)
- A VISIBILITY: on first compatible-yield deferral, CAS-register our waiter bit
  (once; `mxfs.caw_fresh_register`, default 1). Claim CAS clears waiter bits +
  recomputes waiter_mode ATOMICALLY with the grant (this clear is UNCONDITIONAL
  — it also drains pre-existing ghost waiter bits left by compat grants).
- B BOUNDED COURTESY: after `mxfs.caw_fresh_yield_bound` (default 16 ≈ 400ms)
  consecutive deferrals as a REGISTERED waiter, stop deferring and take the
  compatible claim (P221-YIELD-BOUND). Scope: fresh INODE acquires only; never
  bypasses defer_for_waiter; conversions untouched.
- P-CAWEXH now prints `yreg= ybypass=` — ALSO the marker that a line is from
  0.11.269+ (older lines lack it; use `grep yreg=` to scope dmesg counts).

## Verification state (RULE 6: still OPEN, verification accumulating)
- Pre-fix same day: 3 collapses in 4 sequences (03:18, 03:50, 04:32Z).
- Post-fix (0.11.269): 5/5 dirent_durability PASS at 65-66s (incl. 3 laps with
  register=0 — the unconditional ghost-clear alone may suffice), 0 exhaustions
  (`grep 'P-CAWEXH.*yreg='` = 0 cluster-wide), 0 shutdowns, pace unchanged
  (cache 24-26s, dir_reuse 101-110s — RULE 0 clean).
- The failing regime did NOT reproduce post-fix even at loadavg 22 (higher than
  the failing era's 18), so the paired terminal-event A/B is INCOMPLETE — the
  regime is contention-marginal. Harnesses for the completion:
  `tests/ysr_dd_ab.sh <N> <fix|control>` (one dirent lap per arm, scoped
  harvest) and `tests/yield_starvation_repro.sh` (synthetic storm — currently
  NOT harsh enough to reproduce; lacks the criterion's barrier-aligned waves).

## Traps for future sessions
- dmesg counts MUST be scoped: probes without a per-run marker accumulate
  across module loads. `MXFS_YSR_MARK <tag>` via /dev/kmsg is the pattern.
- Serial logs `/var/log/libvirt/qemu/testN-serial.log` are ROOT-ONLY. An
  unprivileged read silently shows nothing — sess30's "no panic in serial log"
  was based on exactly that failure. Use `sudo -n tail`.
