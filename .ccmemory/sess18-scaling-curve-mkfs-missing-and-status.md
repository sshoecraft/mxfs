---
name: sess18-scaling-curve-mkfs-missing-and-status
description: sess18 part 2: scaling_curve timeouts root = mkfs_mxfs binary MISSING (make clean w/o make tools) → silent stale-FS reuse. Tools rebuilt, lib.sh chec…
metadata:
  type: project
---

# sess18 part 2 — scaling_curve diagnosis + infra fixes (continue here)

## Where things stand (build `CB1C5FEF6D9B6C4CA094D29`, v0.5.0, deployed on all 16)
- crash_consistency PASS ×3, fence_during_write PASS — see
  [[sess18-crash-consistency-PASS-foreign-replay-shipped]].
- Ledger `.criteria_results.json`: all 17 entries PASS, but the gate needs ONE
  end-to-end `verify_ship.sh` run (19 criteria incl. posix_semantics --nodes 16
  and scaling_curve --nodes 16; soak only with --include-soak).

## scaling_curve --nodes 16: 3 timeouts at 330s budget, ROOT-CAUSED (infra, not FS)
1. Run 1: test3 was left DOWN by fence_during_write (fence victim) → stage-4
   teardown_all rebooted it (~150s) → budget blown. (Criterion-leaves-node-down
   is a contamination pattern: reset or verify node health between criteria.)
2. Runs 2-3: **`tools/mkfs_mxfs` DID NOT EXIST** — my `make clean && make modules`
   wiped userspace tools and nothing rebuilt them. fresh_cluster_mount's mkfs
   failed silently (`MKFS_OK` echoed but NEVER checked) → mount reused the
   PREVIOUS filesystem → stage 2 inherited stage-1's 8k-file rsync tree →
   `rm -rf scale` became a 2-node cross-node CAW unlink storm (275s+ in D-state,
   xlog_wait_on_iclog) → stall. Stage 1 itself measured fine: 10126ms.
   NOTE: crash_consistency/fence PASSes ran on a reused (not fresh) FS — still
   valid tests (they only need a working cluster FS) but explains stray
   `crash_consistency_test`/`fence_test` files on the LUN.

## Fixes landed this session (infra)
- `make tools` re-run — mkfs_mxfs/chk_mxfs back (42KB/30KB, v0.5.0 defines).
  **LESSON: after `make clean`, ALWAYS `make tools` too.**
- lib.sh fresh_cluster_mount now HARD-FAILS if MKFS_OK absent (first node).
- lib.sh both insmod sites: rmmod-if-loaded before insmod so INSMOD_OPTS params
  always apply (already-loaded insmod fails File-exists silently).
- crash_consistency.sh INSMOD_OPTS = `lease_timeout_ms=16000` (real param).
- TIMEOUT_BUDGETS.md: crash_consistency row updated (150s, measured 106-108s).

## Immediate next steps
1. `scripts/cluster_reset_n.sh 16` (75s) — nodes test1/test2 are contaminated
   (test1 had a wedged rm in xlog_wait_on_iclog; dmesg froze — if that recurs
   on a CLEAN run it's a real log-wedge bug, RULE 4 it).
2. Re-run `tests/criteria/scaling_curve.sh --nodes 16` (budget 330s; stage 1
   measured 10.1s — 5 stages ≈ 5×(teardown+mkfs+mount+rsync) ≈ 250s estimate).
   With working mkfs, rm -rf storm path disappears.
3. `tests/criteria/posix_semantics.sh --nodes 16` (budget 420s).
4. Full gate: `tests/criteria/verify_ship.sh` end-to-end (every criterion PASS
   in ONE run; ~30-40 min — run criteria individually first if any doubt).
5. Also pending from sess17 plan: 16-node crash_consistency storm re-test (the
   "10s lease" attribution was WRONG — params never existed; storm ran at 62s
   detection), awareness docs update (xfs.md, dlm.md, pal.md flagged stale),
   CLAUDE.md current-build line.
