<!-- sess481 END: crash_consistency ceiling ruled (handoff tuning cannot fix it), P132-CREATE extended to file creates, 0.65.0 UNBUILT, chain 128 queued. -->
# sess481 END — relay state

## Tree state — READ THIS FIRST

**VERSION 0.65.0, and the tree is UNBUILT.** The deployed module is still
0.64.37 `sv EAD72FC7EC56BA505829901`. Kernel source changed
(`xfs/xfs_inode.c`, `xfs/xfs_mxfs_dlm.c`, `xfs/xfs_mxfs_dlm.h`), so the next
build produces a NEW srcversion. Any chain that installs a frozen `.ko` is
unaffected; anything that runs `make modules` gets the instrumented build.

Compile-verified, not yet linked into a shipped module: both changed objects
build clean (`rc=0`) in a scratch copy, and `strings` finds `dlk_ms=` in the
new `xfs_inode.o`. The one format warning in that build is in `xfs_rename`,
pre-existing, not from this change.

## What was measured, and what it overturns

The board's `crash_consistency` FAIL was read by sess480 as three stragglers
stalling a barrier. The nodes' own kmsg phase markers refute that: **all 32/32
reach `PHASE=dropcaches-done`**, the write phase eats 85-88 s of the 90 s
budget, and the cross-node cold verify — the whole point of the test — never
executes on any node. `checks=1 passed=1 failed=0` meant *no check was
reached*, not *nothing failed*. Detail:
`docs/history/docs/history/docs/history/compiled-sess481-crash-consistency-ceiling-campaign.md`.

`P291-EXWIN` on the shared dir (test1): n=139, p50=0, p90=0, sum 43,354 ms in
**eight** waits (3354/6581/5620/5662/5813/5845/5159/5320 ms) spaced 7-9 s
apart, each with 26-28 peers queued. That is a **fair** 32-node rotation — 48%
of the budget is queue delay, not starvation and not a lost wakeup.

## The ceiling ruling (RULE-5 checked)

Removing ALL handoff cost buys at most `1/(1-f_H)`. Fitting the workload into
30 s needs 2.84x ⇒ requires **f_H ≥ 64.8%**. Measured `P138-BAST` release on
that directory: n=15, p50 14.9 ms, p90 52.7 ms, max 97.1 ms against turns of
170-320 ms ⇒ **f_H ≈ 5-16%, ceiling 1.05-1.19x.**

**So the queued fastpoll A/B cannot close this row even if it works
perfectly.** Keep it — reframed as a LUN/poll-congestion experiment, since 31
waiters polling one slot can inflate the WORK term too — but do not expect a
closure from it. Full ruling, including five other candidate mechanisms and
the legitimate directory-lock redesigns:
`docs/rulings/pace-ceiling.md`.

**The binding term is the per-create cost that survives removing the shared
directory**: 4.6 ms/create at 1 node → 27.8 ms/create at 32, with nothing
shared but the mount.

## Landed this session (0.65.0)

- `xfs/xfs_inode.c` + `xfs/xfs_mxfs_dlm.{c,h}`: **`P132-CREATE` had been
  started under `is_dir` since sess132** — the one probe that could attribute a
  create's cost had never run on the file-create path that sets the ceiling.
  New knob `mxfs.create_cost_ms` (default 0, behaviour unchanged) starts the
  clock for file creates and prints any create reaching N ms. `pre_ms` is split
  into **`res_ms`** (trans reservation / log grant space), **`dlk_ms`** (parent
  dir cross-node grant), **`dia_ms`** (dialloc, carries the AG grant), stamped
  at call boundaries inside one function so they are mutually exclusive by
  construction. Line also gained `dir=`, `ag=`, `comm=`. `pre_ms` keeps its old
  meaning, so earlier readings stay valid.
- `tools/p132_attribute.py`: parses those lines into per-bucket stats plus a
  per-AG table, and **REFUSES to report when no input carried the probe**
  instead of printing zeros.
- `tests/suite/lib.sh`: `suite_plan <n>` declares a run's intended assertion
  count; breadcrumb, watchdog record and `finish()` all carry
  `planned=`/`notrun=`, and **a run that reaches fewer assertions than it
  declared can no longer report PASS.** Tests that declare no plan are
  unaffected. `tests/d384_terminal_record_guarantee.sh` still passes 13/13.
- `tests/suite/crash_consistency.sh`: declares 204 assertions at 32 nodes (200
  of them the durable verify). The failing row now reads
  `planned=204 notrun=203`.
- Ledger: filed **`D-CAW-WIRE-UNLOCK-100MS-CONTENDED-INODE-SLOT`** (major).
  The wire unlock alone is 15-97 ms with the drain already complete and
  separately accounted (`sw` 8-43 **micro**seconds vs `sx` 48-96 **milli**
  seconds). Leading hypothesis is the anti-CAS-storm backoff ladder
  (`mxfs_caw_unlock_backoff`, default ON) climbing on nearly every release
  because 26-28 peers churn waiter bits in the same slot — **but sess5 proved
  turning that off orphans slot bits and convoys the cluster, so do not.**
  Ledger now 199 records, 82 open.

## In flight at the relay boundary

Five chains, all `ppid=1`, all survive the relay:
`sess480_chain120` (NDR streak ×10), `124` (pace ladder), `125` (ICLUS matrix),
`126` (cc_private barrier), `127` (fastpoll A/B) — the last is the tail of the
gate queue.

**`tests/sess481_chain128_create_cost.sh s481a`** (launched 01:07:42Z) is gated
on chain 127's DONE (bounded to 6 h), then `rig_wait_free`, then it BUILDS
0.65.0, verifies `dlk_ms=` is actually in the linked `.ko` (srcversion cannot
prove that), freezes it to `tests/evidence/sess481_frozen_0650`, and runs
crash_consistency in **both** the shared and private arms with the probe armed
and the arm read back on all 32 nodes. Log:
`tests/evidence/sess481_chain128_create_cost_s481a.log`.

**Reading it:** `dlk_ms` should collapse between the shared and private arms.
Whatever is LEFT in the private arm's `total_ms` is the ceiling term.
`res_ms` ⇒ shared-log serialisation; `dia_ms` ⇒ AG contention (check the per-AG
table); `other_ms` large ⇒ the decomposition needs another boundary, and the
run says where.

## One correction NOT to make

GPT observed that "32 nodes over 25 AGs ⇒ 14 nodes share an AG" is not
derivable (the minimum in non-singleton AGs is 8). That is right as arithmetic
but **`D-RSYNC-LAP-PACE-AG-SHARING-388`'s 14 is MEASURED, not derived** — it
records 18 exclusive-AG nodes at 22-27 s and 14 shared-AG nodes at 34-50 s with
"set equality is exact". Do not "correct" that record. The caveat applies only
to predicting the mapping on a future run, which chain 128's `ag=` field now
measures directly.
