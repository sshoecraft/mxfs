---
name: AAA-ccloopcc87-sess1-FIX3-resource-scoped-orphan-clock-VALIDATING
description: ccloop cc87fed3 sess1: 3rd bug in fence_during_write@8/caw chain fixed (resource-scoped orphan clock, build 0.10.80 06C2F26F). Validating now (fdw_re…
metadata:
  type: project
---

## Context

Criterion: "1/2/4/8/16/32 node caw dlm multipath test working 100%". Entire matrix
is PASS in criteria.json EXCEPT `fence_during_write@8/caw` (FAIL "aborted" at
2026-07-13T05:18:20Z) — the SOLE remaining gap. This is a chain of THREE distinct
bugs found across sessions, discovered via an interactive (non-ccloop) session
040c9ad8 that ran 2026-07-13 ~05:00-12:23Z and exited without saving to memory —
I (ccloop cc87fed3 sess1) reconstructed its findings from the raw transcript
(`/home/steve/.claude/projects/-src-mxfs/040c9ad8-3bad-4f4e-810d-7db0acf54b36.jsonl`)
and continued the work.

## Bug #1 — i_dlm_demoter/irele ordering (soft lockup) — FIXED, VALIDATED
See memory `ccloop703f-sess1-ROOT-FIXED-bast-demoter-cleared-before-irele`. Fixed
0.10.76 (srcversion EAB3334D0AA6A8139C0E838). 15/15 repro iters clean.

## Bug #2 — boot-relative vs wall-clock timestamp — FIXED, VALIDATED
`mxfs_pal_time_ms()` is boot-relative (`ktime_get_boottime_ns()`), used for
`dlm/dlm_caw.c`'s CAW fair-handoff anti-starvation ticket (`yield_set_ms`) which
is WRITTEN by one node and READ/aged by a DIFFERENT node — independently
power-cycled nodes have wildly different boot-uptime origins, so `yt_age = now -
yield_set_ms` (unsigned) silently underflows, making a fresh ticket look
instantly stale (`P-YT-STALECLR` fired 83-251x/node). Fixed via new
`mxfs_pal_time_real_ms()` (wall-clock, `pal/pal.h` + `pal/linux/kern.c` +
`pal/linux/user.c`), used for the 2 `yield_set_ms` write sites + 2 read/age sites
in `dlm_caw.c`. VALIDATED: P-YT-STALECLR dropped from 83-251/node to 0 in the next
repro. Doc: `.claude/awareness/subsystems/pal.md` has a Known Pitfalls entry.
Landed by build 0.10.78 (srcversion 7B591803CF2135C61485ADD).

## Bug #3 — VFS inode eviction wipes the wall-clock anti-starvation escapes — FIX BUILT, VALIDATING NOW
After bug #2's fix, `fence_during_write@8/caw` STILL timed out (RUN_EXIT=124), but
`P-YT-STALECLR` was 0 (bug #2 confirmed fixed) — a DIFFERENT, narrower failure: a
PR (read, mode=3) waiter starves ~360s and self-fences (`DLM inode lock
unrecoverable`).

### Root cause (RULE-4 PROVEN via direct instrumentation, not guessed)
`mxfs_dlm_bast_process` (`xfs/xfs_mxfs_dlm.c`) has TWO wall-clock "orphan-strand"
escape timers meant to force-release a resource this node locally released
(mode==NL) but whose CAW disk grant it still nominally holds ("orphan_live" shape,
driven by `p_rel_gen = mxfs_v5_dlm_inode_grant_gen(...)`, itself CORRECTLY
DLM-layer-sourced, not inode-cached):
- `i_dlm_orphan_since_ns` (P15H-STRAND-TIMEOUT, 3s default `mxfs_caw_orphan_force_ms`)
- `i_dlm_bast_starve_since_ns` (P15H-PEER-STARVE-TIMEOUT, survives LOCAL mode churn
  by design — added specifically because the first clock gets defeated by local
  re-acquire cycling)

Both are **fields on `struct xfs_inode`** (`xfs/xfs_inode.h`). PROVEN (added a new
diagnostic field `i_dlm_init_seq`, a global-atomic-counter stamp set in
`mxfs_dlm_inode_init` — i.e. "which in-core instantiation is this" — and printed
it + recomputed ages alongside the existing P15-REL-ABORT dmesg line): for the
SAME `ino` (131, the hot shared dir), `init_seq` DIFFERS across "consecutive"
(in dmesg-content terms) P15-REL-ABORT samples, and each `init_seq` change
co-occurs with the age clocks resetting to ~0 — i.e. **the in-core VFS xfs_inode
is being evicted and reinstantiated** (icache reclaim, driven by the
fence_during_write hot-dir create/unlink storm's inode churn) **faster than the
3-second force-release threshold can accumulate**, silently wiping BOTH escape
timers (via `mxfs_dlm_inode_init`'s zeroing, `xfs/xfs_mxfs_dlm.c` ~23198/23221)
every time. This is the SAME defeat-class bug as the local-mode-churn problem the
2nd clock was built to fix, just via inode LIFECYCLE churn instead of MODE churn —
neither timer nor the same-gen 280-strike counter (`i_dlm_orphan_gg`, ALSO
per-inode) can ever accumulate 3s/280 samples of continuous observation.
`mxfs_dlm_evict()` was checked too: its early-return on
`state==NONE && mode==NL` doesn't even look at `i_dlm_bast_pending`, so the
in-flight retry's bookkeeping is dropped with no log — but did NOT change this
function (see "Fix considered and rejected" below).

### Fix (built, not yet validated) — resource-scoped clock, NOT per-inode
Moved BOTH wall-clock trackers off the xfs_inode and into a NEW, dedicated,
resource-keyed (fnv1a hash of `struct mxfs_resource_id`, same key as CAW's
existing `grant_meta` table) direct-mapped table in `dlm/dlm_caw.c`/`.h`:
`ctx->orphan_clock[MXFS_CAW_ORPHANCLOCK_SIZE=4096]` — survives VFS inode eviction
entirely (not stored on the xfs_inode) AND survives local re-acquire churn
(same-resource claims preserve the bucket; only a genuine foreign-resource
collision resets it, rare at 4096 buckets for a tiny "currently orphan-live"
working set).

**Critical gotcha caught before deploy**: `mxfs_dlm_bast_process` holds
`ip->i_dlm_lock` (a real kernel `spinlock_t`, taken at
`xfs_mxfs_dlm.c:12046`, continuously held through the whole orphan-clock decision
block) at the exact point these clocks are read/written. CAW's EXISTING
`grant_meta` table is protected by `grant_meta_lock`, a `mxfs_mutex_t`
(`mxfs_pal_mutex_lock` wraps a real `mutex_lock()`, CAN SLEEP) — reusing it would
be scheduling-while-atomic. Do NOT store new orphan-clock fields inside
`grant_meta`'s struct even if using a different lock for them — that's a
cross-lock data race on the same memory (both `caw_release_mark` and
`caw_grant_seq_prebump` do a wholesale `memset(&ctx->grant_meta[h], 0, ...)` on
bucket-claim, under the MUTEX, which would race a spinlock-protected
reader/writer of overlapping fields). Fix: added a brand-new PAL primitive
`mxfs_spinlock_t` / `mxfs_pal_spinlock_{create,destroy,lock,unlock}` (`pal/pal.h`
+ kernel impl in `pal/linux/kern.c` wrapping real `spinlock_t` + user impl in
`pal/linux/user.c` wrapping `pthread_mutex_t`, mirroring the existing
`mxfs_mutex_t` pattern exactly), and gave the new `orphan_clock` table its OWN
`orphan_clock_lock` (spinlock, never sleeps) — fully independent of `grant_meta`.

New API surface (all interactive-session-2026-07-13-dated in comments):
- `dlm/dlm_caw.c/.h`: `mxfs_dlm_caw_orphan_clock_get/set(ctx, resource, starve)`
- `dlm/v5_mount.c/.h`: `mxfs_v5_dlm_inode_orphan_clock_get/set(ctx, ino, starve)`
  (ino-keyed wrapper, CAW-only — 0/no-op on TCP, mirrors
  `mxfs_v5_dlm_inode_grant_gen`'s pattern exactly)
- `xfs/xfs_mxfs_dlm.c` (~line 12193 in `mxfs_dlm_bast_process`): the force-decision
  logic now reads/writes the resource-scoped clock via these wrappers instead of
  `ip->i_dlm_orphan_since_ns`/`i_dlm_bast_starve_since_ns`. The OLD per-inode
  fields are LEFT IN PLACE, still updated exactly as before, but now
  **diagnostic-only** (still printed as `age_orph_ms`/`age_starve_ms` in the
  P15-REL-ABORT dmesg line for A/B comparison — expect them to keep resetting,
  harmlessly, while the NEW resource-scoped clock should not).

### Fix considered and rejected
Directly fixing `mxfs_dlm_evict()`'s early-return gap (skip disk release when
`bast_pending` true) was considered but REJECTED for this pass: `evict()` doesn't
set `i_dlm_demoter = current` before doing its work, so calling
`mxfs_dlm_bast_process` (or replicating its logic) from there risks the SAME
self-deadlock class as Bug #1 (the demoter-exemption re-entrant-ILOCK protection
wouldn't apply). The resource-scoped-clock fix is a pure bookkeeping change (no
control-flow/locking changes to the release pipeline itself) and directly targets
the PROVEN mechanism, so it was strictly lower-risk. If bug #3's fix doesn't fully
resolve fence_during_write, revisit evict() next — but with the demoter-exemption
added correctly this time.

### Instrumentation added (kept, useful going forward)
- `xfs/xfs_inode.h`: new `i_dlm_init_seq` field (diagnostic).
- `xfs/xfs_mxfs_dlm.c`: `mxfs_dlm_inode_init` stamps it from a file-local atomic
  counter; the P15-REL-ABORT pr_warn now also prints
  `init_seq=%u age_orph_ms=%llu age_starve_ms=%llu`.

## Build chain this session
0.10.78 (7B591803, inherited, has bug#2 fix) → 0.10.79 (233778DFD16543A887C8347,
diagnostic instrumentation only, used to PROVE bug #3) → **0.10.80
(06C2F26F678BBC77FE670AF, bug #3 fix — resource-scoped clock)**, kernel build
clean (`make modules`), new PAL spinlock compiles clean in isolation
(`gcc -Wall -Wextra -c -Ipal -Iinclude pal/linux/user.c` → zero warnings). Could
NOT verify `dlm_caw.c` compiles standalone in user-mode (no working Makefile
target found for that; pre-existing undeclared-symbol errors — `GFP_NOFS`,
`mxfs_caw_fair_handoff` — appear environmental/pre-existing to my ad-hoc gcc
invocation, not caused by my diff, but this is UNVERIFIED, not proven clean).

## State AS OF THIS WRITE
- Cluster: all 8 test nodes (test1-8) healthy, build 06C2F26F deployed via
  `tests/repro_fdw_instrumented.sh` (which does its own `run.sh` prep/mkfs/mount).
- **`fdw_repro3` LAUNCHED 2026-07-13T13:35:28Z**, pid printed in that turn's tool
  output (background nohup+setsid). Budget ~1720s (~29min); expect done ~14:04Z.
  Log: `/tmp/claude-1000/-src-mxfs/e5590c3e-cda7-43fa-9e59-e0fd6fda11ff/scratchpad/fdw_repro3/run.log`
  (+ `sample.log`, though the sampler itself has a KNOWN pre-existing bug — see
  below — so don't expect periodic samples, just the final tail).
- **Next action**: check `fdw_repro3/run.log` for `RUN_EXIT=` — if 0 (or PASS on
  fence_during_write specifically) and dmesg across all 8 nodes shows 0
  UNRECOVERABLE / 0 D-state / P15H-PEER-STARVE-TIMEOUT or P15H-STRAND-TIMEOUT
  firing with resource-scoped `age_*` climbing correctly instead of resetting →
  bug #3 confirmed fixed. Run it again (2-3 clean iters ideally, this class of
  bug hits ~1-in-2) before declaring victory, per RULE 4.
- Known pre-existing harness bug (NOT yet fixed, low priority): `bash` bare
  `wait` in `tests/repro_fdw_instrumented.sh`'s sampler loop blocks on ALL
  background jobs in the shell — including the main `run.sh` job itself (also
  started with `&` in the same shell) — so it only ever captures ONE sample
  round at launch instead of periodic ones. Harmless to correctness (just means
  no mid-run telemetry; pull dmesg directly post-completion instead). Fix if
  convenient: track PIDs explicitly (`wait "${SAMPLE_PIDS[@]}"`) instead of bare
  `wait`.

## After fence_during_write@8/caw is clean
Per `AAA-ccloopff21-sess1-32caw-COMPLETE-17of17` and
`ccloop703f-sess1-ROOT-FIXED-bast-demoter-cleared-before-irele`: run the FULL
fresh single-build revalidation sweep on THIS FINAL build via
`scripts/revalidate_cell.sh` at every node count (1,2,4,8,16,32), then
`python3 scripts/matrix_check.py --since <this-build-epoch>` (no --nodes filter)
must show ALL of 1/2/4/8/16/32 @ caw as 17/17 PASS (fresh) before writing YES to
`/src/mxfs/.ccloop/runs/cc87fed3-3278-4883-86ac-a3c1b5ddfac8/criteria-met`.
`MXFS_DEV=/dev/mapper/mpatha` always (multipath is part of the criterion). No
`MXFS_EXTRA_MODARGS` (ship config — `caw_fair_handoff` defaults to 1 already per
its module_param default; verify this hasn't regressed anything at lower N).
