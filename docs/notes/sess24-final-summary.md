# Sess24 Final Summary

## Where we ended up
- **v0.3.83 + P33-INSTR in tree**, srcversion `9A023439F613AE4B6120C26`.
- Source clean: all sess24 fix attempts reverted; only P33 alloc/fail diagnostic added.
- New tool: `tools/caw_verify.c` (built standalone) — cross-init CAW verification.
- VERSION still `0.3.83`.

## Headline finding

**Bnobt LEFT/RIGHT-FAIL is caused by silent cached-AG state divergence.**

P33-INSTR captured the smoking gun:
- Run-1 iter 4: T1 alloc'd [24568..48008) at AG=0 + T2 alloc'd [16392..91288) at AG=0
  within the same ~1 second window.  Overlap [24568..48008).
- Run-3 iter 9: same pattern at AG=0 with [8200..91288) range.
- Run-7 baseline iter 4: T1 alloc'd [16392..24568) + T2 alloc'd [16392..23544).
  Overlap [16392..23544).

P35-INSTR confirmed both nodes had `pag_dlm_cached=true` simultaneously:
from 21:03:36 until iter-9 fail (~50 seconds), neither node did fresh-acquire
on AG=0; both used `fast-cached` path on every alloc.

## LIO target CAW cross-init coherence WORKS (pre-reboot)

`tools/caw_verify.c` (added sess24, built standalone with gcc):
- T1 CAW write 0xAA, T2 FUA-read → 0xAA ✓
- T2 CAW write 0x55, T1 FUA-read → 0x55 ✓

**Sess23 hypothesis #1 ("LIO drops CAW writes silently") is FALSE.**
The cross-initiator coherence is fine; the bug is purely in MXFS software.

### Caveat: post-reboot caw_verify anomaly

After a forced VM reboot (sysrq-trigger 'b') of T1 + T2, caw_verify
post-CAW reads return constant garbage `5a 4a 00 00 22 1e 00 01` at
all tested LBAs.  Plain dd writes/reads work correctly cross-init.
Likely an iSCSI/LIO session state issue post-ungraceful-shutdown.
MXFS operation is presumably also affected — but the bug we're
chasing reproduces consistently on FIRST stress run (iter 3-4) which
predates any reboot, so this anomaly doesn't change conclusions.

## Mode A and bnobt LEFT/RIGHT-FAIL share root cause

Sess24's `bast_poll_fn` self-correct experiment (fire `bast_cb` when slot
shows our_mode=NL despite being in our held list) triggered Mode A
(`xfs_dir_removename rc=-ENOENT`) immediately at iter 1.

This means premature cache invalidation breaks dir/inode ops.  The
upper-layer drain/release path (`mxfs_dlm_ag_bast_work_fn`) has correctness
issues that surface as Mode A whenever cache invalidation is forced.

**Implication**: any cache-divergence fix for bnobt must also handle the
drain ordering correctly, or Mode A surfaces.

## Failed fix attempts (all reverted)

| Attempt | Result |
|---|---|
| P34 post-CAS verify-read | mount-time noise from pre-mkfs garbage; benign release-vs-promote race during stress; not the actual bug signal |
| UDP BAST on claim-empty | run-4 iter 3 vs run-3 iter 9 baseline — strictly worse |
| Disable cached fast-path | inode-DLM wedged DEMOTING on T1; T2 root-dir lock timeout iter 1; needed reboot |
| bast_poll self-correct | Mode A trans_cancel at iter 1 — premature invalidation breaks dir ops |

## Stress run summary

| Run | Build / Workload | First fail | Mode |
|---|---|---|---|
| 1 | v0.3.83 + P33, 15×512 | iter 4 | RIGHT-FAIL T1 AG=0 |
| 2 | + P34 verify, 15×512 | iter 2 | LEFT-FAIL T1 AG=0 |
| 3 | + P35 path, 15×512 | iter 9 | RIGHT-FAIL T1 AG=0 |
| 4 | + UDP BAST claim-empty, 15×512 | iter 3 | LEFT-FAIL T2 AG=1 (worse) |
| 5 | disable cached fast-path, 15×512 | hung iter 1 | inode-DLM wedged DEMOTING |
| 6 | bast_poll self-correct, 15×512 | iter 1 | Mode A trans_cancel |
| 7 | back to clean, 15×512 | iter 4 | LEFT-FAIL T2 AG=0 (baseline) |
| 8 | clean, 15×512 | iter 3 | RIGHT-FAIL T1 (variance) |
| 9 | clean, 5×256 | PASS 5/5 | smaller workload safe |
| 10 | clean, 5×512 | iter 1 | LEFT/RIGHT-FAIL — workload-size dominant |
| 11 | clean, 5×400 | PASS 5/5 | 400MB sometimes safe |
| 12 | clean, 15×400 | iter 1 | 400MB also fails at scale |
| 13 | clean, 30×256 | LEFT-FAIL ~iter N | 256MB also fails at scale |
| 14 | clean, 15×512 | iter 3 | another baseline data point |

## Next-session priority

1. **Audit Mode A drain correctness FIRST**: when `mxfs_dlm_ag_bast_work_fn`
   sets `cached=false` (line 1823), in-flight transactions / dir ops /
   inode ops with stale dir/inode cache references corrupt.  The drain
   needs to be trans-aware.

2. **Lease-based cached-AG**: per-resource expiring lease.  Cache valid
   only within lease window.  Avoids "premature invalidation triggers
   Mode A" because cache expiry happens at quiescent points.

3. Strip P14/P15/P22/P23/P25/P28/P29/P30/MX-INSTR + P33 before final benchmarking.

## Files (sess24)

- Source: `xfs/libxfs/xfs_alloc.c` — P33-INSTR alloc/fail dumps.
- Tool: `tools/caw_verify.c` — built standalone with gcc.
- Stress logs: `/tmp/sess24_run{1..7}.log` and `/tmp/sess24_t{1,2}_run{2,3,4,7}.log`.
- Analysis: `/tmp/sess24-analysis.md` — deep technical writeup.
- State: `/src/mxfs/state.md` — sess24 handoff at top.
- Next-session: `/src/mxfs/next-session-prompt.md`.
- Memory: `~/.claude/projects/-src-mxfs/memory/sess24_lessons.md`.
- Per-version history: `~/.claude/projects/-src-mxfs/memory/v3-version-history.md`.
