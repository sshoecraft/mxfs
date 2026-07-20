---
name: AAA-ccloopcc87-sess6-ringbuf-built-0.10.87-validating
description: sess6: built+deployed 0.10.87 (ring-buffer P135-PRSWEEP-CYCLE, 32-entry hist) to test1/test2, srcversion 259331EEDA95B8BB944D8E7. Validating now.
metadata:
  type: project
tags: [ccloop-cc87fed3, pr_sweep, build-0.10.87]
---

## Context
Continuation of sess5's work. Sess5 found a NEW bug during BUG3-fix validation: `mxfs_dlm_pr_sweep_work_fn`'s `sb->s_inodes` walk gets stuck on a self-referential post-eviction list entry, starving `drop_caches()` for 200s+ (softlockup). Sess5 shipped a v1 mitigation (0.10.86, single-first-pointer cycle check) but during validation found it INSUFFICIENT — a second softlockup hit ~30s after a clean v1 bailout, same signature, different inode (proves the stale node isn't always at walk position 1). Sess5 ended mid-implementation of a ring-buffer upgrade (32-entry history, checks current entry against ALL recently-visited pointers each iteration) and had NOT rebuilt/redeployed/validated it when the relay boundary hit.

## What sess6 found at start
The ring-buffer code (`MXFS_PRSWEEP_HIST_SZ=32`, `p135_hist[]` array, comment block citing "ccloop cc87fed3 sess5") WAS already fully written in xfs_mxfs_dlm.c (~line 26887-26999) — but `mxfs.ko`'s mtime (21:29:09) predated the .c file's mtime (21:41:04), proving the loaded module on test1/test2 (labeled 0.10.86 in cluster_reset_n.sh's ALL_OK check) was still running the OLD, proven-insufficient v1 detector. This would have made any validation in sess6 meaningless (testing the wrong binary) had it not been caught by checking mtimes before trusting VERSION/cluster_reset output.

## Action taken
- Bumped VERSION 0.10.86 -> 0.10.87 (real behavioral fix, not a no-op).
- `make modules` clean build, srcversion 259331EEDA95B8BB944D8E7, mtime now postdates the source edit.
- Deployed to test1+test2 via `cluster_reset_n.sh 2` — ALL_OK srcversion=259331EEDA95B8BB944D8E7 confirmed on both.

## Next step (in progress when this was written)
Re-run the EXACT repro: `dir_reuse_coherency fence_during_write fault_netpartition` @ 2/caw with live per-node `dmesg -T -w` streaming (see sibling memory `AAA-ccloopcc87-sess5-SEPARATE-BUG-prsweep-list-corruption-bailout` for the exact reusable repro command block). Confirm fault_netpartition PASSES; if P135-PRSWEEP-CYCLE fires, confirm instant clean bailout with NO softlockup following (ring buffer catching it wherever it occurs, not just position 1).

## Reminder for future sessions
**Always check mtime(mxfs.ko) vs mtime(source files) before trusting a VERSION number or cluster_reset "ALL_OK" line** — VERSION is manually bumped and can lag behind uncommitted source edits made near a context/relay boundary. This is a general gotcha, not specific to this bug.

## Also: criteria.json / matrix_check.py freshness trap (re-confirmed this session)
matrix_check.py (no --since) showed 1/caw, 4/caw, 8/caw, 16/caw, 32/caw all "17/17 PASS" at session start — but per-cell `iso` timestamps in criteria.json show most of those are STALE (8/16/32caw precond_readiness stamped 2026-07-12, i.e. TWO DAYS before this session, well before BUG3 or pr_sweep were even found). Only trust matrix_check.py output when passed `--since <build-epoch-iso>` for the CURRENT build. Do not shortcut the fresh sweep because a stale matrix_check.py summary looks green.
