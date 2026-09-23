---
name: trap-a-dlm-flag-a-wrapper-drops-on-one-engines-branch-leaves-a-whole-escalation-inert-and-a-negative-cache-must-not-outlive-the-release-it-asked-for
description: TRAP (D-0939, 0.87.13): inode_reserve_try passed NOQUEUE alone on TCP and dropped demand — the allocator's DEMAND escalation never BASTed the holder;…
metadata:
  type: feedback
tags: [dlm, tcp, dialloc, demand, cooldown, dir_reuse_coherency]
---

# TRAP: a per-engine wrapper can drop a flag on one branch, and the caller's escalation reads as working

Context: D-DIR-REUSE-COHERENCY-2NODE-TCP-BARRIER-TIMEOUT-ROUND2-BOTH-NODES-0939, fixed 0.87.13 (sess52 of run 09d46fe5).

## What bit
- `mxfs_v5_dlm_inode_reserve_try(ctx, ino, demand, gres)` had two branches: CAW passed `NOQUEUE | (demand ? DEMAND : 0)`, TCP passed `NOQUEUE` only. The allocator (`xfs_ialloc.c` failed-sweep backoff) set `rs->demand=1`, its `mxfs_resv_stat_demand` counter climbed, the code comments promised "a sticky revoke so the holder is told to let go" — and on TCP nothing ever reached the holder. The 0.75.42 TCP DEMAND fix (demand_collect_holders/demand_fire) was real; this caller simply never asked for it.
- The sess523 trap (`trap-mxfs-lkf-demand-was-caw-only-tcp-noqueue-deny-never-basts-the-holder`) said "check a DLM flag in BOTH engines". The remaining hole was the WRAPPER between the caller and the engines: grep every `mxfs_v5_dlm_*` wrapper that takes a flag/bool for `ctx->dlm` vs `ctx->dlm_caw` branches passing different flag sets.
- Signature in the logs: requester prints `P-DIALLOC-SWEEP-RETRY ... re-sweeping with DEMAND` and dozens of `P74-GRANT ino=X mode=NL status=1` (status 1 = MXFS_ERR_DEADLOCK deny) while the holder node's ring is silent on those inodes and `P-DEMAND-BAST` never appears on the master. A caller-side demand count is NOT evidence the wire carried it — count `P-DEMAND-BAST` on the master.

## Second half: the negative cache outlived the release
- Even with DEMAND delivered, a refused candidate went on the 500-1000 ms silent-contention cooldown, while the demanded holder's corpse release lands in ~10 ms (measured: the next queued EX on such a number handed off in 10 ms). Fix: a named `MXFS_DEMAND_COOL_MS` class (40-80 ms). Rule: a cooldown after a demanded refusal is bounded by the PEER's release fence; after a publication-pending refusal by a LOCAL write; only a silent refusal waits on nothing and earns the long ring.

## How it presented (so the next reader recognises it)
- dir_reuse_coherency 2/tcp PASSing at 101 s/120 s with rank 1 `P36-RETRY ino=<dir> mode=PR comm=stat` twice per round (retries_left 59, 58) and `P36-STACK` x8 (the per-boot cap) — read at first as "51 s of stack dumps on one inode"; it was 8 rounds x 2 s. The asymmetry (all on rank 1) is role: rank 1 does the rm -rf and holds the freed numbers; rank 2's allocator stalls; rank 1's stat waits behind rank 2's dir EX.
- Holder-side tell on the dir: `P70-BP ino=<dir> ENTRY ... held_ms=2345 tops=3` — a 2.3 s EX tenure with 3 ops is a holder BLOCKED, not a holder busy. Then look at what its `exh_pid` was doing: `P1-AGWAIT` / `P-DIALLOC-RESV-EXHAUST` lines under the same comm.
- Two clocks: `dmesg -T` on these VMs ran ~1 s behind the probes' `realns=` field. Order events by `realns` (or ring position), never by the `-T` second.

## Verification shape that closed it
Fresh prep, 3 laps: P36-RETRY 23 -> 0 (both nodes), rounds in the 100 s box 13 -> 17/18, dir EX tenure max 2345 -> 339-565 ms, P-DEMAND-BAST 0 -> ~160/lap on each node. The row now emits `rounds= p36_retry= ... dialloc_sweep_retry=` in measured= (SUITE_MEASURED_EXTRA in tests/suite/lib.sh) so a stalling PASS is visible on the board.

## Left measured, not fixed
Rank 2 still runs 55-72 failed sweeps per lap and holds the dir up to ~0.5 s per round from the SILENT first sweep's 500-1000 ms cooldown. First-probe DEMAND for inode reservations (Astra 2026-09-18: a reasonable policy, land and measure separately, inode-only, never for the AG discovery pass) would remove it.
