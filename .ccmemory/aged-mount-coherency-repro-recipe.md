---
name: aged-mount-coherency-repro-recipe
description: Reproducible aging recipe for the aged-mount coherency failure: ~12 heavy runs on ONE mount then cache_coherency reads 653/654 on all 32 nodes; fresh…
metadata:
  type: reference
tags: [dirent-inode-type-mismatch, mount-degrades-with-use, cache_coherency, repro, aging]
---

# Aged-mount coherency failure — a concrete aging recipe

state.md's open item for D-MOUNT-DEGRADES-WITH-USE / D-DIRENT-INODE-TYPE-MISMATCH
said "the next attempt needs the heavy tests re-run after a storm on the CURRENT
build" but gave no recipe. Here is one that worked, sess26, v0.11.225.

## Recipe

On ONE mount, without re-prepping, run roughly:

- ~12 x `dirent_durability` @32/caw (each ~120 s), plus
- 2-3 full correctness boards (cache_coherency, strong_consistency, posix_multi,
  mmap_coherency, zero_silent_loss, dlm_fairness, dlm_membership,
  dir_reuse_coherency, crash_consistency), plus
- a few `node_responsive` / `kernel_health` passes.

Then run `cache_coherency` + `strong_consistency`.

## Result — the paired measurement

| mount state | cache_coherency | strong_consistency |
|---|---|---|
| **aged** (as above) | **FAIL 0/32** — `checks=654 passed=653 failed=1` on EVERY node, 47s/60s | **FAIL 17/32** — `checks=67 passed=65 failed=2` |
| **fresh prep**, same build, minutes later | **PASS 32/32 654/654, 26s** | **PASS 32/32, 3s** |

Same build (`46D1F995844F7703DE4302D`), same node count, same transport. The only
variable is mount age. That is the paired control the defect needed.

## Why this is NOT a timeout / straggler artifact

- The run COMPLETED (47s of a 60s budget) — it is not the 240s truncation mode.
- Exactly ONE check of 654 fails, and it fails on all 32 nodes identically —
  cluster-wide agreement on a wrong result, which is the durable-corruption
  shape, not a per-node flake.
- A SINGLE-node run of the same script on the aged mount passes 530/530, so it
  requires the 32-way concurrency.

## What it is not

Not caused by the sess26 changes: the immediately preceding fresh-prep run on
the SAME build passed 654/654 twice (26s, 28s), and the failure appears only
after aging. Also not the demoter work — `foreign_clear=0`, `contest=0`
throughout.

## Next step

Identify WHICH of the 654 checks fails. `cache_coherency` includes the
`rename_visibility` subtest that sess22 tied to
D-DIRENT-INODE-TYPE-MISMATCH (`rv content nodeN_after_1(exp=... got=)`), so
capture the failing check's text on an aged mount and compare against that
signature. Harvest per-node output at failure time — and scope kernel probes with
`journalctl -k`, never `dmesg` (dmesg retains ~112 s, shorter than the run).
