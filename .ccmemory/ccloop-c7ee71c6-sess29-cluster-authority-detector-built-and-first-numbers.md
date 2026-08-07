---
name: ccloop-c7ee71c6-sess29-cluster-authority-detector-built-and-first-numbers
description: D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY detector BUILT (0.11.253): 2970 slots published with no write tenure, 68277 with no in-core inode, per boar…
metadata:
  type: project
tags: [mxfs, D-INODE-CLUSTER-PUBLISH-WITHOUT-AUTHORITY, detector, sess29, xfs_buf]
---

# sess29 — the inode-cluster authority detector, built and first numbers

Build **0.11.253** (`43F47B1AC4270AB1BA75DF9`). Census:
`tests/cluster_authority_census.sh [n] [full]`.

## Where the gap is

`pal/linux/xfs_buf.c`, the per-slot masking loop. Every other slot class is
guarded — FREE and NL are skipped, and a DIRECTORY slot is never written unless
logged this round (P56-CORESIDENT-DIR-SKIP). The branch commented
**"held non-dir inode -> write it"** writes unconditionally, from whatever bytes
the cached cluster buffer holds. That `continue` is the defect.

## First measurement — 32/caw, cache_coherency + dir_reuse + dirent_durability (all PASS)

| counter | value | meaning |
|---|---|---|
| writes | 9787 | cluster writes carrying >=1 passenger slot |
| unlogged_written | 73097 | **DENOMINATOR** — passenger slots written |
| **no_write_tenure** | **2970** | held only in PR — no write authority for bytes we publish |
| gen_mismatch | 33 | buffer image is a different incarnation than our in-core one |
| no_incore | 68277 | no in-core inode at all; no tenure can even be consulted |

Writer is `xfsaild` in every sample.

`unlogged_written` on its own is NOT a defect — ordinary preserved bytes, ~20 of
21 slots on every write. That is the sess27 counting trap; never report a
numerator without it.

## HONEST LIMIT — read this before claiming severity

The detector measures **AUTHORITY, not DIVERGENCE**. It proves the node had no
write tenure for those bytes. It does NOT prove each one differed from the
platter — rewriting identical bytes is harmless. Pair a nonzero numerator with a
plain-bio platter read (the `P207-COHERENT-TRUTH` primitive) before assigning a
loss count to this defect.

## The bug I shipped building it — cost 3 test cycles

```c
is_nl = (ip && ip->i_dlm_mode == MXFS_LOCK_NL);
...
if (!is_free && !is_nl) { /* "held non-dir inode" */ }
```

**`ip` can be NULL in that branch** — `is_nl` requires `ip`, so `!is_free &&
!is_nl` admits `ip == NULL`. The comment describes the intent, not the
condition. I dereferenced `ip` there: a NULL deref in the writeback path. It
killed ONE NODE PER RUN on three consecutive runs, and the symptom was
thoroughly misleading:

- `cache_coherency 0/32 NO_TERMINAL_RECORD` (all 32 nodes, not the one that died)
- next-boot `mount` hung in `mxfs_disklock_claim_slot` -> `bdev_pipelined_read`
  with `sd 4:0:0:0: reservation conflict`, which reads exactly like a storage/PR
  problem
- the probe printed **zero** lines, because the oops came before any print

I nearly blamed the rig (there IS a real known spurious-power-cycle issue) and
`scripts/cluster_reset.sh` — which is the OLD 2-NODE harness and cannot reset the
32-node rig (it looks for `/mnt/mxfs-src/mxfs.ko`); use
`MXFS_FORCE_PREP=1 ./run.sh 32 caw prep_cluster`.

**Lessons:** a "node lost its mount / 0/32 NO_TERMINAL_RECORD" after a
kernel-side change is your change until proven otherwise — check
`journalctl -k -b -1` for the PREVIOUS boot before believing the rig. And the
`ip == NULL` case here is not a nuisance to skip: it is the worst case, and it
is 93% of the exposure.
