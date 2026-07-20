# MXFS Performance Benches

Performance harnesses for MXFS.  Distinct from `tests/` (correctness)
and `tests/decision_reproducers/` (per-spec-decision reproducers).
These run on real cross-node hardware and produce wall-clock numbers.

These scripts live in the source tree (per `CLAUDE.md` RULE 3) so they
survive reboots of the dev host or test cluster.

## Inventory

### `rsync_bench.sh`

The canonical metadata-heavy rsync workload, paired so the same
hardware runs against XFS native, mxfs.1, and v5/v6.  Used in
sess30 to measure the v5 D6 architectural ceiling (9+ min cross-node
parallel for what takes 3-4 s single-node).

**Invocation:**

```
bench/rsync_bench.sh <label> <hosts_csv> <iterations>
```

**Example (sess30 baseline):**

```
bench/rsync_bench.sh v5_v0_3_128_2node 192.168.120.186,192.168.120.182 3
bench/rsync_bench.sh v5_v0_3_128_solo  192.168.120.186                  3
bench/rsync_bench.sh xfs_native_2node  192.168.120.186,192.168.120.182  3
```

**Per-host workloads (hard-coded by IP — edit if cluster changes):**

| Host                | Source tree                       | Files | Notes                       |
|---------------------|-----------------------------------|-------|-----------------------------|
| 192.168.120.186 (test1) | /root/open-gpu-kernel-modules | 8137  | Linux kernel module source  |
| 192.168.120.182 (test2) | /root/element-web              | 4385  | JS/TS deeply nested tree    |

The two trees were chosen for shape diversity: open-gpu has many
medium-sized files in moderate depth; element-web has many small
files in deep nesting (the workload that historically corrupted
mxfs.1's dir_cache format-transition path).

**Per-iter output line format** (parseable):

```
ITER <i> <label> <host> <tree> wall_s=<f> files=<got>/<expected> match=<Y/N> md5=<Y/N> dmesg_hits=<n>
```

**Pass criteria** (for v6a H1):

- `wall_s` < 60 (strong: < 30) on the cross-node 2-host run.
- `match=Y` and `md5=Y` for every iter (correctness).
- `dmesg_hits=0` (no kernel-level errors).

### `rsync_bench_v6a.sh` (planned)

Wrapper around `rsync_bench.sh` that captures the v6a hypothesis
measurements:

- H1: bench wall time vs target.
- H2: cross-node lock-bounce rate per AG (requires kernel
  instrumentation to be in place).
- H3: read-class profile (stat vs dir-block vs data-extent).

Not yet built.  Build as part of v6a phase 3 measurement work.

## Methodology

Per the project's hypothesize → measure → develop → commit cycle:

1. State the hypothesis (e.g., "removing FUA-on-every-read drops the
   2-node bench under 60 s").
2. Capture the falsifying measurement in `bench.json` BEFORE making
   the change.
3. Implement the change.
4. Re-run the bench.  Record actual numbers.
5. Compare to the hypothesis.  Commit only if the hypothesis holds
   AND no correctness regression.

Output should always be appended to `/src/mxfs/bench.json` with a
sample entry like:

```json
{
  "label": "v5_v0_3_128_2node",
  "version": "0.3.128",
  "hosts": ["test1", "test2"],
  "iters": 3,
  "results": [
    {"host": "test1", "tree": "open-gpu", "wall_s": 540.0,
     "files_got": 6800, "files_expected": 8137,
     "match": "N", "md5": "N", "dmesg_hits": 0,
     "note": "killed at 9 min, never finished iter 1"},
    ...
  ],
  "ts": "2026-05-07T..."
}
```

## Why bench/ is in the source tree, not /tmp

See `/src/mxfs/CLAUDE.md` RULE 3.  Test cluster reboots regularly
(sysrq-b after wedged unmounts, cluster resets); /tmp evaporates.
Persistent bench harnesses live here.
