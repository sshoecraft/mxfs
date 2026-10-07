---
name: technique-time-a-module-function-on-a-live-host-with-a-private-ftrace-instance
description: TECHNIQUE: per-call latency of mxfs functions on a PVE host, zero kernel-log lines: ftrace instance/profiler; set the filter by line index, not names
metadata:
  type: reference
---

Measure every call of a module function (e.g. `mxfs_pal_drbd_cas_emulate`, one DRBD coordination swap; `mxfs_drbd_reg_put`, one bakery register write) on a live host without printing anything to the kernel log (the owner reads mxfs-prefixed log lines as spam) and without touching the global tracer:

```
T=/sys/kernel/tracing/instances/<name>
mkdir $T
echo 'fnA fnB' > $T/set_ftrace_filter      # only these, so no children are traced
echo 8192 > $T/buffer_size_kb
echo function_graph > $T/current_tracer   # FIRST
echo funcgraph-tail > $T/trace_options    # only AFTER the tracer: the funcgraph-* options
                                          # do not exist until function_graph is current
                                          # ("echo: write error: Invalid argument")
echo 1 > $T/tracing_on ... echo 0 > $T/tracing_on; cat $T/trace
echo nop > $T/current_tracer; rmdir $T
```
Durations are in us on the closing line `} /* fn [mxfs] */` or on a leaf line `fn [mxfs]();` (large ones print as `10329.68 us`, two decimals). Works on PVE 9's 6.17 (function_graph in instances needs a recent kernel; clyde's 6.8 is not known to support it). Both functions are listed in `available_filter_functions` as `name [mxfs]`. tests/pve_pair_write_bound.sh does this on both hosts of a pair and prints p50/p90/p99/max. Measured idle on the nested PVE pair: a swap 10-12 ms (three register writes 0.4-5 ms each).

**Many functions at once, over a long workload: `tests/pve_pair_profile.sh`.** ftrace's function profiler (`function_profile_enabled`, tables in `trace_stat/function<cpu>`: calls, total, mean, with sleep and callees included) on both hosts, snapshotted every INTERVAL_S, plus every call past SLOW_MS kept through function_graph with `tracing_thresh`. Traps measured 2026-10-06:
- **Writing NAMES to set_ftrace_filter costs ~7 s per name on pve1** (each is matched against every traceable function: 29 names took 196 s and overran the setup's ssh timeout). Write the names' LINE NUMBERS in `available_filter_functions` instead (`awk ... {print NR}`); that takes milliseconds.
- **The profile table hides every function whose mean is below `tracing_thresh` at read time** (function_stat_show), so zero the threshold while reading the table.
- A local `timeout` on ssh ends only the client: a setup left running on the host finished its 196 s filter write after the script had restored the tracer, and left pve1 tracing. Bound the remote command with its own `timeout` too.
