---
name: technique-time-a-module-function-on-a-live-host-with-a-private-ftrace-instance
description: TECHNIQUE: per-call latency of an mxfs function on a PVE host, zero kernel-log lines: tracefs instance + set_ftrace_filter + function_graph, then fun…
metadata:
  type: reference
tags: [ftrace, latency, drbd, technique]
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
