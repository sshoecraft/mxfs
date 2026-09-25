---
name: trap-a-harness-that-loads-mxfs-without-dyndbg-sees-no-probe-lines-and-reads-them-as-absent
description: TRAP (0.89.89+): P-probes are pr_debug. insmod without dyndbg=+p => every probe grep finds 0 and reads as 'did not happen', not as an error.
metadata:
  type: feedback
tags: [harness, logging, probes, dyndbg]
---

Since 0.89.89 every instrumentation line (`P12-...`, `P-AGIFC-MOD`, `PW-...`, `tauth: P-TAUTH-...`, untagged ALL-CAPS-HYPHEN tags like `EVICT-RING-FLAG`) is dynamic debug via `mxfs_probe*` (`pal/mxfs_probe.h`) or `mxfs_pal_log(MXFS_LOG_DEBUG, ...)`. They print only when enabled:

- `insmod mxfs.ko dyndbg=+p` (prep_node.sh and all 53 existing harnesses that insmod do this)
- `echo 'module mxfs +p' > /proc/dynamic_debug/control` at run time (packaged / modprobe nodes)
- `options mxfs dyndbg=+p` in /etc/modprobe.d for modprobe loads

**The trap:** a new lap that loads the module itself without `dyndbg=+p`, or a check on a packaged node, greps for a probe, finds 0, and reports the event as absent — the same false verdict class as the LOG_CONT newline bug. Before trusting a zero probe count, confirm probes are on: `grep -c '=p' /proc/dynamic_debug/control` for module mxfs lines, or look for any high-volume probe (P-AGIFC-MOD fires on every AGI free-count change).

Also: `dump_stack()`/`sched_show_task()` that belong to a probe are gated by `mxfs_probe_on()`, so a "stack follows" probe prints no stack either when probes are off.
