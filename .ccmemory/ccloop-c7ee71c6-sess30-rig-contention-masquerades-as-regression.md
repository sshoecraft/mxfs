---
name: ccloop-c7ee71c6-sess30-rig-contention-masquerades-as-regression
description: Node hangs + growing prep times on IDENTICAL code = clyde host contention from unrelated workloads, NOT an MXFS regression. Check loadavg first.
metadata:
  type: project
tags: [mxfs, rig, sess30, false-regression, RULE-0]
---

# sess30 — a "regression" that was host contention

## Symptom

On build 0.11.265, four consecutive 32/caw runs failed with:

- one or more nodes losing their mxfs mount mid-run,
- `NO_TERMINAL_RECORD=32` on barrier criteria (one rank can never reach a
  barrier, so EVERY node reports it),
- `pre-assert: mxfs not mounted/readable on testN` on the next criterion,
- **no panic, no Oops, no EFSCORRUPTED, no withdraw** on any node,
- the harness power-cycling the dead node (`run.sh:433`, virsh destroy+start).

Builds 0.11.261/262/263 had passed the same three criteria cleanly earlier in
the same session, so this read as a clean regression window (0.11.264 was never
run; 0.11.265 added only a `uint16_t` field and nine single stores, all inside
already-braced blocks — semantically inert).

## The tell, and the actual cause

**`prep_cluster` wall on IDENTICAL code, in session order: 72s, 73s, 77s, 81s,
104s, 160s.** Monotonic degradation with no code change between several of those
points. A build cannot do that.

    $ cat /proc/loadavg          -> 17.98 19.38 18.34   (8 CPUs)
    $ free -g                    -> 94 total, 74 used, 1 free, 20 available
    $ ps -eo pcpu,pmem,comm --sort=-pcpu | head
       333%  Wow.exe
       166%  python3
       122%  tesseract
        90%  worldserver
        18%  VLLM::Worker_TP

Clyde was running unrelated user workloads. 32 test VMs on 8 heavily contended
cores with ~20 GB available RAM get starved, block on I/O to the SCST backing
file (`/home/steve/disk.img`, on an 84%-full NVMe), go unresponsive, and the
harness power-cycles them.

## Rule for future sessions

**Before diagnosing any node hang, pace failure, or "regression" that shows up
as unresponsive nodes with NO kernel error signature, check `/proc/loadavg` and
`ps --sort=-pcpu` on clyde.** Specifically suspect contention when:

- prep/mount times grow across a session on unchanged code,
- nodes die with no panic in `/var/log/libvirt/qemu/testN-serial.log`, no
  pstore entry, and no corruption/withdraw markers in dmesg,
- the failure moves between criteria run-to-run instead of reproducing on one.

RULE 0 timeout budgets are performance ASSERTIONS. They are only meaningful on
an unloaded host — under external contention a budget overrun measures the
host, not MXFS. Record the load with the result, or the reading is worthless.

Do NOT kill the user's workloads. Report the contention, do rig-independent
work (design, code, log analysis of already-captured clean runs), and re-run
timing-sensitive criteria when the host is quiet.
