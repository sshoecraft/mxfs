---
name: trap-a-kernel-upcalls-child-starts-with-fds-0-1-2-closed-so-a-helper-dies-on-its-first-print-and-its-first-open-becomes-stdout
description: TRAP (s101): call_usermodehelper gives the child kthreadd's empty file table — the helper died writing stdout, and its first os.open() would have BEE…
metadata:
  type: feedback
tags: [upcall, usermodehelper, fencing, helper, lu-reset]
---

# A kernel upcall's child has no standard streams, and that breaks a helper twice

Measured on test1, 2026-09-20 (0.89.30), while building the module-side
witnessed LOGICAL UNIT RESET. The module execs
`tools/mxfs_lu_reset_witness.py` through `call_usermodehelper(...,
UMH_WAIT_EXEC)` and then waits for the helper's report. Every invocation
timed out at the full 45 s bound with `reason=no-report-within-bound`, and
`P305-LURESET-NOEXEC` never fired — so the exec had SUCCEEDED and the helper
had then said nothing at all.

## The cause, proved directly rather than by reading code

The child of `call_usermodehelper` inherits the helper thread's file table,
in which descriptors 0, 1 and 2 are CLOSED. Run the same program that way by
hand and it reproduces exactly:

    python3 /root/mxfs_lu_reset_witness.py <args> /tmp/out.txt 0>&- 1>&- 2>&-
    EXIT=1 ; /tmp/out.txt was never created

    python3 /root/mxfs_lu_reset_witness.py <args> /tmp/out2.txt
    EXIT=1 ; full report written

CPython leaves `sys.stdout` as `None` when descriptor 1 is missing, so the
report function died on `sys.stdout.write(...)` before it reached the write
that actually mattered.

## The second failure is the dangerous one

With 0, 1 and 2 closed, the FIRST `os.open()` in the program is handed
descriptor 0 and the next gets 1. In this helper the first thing opened is
the block device it is about to reset — so a later write to what the runtime
still calls standard output would have landed **inside the LUN**. Nothing in
this program's own logic would have noticed.

## What to do in any program a kernel may exec

1. Before opening anything, fill 0, 1 and 2 (`os.fstat(fd)` to test,
   `/dev/null` + `dup2` to fill). This is not tidiness; it is what stops a
   device file from becoming a stream.
2. Write the load-bearing channel FIRST and the console second, each in its
   own try/except. A failure printing to a terminal that may not exist must
   never cost the report the caller is blocked on.
3. `UMH_WAIT_EXEC` succeeding says only that `execve` succeeded. It says
   nothing about the program surviving its first statement.

Landed in `tools/mxfs_lu_reset_witness.py` as `secure_fds()` plus a
channel-first report function; verified by
`tests/lu_reset_witness_probe.sh` (lap s101c, 16/16).
