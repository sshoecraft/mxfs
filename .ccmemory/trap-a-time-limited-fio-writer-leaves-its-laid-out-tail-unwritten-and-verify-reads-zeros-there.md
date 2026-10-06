---
name: trap-a-time-limited-fio-writer-leaves-its-laid-out-tail-unwritten-and-verify-reads-zeros-there
description: TRAP (0.90.70): fio time_based writer + later verify_only: unwritten tail of the laid-out file read as "got pattern '00'"; bad offset = exactly io_by…
metadata:
  type: feedback
tags: [fio, verify, test-design, trap]
---

A fio write job with `--time_based --runtime=N` on a `--size` file lays the whole file out first, then writes only as far as N seconds allow. A later `--verify_only` (or any whole-file check) reads the unwritten tail as zeros and reports bad blocks: `fio: got pattern '00', wanted 'e0' ... verify failed at file .../dio.0.0 offset 232783872`.

Before calling it corruption, compare the first bad offset with the job's `write.io_bytes` in the fio JSON: on the nested PVE pair (0.90.70) they matched exactly (222.0 MiB and 175.0 MiB). It was the test, not the filesystem.

How to apply: for a write load whose data is checked afterwards, make every writer write its whole file (size-based, `--loops` for duration), or verify only `io_bytes` per file. tests/pve_pair_write_bound.sh does the former; `verify_pattern=%o` makes every pass write identical content, so loops and verify_only agree.
