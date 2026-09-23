---
name: trap-io-uring-reaches-iocb-nowait-on-any-o-nonblock-file-even-without-fmode-nowait
description: TRAP (D-0532, 0.87.1): MXFS sets no FMODE_NOWAIT so RWF_NOWAIT gets EOPNOTSUPP, yet io_uring issues IOCB_NOWAIT on any O_NONBLOCK fd → IOMAP_NOWAIT p…
metadata:
  type: feedback
---

# io_uring reaches IOCB_NOWAIT on any O_NONBLOCK file, whatever f_mode says

**What bit:** `preadv2/pwritev2(RWF_NOWAIT)` against MXFS returns `EOPNOTSUPP`, because `xfs_file_open` never sets `FMODE_NOWAIT`. It is tempting to conclude from that that every `IOCB_NOWAIT` / `IOMAP_NOWAIT` branch in the tree is dead. It is not. io_uring (`io_file_get_flags`) marks a file nowait-capable when it has `FMODE_NOWAIT` **or** was opened `O_NONBLOCK`, and then issues the first attempt of every read or write with `IOCB_NOWAIT`. If that attempt returns `-EAGAIN`, it reissues the operation from an io-wq worker without the flag.

**How it showed:** `xfs_ilock_for_iomap`'s nowait arm took the ILOCK with no DLM begin, and its callers ran the DLM end. A raw io_uring driver (`tests/d0532_uring_nowait.c`) on an `O_NONBLOCK` + `O_DIRECT` fd produced 184 `P71-UNDERFLOW` per 200 reads on 2/tcp. The control, with no `O_NONBLOCK`, produced 0.

**Apply:**
- To exercise a nowait path from userspace, use io_uring on an `O_NONBLOCK` fd. `RWF_NOWAIT` won't get there.
- Userspace success proves nothing about which path ran, because io_uring retries from a worker. Read a kernel counter.
- On the nodes' 6.8 kernel, io_uring's *buffered* write nowait needs `FMODE_BUF_WASYNC` in `f_mode`, so that arm is unreachable there. Only the O_DIRECT arms are reached.
- A lock-pairing audit that scores "caller-released" helpers as INFO misses exactly this class. The audit now fails them unless they carry an explicit contract.
- `P71-UNDERFLOW` is print-budgeted at 300 per load. Read the exact `p71_underflows` counter (write 0 to reset it) instead of counting lines.
