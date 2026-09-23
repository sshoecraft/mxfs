#!/usr/bin/env python3
"""tests/iomap_stale_race.py — make a buffered write's cached mapping go stale
underneath it, on purpose, and check afterwards that the data landed where the
file says it did.

    iomap_stale_race.py write  <path> <mb>        one write() call of <mb> MiB,
                                                  fsynced from a second thread
                                                  the whole time
    iomap_stale_race.py verify <path> <mb>        every page's stamp, cold

Runs ON the node.  (ledger D-NO-BUFFERED-WRITE-REVALIDATES-ITS-MAPPING-ON-THE-
KERNEL-UNDER-TEST, tests/iomap_revalidation_hook_reached.sh arm 2.)

THE SCHEDULE.  iomap_file_buffered_write maps the file once per iomap and then
copies folio after folio under that one mapping; for a fresh file the mapping
is a delalloc extent as long as XFS's speculative preallocation makes it, so a
single write() of a few hundred MiB runs a long way on one mapping.  The
second thread fsyncs the same file continuously.  Each fsync writes back the
folios dirtied so far, writeback converts their delalloc blocks to real ones,
and that conversion updates the inode's extent tree and bumps its sequence —
the number the mapping's validity_cookie was stamped from.  The writer's next
folio then asks iomap_valid, the cookie no longer matches, and iomap has to
remap before it writes.  Without the hook the writer would go on under the
stale mapping.  With it, MXFS logs P312-IOMAP-STALE (rate-limited) at every
refusal, and the lap counts those.

THE ORACLE.  Every 4 KiB page begins with its own page index as an 8-byte
little-endian stamp and is filled with 0x5a after it.  A write that landed
under a stale mapping — into blocks the mapping no longer names — shows up on
a cold read as a page whose stamp is not its index, or as zeros.  The verify
pass reads the file back page by page after the harness has remounted it and
prints CHECKED=<pages> BAD=<n> plus the first few bad pages.

OUTPUT (write):  WROTE=<bytes> WRITE_CALLS=<n> FSYNCS=<n> ELAPSED_MS=<n> RC=<n>
  WRITE_CALLS is the number of write() syscalls it took (1 is the shape the
  schedule wants; the kernel may return short, and a short return is reported
  and not hidden).  FSYNCS is how many fsyncs the racing thread completed while
  the write was in flight: 0 means nothing raced and the run measured nothing,
  which the caller must treat as VACUOUS.
"""
import os
import struct
import sys
import threading
import time

PAGE = 4096
FILL = b'\x5a' * (PAGE - 8)


def build(mb):
    n = mb * 1024 * 1024 // PAGE
    return b''.join(struct.pack('<Q', i) + FILL for i in range(n))


def write(path, mb):
    data = build(mb)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o644)
    fd2 = os.open(path, os.O_RDONLY)
    done = threading.Event()
    fsyncs = [0]

    def syncer():
        while not done.is_set():
            os.fsync(fd2)
            fsyncs[0] += 1

    t = threading.Thread(target=syncer)
    t.start()
    t0 = time.monotonic()
    wrote = 0
    calls = 0
    rc = 0
    view = memoryview(data)
    try:
        while wrote < len(data):
            n = os.write(fd, view[wrote:])
            calls += 1
            if n <= 0:
                rc = 5
                break
            wrote += n
    except OSError as e:
        rc = e.errno
    done.set()
    t.join()
    # the closing fsync is the durability the verify pass relies on; its
    # failure is part of the result and not swallowed
    try:
        os.fsync(fd)
    except OSError as e:
        rc = rc or e.errno
    ms = int((time.monotonic() - t0) * 1000)
    os.close(fd)
    os.close(fd2)
    print("WROTE=%d WRITE_CALLS=%d FSYNCS=%d ELAPSED_MS=%d RC=%d"
          % (wrote, calls, fsyncs[0], ms, rc))
    return 0 if rc == 0 else 1


def verify(path, mb):
    n = mb * 1024 * 1024 // PAGE
    bad = []
    checked = 0
    with open(path, 'rb', buffering=0) as f:
        chunk = 256
        for base in range(0, n, chunk):
            want = min(chunk, n - base)
            buf = f.read(want * PAGE)
            if len(buf) != want * PAGE:
                bad.append((base, 'short read %d' % len(buf)))
                break
            for i in range(want):
                idx = base + i
                off = i * PAGE
                stamp = struct.unpack_from('<Q', buf, off)[0]
                checked += 1
                if stamp != idx:
                    bad.append((idx, 'stamp=%d' % stamp))
                elif buf[off + 8:off + PAGE] != FILL:
                    bad.append((idx, 'fill'))
    print("CHECKED=%d BAD=%d" % (checked, len(bad)))
    for idx, why in bad[:12]:
        print("  page=%d %s" % (idx, why))
    return 0 if not bad else 1


def main():
    if len(sys.argv) != 4 or sys.argv[1] not in ('write', 'verify'):
        print(__doc__)
        return 2
    mode, path, mb = sys.argv[1], sys.argv[2], int(sys.argv[3])
    return write(path, mb) if mode == 'write' else verify(path, mb)


if __name__ == '__main__':
    sys.exit(main())
