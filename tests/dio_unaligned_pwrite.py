#!/usr/bin/env python3
"""One unaligned O_DIRECT pwrite whose open happened BEFORE the fault it measures.

tests/tcp_lockreq_blackhole.sh (WORKLOAD=held_fd_dio_unaligned) and
tests/live_holder_wait.sh (RW=dio_unaligned) measure the acquire inside the
direct write's exclusive retry (xfs_file_dio_write_unaligned: the shared
attempt answers -EAGAIN at its first mapping because the range is unwritten,
and the retry re-takes IOLOCK exclusive).  For that acquire to be the ONLY
one the fault or the paused holder meets, the open must already be done when
the fault is armed: open() is an audited fallible site of its own, and a
shell cannot open O_DIRECT, so an open inside the armed command lands the
refusal on open (measured s596d: the blocked task sat in mxfs_dlm_open_protect
and the verdict scored the wrong site).

So this process opens O_WRONLY|O_DIRECT first, announces it (`opened`
marker), parks until the `go` marker exists, then issues exactly one pwrite of
`length` bytes from a page-aligned anonymous mapping at `offset`, followed by
fsync, and prints what came back.

Usage: dio_unaligned_pwrite.py <file> <offset> <length> <opened-marker> <go-marker>
Prints `dio_write_bytes=N` on success, else `dio_write_rc=-E <strerror>`.
"""
import mmap
import os
import sys
import time


def main():
    path, offset, length, opened, go = (sys.argv[1], int(sys.argv[2]),
                                        int(sys.argv[3]), sys.argv[4],
                                        sys.argv[5])
    fd = os.open(path, os.O_WRONLY | os.O_DIRECT)
    with open(opened, "w"):
        pass
    while not os.path.exists(go):
        time.sleep(1)
    buf = mmap.mmap(-1, length)
    buf.write(b"d" * length)
    try:
        n = os.pwrite(fd, buf, offset)
        os.fsync(fd)
        sys.stdout.write("dio_write_bytes=%d\n" % n)
    except OSError as e:
        sys.stdout.write("dio_write_rc=%d %s\n" % (-e.errno, os.strerror(e.errno)))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
