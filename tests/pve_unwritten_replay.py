#!/usr/bin/env python3
"""pve_unwritten_replay.py — the writer and the reader of
tests/pve_unwritten_replay.sh, fed to a host's python3 on stdin.

  write <path> <first> <count> <block> <stride> <reset>
      O_DIRECT writes of blocks <first> .. <first>+<count>-1, each of <block>
      bytes at offset i * <stride> and followed by fdatasync; "DURABLE <i>" is
      printed (and flushed) once block i's fdatasync has returned.  With
      <reset> = 1 the host is reset (sysrq b) the moment the last fdatasync
      returns: nothing synced, nothing unmounted, the inode not written home.
  read <path> <block> <stride> <i> ...
      reads block i at i * <stride> with O_DIRECT and prints
      "REGION <i> OK|ZERO|OTHER <first 16 bytes>".

Block i holds the 16-byte line "%015d\\n" % i repeated, so a block read back
names the write it came from.
"""
import mmap
import os
import sys


def pattern(i, block):
    line = ("%015d\n" % i).encode()
    return line * (block // len(line))


def write(path, first, count, block, stride, reset):
    fd = os.open(path, os.O_RDWR | os.O_DIRECT)
    buf = mmap.mmap(-1, block)
    for i in range(first, first + count):
        buf.seek(0)
        buf.write(pattern(i, block))
        n = os.pwrite(fd, buf, i * stride)
        if n != block:
            print("SHORT %d %d" % (i, n), flush=True)
            sys.exit(1)
        os.fdatasync(fd)
        print("DURABLE %d" % i, flush=True)
    if reset:
        with open("/proc/sysrq-trigger", "w") as f:
            f.write("b")
    os.close(fd)


def read(path, block, stride, idx):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
    buf = mmap.mmap(-1, block)
    for i in idx:
        n = os.preadv(fd, [buf], i * stride)
        data = buf[:n]
        if n == block and data == pattern(i, block):
            verdict = "OK"
        elif n > 0 and data.count(0) == n:
            verdict = "ZERO"
        else:
            verdict = "OTHER"
        print("REGION %d %s %r" % (i, verdict, data[:16]), flush=True)
    os.close(fd)


def main():
    mode = sys.argv[1]
    if mode == "write":
        write(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]),
              int(sys.argv[6]), sys.argv[7] == "1")
    elif mode == "read":
        read(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]),
             [int(a) for a in sys.argv[5:]])
    else:
        sys.exit("usage: write|read ...")


if __name__ == "__main__":
    main()
