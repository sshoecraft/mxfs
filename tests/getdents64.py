#!/usr/bin/env python3
"""getdents64 on an already-open directory fd, with no open() and no fstat().

tests/tcp_lockreq_blackhole.sh (WORKLOAD=held_dir_readdir / leaf_midlist)
needs the readdir acquire of a directory to be the ONLY acquire the armed
fault meets.  Every library route to a listing does something else first:
opendir() is a fresh open(), fdopendir() fstat()s the fd, os.listdir(fd)
dup()s and fdopendir()s -- and open and getattr are already-audited sites
that would take the refusal before readdir was ever reached.  This issues
the syscall itself on the inherited fd and reports what came back.

Usage: python3 getdents64.py <fd> [calls]
Prints one line per call: `getdents_bytes=N names=K` or
`getdents_rc=-1 errno=E <strerror>`.  A refused acquire that stops a leaf
listing between two data blocks returns the bytes already copied (the
kernel drops the error when entries were copied), and the NEXT call, which
resumes at the unread block, returns the error -- so two calls are the
default.
"""
import ctypes
import os
import struct
import sys

SYS_GETDENTS64 = 217        # x86_64
BUFSZ = 262144


def main():
    fd = int(sys.argv[1])
    calls = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    buf = ctypes.create_string_buffer(BUFSZ)
    for _ in range(calls):
        n = libc.syscall(SYS_GETDENTS64, ctypes.c_int(fd), buf,
                         ctypes.c_size_t(BUFSZ))
        if n < 0:
            e = ctypes.get_errno()
            sys.stdout.write("getdents_rc=-1 errno=%d %s\n" % (e, os.strerror(e)))
            sys.stdout.flush()
            continue
        names = 0
        off = 0
        raw = buf.raw[:n]
        while off < n:
            # struct linux_dirent64: u64 ino, s64 off, u16 reclen, u8 type, name
            reclen = struct.unpack_from("<H", raw, off + 16)[0]
            if reclen == 0:
                break
            names += 1
            off += reclen
        sys.stdout.write("getdents_bytes=%d names=%d\n" % (n, names))
        sys.stdout.flush()
        if n == 0:
            break


if __name__ == "__main__":
    main()
