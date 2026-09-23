#!/usr/bin/env python3
"""One inode operation through an fd opened BEFORE the fault it measures.

tests/tcp_lockreq_blackhole.sh (WORKLOAD=held_fd_<op>) and
tests/live_holder_wait.sh (RW=<op>) measure the FIRST cluster acquire of an
operation: an attribute change (xfs_setattr_nonsize: the ILOCK_EXCL inside
xfs_trans_alloc_ichange), fallocate (__xfs_file_fallocate: its IOLOCK_EXCL
take), an extended-attribute read (xfs_attr_get / xfs_attr_list: the
attr-fork lock, a cluster PR), an extended-attribute change (the reservation
inside xfs_attr_set / xfs_attr_add_fork) or a page fault (the counted hold a
fault takes, and a write fault's timestamp update).  For that acquire to be
the only one the fault or the paused holder meets, the open must already be
done — open() is an audited fallible site of its own — and the file's grant
must have been revoked between the open and the operation (the harness has
the holder rewrite the file in between), so the operation's own request is
the first one sent.

The process opens O_RDWR, announces it (`opened` marker), parks until the
`go` marker exists, then issues exactly one operation on the fd and prints
what came back:

  chmod      fchmod(fd, 0640)                        -> chmod_ok=1
  fallocate  fallocate(fd, 0, 1 MiB, 4096)           -> fallocate_ok=1
             (the size becomes 1 MiB + 4096; the harnesses compare mode and
             size, which a refused operation must leave untouched)
  truncate   ftruncate(fd, 4096)                     -> truncate_ok=1
             (a residual NON-fallible site: xfs_setattr_size's ILOCK_EXCL is
             taken after truncate_setsize has already changed the in-core
             size, so the wait is reported DEGRADED and kept; the harness
             measures that report under EXPECT=degraded)
  getxattr   fgetxattr(fd, user.d958)                -> getxattr_ok=1 value=<v>
  listxattr  flistxattr(fd)                          -> listxattr_ok=1 names=<a,b>
             (both set user.d958=v958 on the fd BEFORE announcing, so the
             attribute exists, its value is known, and the set's own EX has
             landed before the holder's rewrite revokes it; the read that
             follows the go marker sends the attr-fork PR as its first
             request.  A refused read must have changed nothing; a read that
             lands must return v958 / a name list containing user.d958.)
  setxattr   fsetxattr(fd, user.d958, v958)         -> setxattr_ok=1
             (NO attribute is set beforehand; the change's first request is
             the reservation inside xfs_attr_add_fork when the inode has no
             attr fork yet — stage=addfork — or xfs_attr_set's own when it
             has one — stage=set; the kernel's P958-XATTRSET-PATH line says
             which the change saw)
  removexattr fremovexattr(fd, user.d958)           -> removexattr_ok=1
             (user.d958=v958 is set before announcing, so the change's first
             request is xfs_attr_set's own reservation: stage=remove)
  setxattr_nofork
             fsetxattr(fd, user.d958, v958) on an inode whose attr fork has
             been REMOVED: user.d958 is set and then removed before
             announcing (removing the last attribute drops the fork), so
             the change's first request is xfs_attr_add_fork's reservation:
             stage=addfork.  Every new inode on this build is created with
             an empty extents-format attr fork (xfs_bmap.c, the default
             attr offset), so plain setxattr never reaches add-fork; this
             op does.                                -> setxattr_nofork_ok=1
  mmap_read  a 4 KiB MAP_SHARED PROT_READ mapping made before announcing;
             after the go marker a forked CHILD reads its first 4 bytes (a
             read fault: xfs_filemap_fault's counted PR hold)
                                                    -> mmap_read_ok=1 value=<hex>
  mmap_write a 4 KiB MAP_SHARED PROT_READ|PROT_WRITE mapping made before
             announcing; after the go marker a forked CHILD stores b'mmw!' at
             offset 0 and msyncs (a write fault: the read fault's hold if the
             page is not present, then page_mkwrite's timestamp update and
             counted EX hold)                       -> mmap_write_ok=1
             Both fault ops run the access in a child so a refused fault,
             which is SIGBUS, is reported by the parent as
             `<op>_rc=-7 SIGBUS` instead of killing the driver; the child's
             pid is written to `<go-marker>.child` so a harness can sample
             the faulting task's stack.

(FS_IOC_FSSETXATTR is not an op: MXFS does not compile pal/linux/xfs_ioctl.c
and its fileattr entries are stubs answering EOPNOTSUPP.)

Usage: held_fd_op.py <file> <op> <opened-marker> <go-marker>
On failure prints `<op>_rc=-E <strerror>`.
"""
import ctypes
import mmap
import os
import signal
import sys
import time

XATTR_NAME = "user.d958"
XATTR_VALUE = b"v958"
OPS = ("chmod", "fallocate", "truncate", "getxattr", "listxattr",
       "setxattr", "removexattr", "setxattr_nofork", "mmap_read", "mmap_write")


def run_fault_child(op, m, go):
    pid = os.fork()
    if pid == 0:
        try:
            if op == "mmap_write":
                m[0:4] = b"mmw!"
                m.flush()
                sys.stdout.write("%s_ok=1\n" % op)
            else:
                v = bytes(m[0:4])
                sys.stdout.write("%s_ok=1 value=%s\n" % (op, v.hex()))
            sys.stdout.flush()
            os._exit(0)
        except OSError as e:
            sys.stdout.write("%s_rc=%d %s\n" % (op, -e.errno, os.strerror(e.errno)))
            sys.stdout.flush()
            os._exit(1)
    with open(go + ".child", "w") as f:
        f.write("%d\n" % pid)
    wpid, st = os.waitpid(pid, 0)
    if os.WIFSIGNALED(st):
        sig = os.WTERMSIG(st)
        sys.stdout.write("%s_rc=-%d %s\n" % (op, sig, signal.Signals(sig).name))
    elif os.WEXITSTATUS(st) != 0:
        sys.stdout.write("%s_child_exit=%d\n" % (op, os.WEXITSTATUS(st)))
    sys.stdout.flush()


def main():
    path, op, opened, go = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
    if op not in OPS:
        sys.stdout.write("ABORT: op must be one of %s\n" % ", ".join(OPS))
        sys.exit(2)
    fd = os.open(path, os.O_RDWR)
    m = None
    if op in ("getxattr", "listxattr", "removexattr"):
        # The set is a transaction of its own (a cluster EX); it must be
        # done and its grant revoked by the holder before the read under
        # test, so it happens before the `opened` announcement.
        os.setxattr(fd, XATTR_NAME, XATTR_VALUE)
        os.fsync(fd)
        sys.stdout.write("setxattr_ok=1\n")
        sys.stdout.flush()
    elif op == "setxattr_nofork":
        os.setxattr(fd, XATTR_NAME, XATTR_VALUE)
        os.removexattr(fd, XATTR_NAME)
        os.fsync(fd)
        sys.stdout.write("setxattr_ok=1 removexattr_ok=1\n")
        sys.stdout.flush()
    elif op in ("mmap_read", "mmap_write"):
        prot = mmap.PROT_READ | (mmap.PROT_WRITE if op == "mmap_write" else 0)
        m = mmap.mmap(fd, 4096, flags=mmap.MAP_SHARED, prot=prot)
        sys.stdout.write("mmap_ok=1\n")
        sys.stdout.flush()
    with open(opened, "w"):
        pass
    while not os.path.exists(go):
        time.sleep(1)
    if m is not None:
        run_fault_child(op, m, go)
        return
    try:
        if op == "chmod":
            os.fchmod(fd, 0o640)
        elif op == "truncate":
            os.ftruncate(fd, 4096)
        elif op == "getxattr":
            v = os.getxattr(fd, XATTR_NAME)
            sys.stdout.write("getxattr_ok=1 value=%s\n" % v.decode("ascii", "replace"))
            sys.stdout.flush()
            return
        elif op == "listxattr":
            names = os.listxattr(fd)
            sys.stdout.write("listxattr_ok=1 names=%s\n" % ",".join(names))
            sys.stdout.flush()
            return
        elif op in ("setxattr", "setxattr_nofork"):
            os.setxattr(fd, XATTR_NAME, XATTR_VALUE)
        elif op == "removexattr":
            os.removexattr(fd, XATTR_NAME)
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            rc = libc.fallocate(ctypes.c_int(fd), ctypes.c_int(0),
                                ctypes.c_longlong(1 << 20), ctypes.c_longlong(4096))
            if rc != 0:
                e = ctypes.get_errno()
                raise OSError(e, os.strerror(e))
        sys.stdout.write("%s_ok=1\n" % op)
    except OSError as e:
        sys.stdout.write("%s_rc=%d %s\n" % (op, -e.errno, os.strerror(e.errno)))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
