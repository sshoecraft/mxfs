#!/usr/bin/env python3
"""
dirshard_ioctl.py — drive the MXFS directory-sharding ioctls (sess466,
docs/dir-sharding.md; format include/mxfs/mxfs_dirshard.h).

  dirshard_ioctl.py mkdir <parent-dir> <name> <nshards> [mode-octal]
      MXFS_IOC_DIRSHARD_MKDIR on <parent-dir>: create the sharded child
      <name> with <nshards> containers (16/32/64), published atomically.
  dirshard_ioctl.py info <dir> [name]
      MXFS_IOC_DIRSHARD_INFO on <dir>: JSON with state/nshards/nentries/
      hash_id/valid_mask/set_uuid/hash_key (root only) and, for [name], its
      SipHash-2-4 under the directory's key and its shard index.

Struct sizes are pinned by MXFS_IOC_DIRSHARD_{MKDIR,INFO}_SIZE (272 / 1352)
and BUILD_BUG_ON'd in the kernel; a size drift fails here with ENOTTY or a
short copy, never silently.  Exit 0 on success; the errno name on failure
(printed as 'ERR <errno-name> <message>') and exit 1.
"""
import errno
import fcntl
import json
import os
import struct
import sys

IOC_TYPE = 0xB7
MKDIR_SIZE = 272
INFO_SIZE = 1352
IOC_NRBITS, IOC_TYPEBITS, IOC_SIZEBITS = 8, 8, 14
IOC_NRSHIFT = 0
IOC_TYPESHIFT = IOC_NRSHIFT + IOC_NRBITS
IOC_SIZESHIFT = IOC_TYPESHIFT + IOC_TYPEBITS
IOC_DIRSHIFT = IOC_SIZESHIFT + IOC_SIZEBITS
IOC_WRITE, IOC_READ = 1, 2


def ioc(direction, nr, size):
    return ((direction << IOC_DIRSHIFT) | (IOC_TYPE << IOC_TYPESHIFT) |
            (nr << IOC_NRSHIFT) | (size << IOC_SIZESHIFT))


MXFS_IOC_DIRSHARD_MKDIR = ioc(IOC_WRITE, 1, MKDIR_SIZE)
MXFS_IOC_DIRSHARD_INFO = ioc(IOC_READ | IOC_WRITE, 2, INFO_SIZE)

MKDIR_FMT = "<IIII256s"
INFO_HDR_FMT = "<256sIIIIQQII16s16s"
INFO_SHARD_FMT = "<QII"
assert struct.calcsize(MKDIR_FMT) == MKDIR_SIZE
assert struct.calcsize(INFO_HDR_FMT) + 64 * struct.calcsize(INFO_SHARD_FMT) == INFO_SIZE

STATES = {0: "NONE", 1: "ALLOCATING", 2: "COMPLETE", 3: "PUBLISHED", 4: "DELETING"}


def fail(e, what):
    name = errno.errorcode.get(e.errno, str(e.errno))
    print("ERR %s %s: %s" % (name, what, e.strerror))
    sys.exit(1)


def cmd_mkdir(args):
    if len(args) < 3:
        print(__doc__)
        sys.exit(2)
    parent, name, nshards = args[0], args[1], int(args[2])
    mode = int(args[3], 8) if len(args) > 3 else 0o755
    buf = struct.pack(MKDIR_FMT, nshards, mode, 0, 0, name.encode())
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.ioctl(fd, MXFS_IOC_DIRSHARD_MKDIR, buf)
    except OSError as e:
        fail(e, "MXFS_IOC_DIRSHARD_MKDIR")
    finally:
        os.close(fd)
    # last line is exactly "OK": tests/suite/crash_consistency.sh (CC_SHARDED)
    # asserts it verbatim.
    print("mkdir %s/%s nshards=%d mode=0%o" % (parent, name, nshards, mode))
    print("OK")


def cmd_info(args):
    if len(args) < 1:
        print(__doc__)
        sys.exit(2)
    path = args[0]
    name = args[1].encode() if len(args) > 1 else b""
    buf = bytearray(INFO_SIZE)
    buf[0:len(name)] = name
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        fcntl.ioctl(fd, MXFS_IOC_DIRSHARD_INFO, buf)
    except OSError as e:
        fail(e, "MXFS_IOC_DIRSHARD_INFO")
    finally:
        os.close(fd)
    hdr = struct.unpack_from(INFO_HDR_FMT, buf, 0)
    (_, state, nshards, nentries, hash_id, valid_mask, name_hash, name_shard,
     _reserved, set_uuid, hash_key) = hdr
    off = struct.calcsize(INFO_HDR_FMT)
    shards = []
    for i in range(64):
        ino, gen, nlink = struct.unpack_from(INFO_SHARD_FMT, buf, off + i * 16)
        if i < nshards:
            shards.append({"index": i, "ino": ino, "gen": gen, "nlink": nlink,
                           "live": bool(valid_mask >> i & 1)})
    out = {
        "path": path,
        "state": STATES.get(state, state),
        "state_num": state,
        "nshards": nshards,
        "nentries": nentries,
        "hash_id": hash_id,
        "valid_mask": "0x%016x" % valid_mask,
        "set_uuid": set_uuid.hex(),
        "hash_key": hash_key.hex(),
        "shards": shards,
    }
    if name:
        out["name"] = name.decode(errors="replace")
        out["name_hash"] = "0x%016x" % name_hash
        out["name_shard"] = name_shard
    # one key=value summary line first (tests/suite/crash_consistency.sh
    # greps '^state=... nshards=...'), then the JSON document.
    print("state=%s nshards=%d nentries=%d valid_mask=%s hash_id=%d" %
          (out["state"], nshards, nentries, out["valid_mask"], hash_id))
    print(json.dumps(out, indent=1))


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sub, rest = sys.argv[1], sys.argv[2:]
    if sub == "mkdir":
        cmd_mkdir(rest)
    elif sub == "info":
        cmd_info(rest)
    else:
        print(__doc__)
        sys.exit(2)


if __name__ == "__main__":
    main()
