#!/bin/bash
# mxfs_shutdown.sh — force-shutdown an mxfs mount on a node.
#
# xfs_io -x -c 'shutdown -f' CANNOT be used on mxfs: xfs_io probes the fd
# with XFS_IOC_FSGEOMETRY first, which an mxfs mount does not answer
# ("Inappropriate ioctl for device"), so xfs_io exits before ever sending
# the shutdown.  (sess37 discovery: every prior scripted "shutdown -f" on
# mxfs was a silent no-op.)  mxfs DOES implement XFS_IOC_GOINGDOWN
# (pal/linux/xfs_ioctl.c) — issue it directly.
#
# XFS_IOC_GOINGDOWN = _IOR('X', 125, uint32_t) = 0x8004587d
# flags: 0=default (flush data+log)  1=logflush  2=NOLOGFLUSH (== -f)
#
# Usage: tests/mxfs_shutdown.sh <node> [mnt] [flags]
set -u
NODE="${1:?usage: mxfs_shutdown.sh <node> [mnt] [flags]}"
MNT="${2:-/mnt/shared}"
FLAGS="${3:-2}"
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec "$SCRIPT_DIR/../tools/mxfs_sshpass.sh" "$NODE" \
	"python3 -c \"
import fcntl, os, struct
fd = os.open('$MNT', os.O_RDONLY)
fcntl.ioctl(fd, 0x8004587d, struct.pack('I', $FLAGS))
os.close(fd)
print('GOINGDOWN($FLAGS) sent to $MNT')\""
