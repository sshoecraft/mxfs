#!/usr/bin/env python3
"""tests/d0532_img_check.py <file> [--wrote <writer_file>...] — one line
describing a file's image.

Used by tests/d0532_nowait_iomap_probe.sh (PEER mode) and
tests/dio_write_conversion_deadlock.sh on both nodes after the writers have
stopped and caches are dropped.  Every writer in those arms writes whole,
aligned 4 KiB blocks of one byte value, so a block holding more than one
distinct byte is torn.

With --wrote the file is read one data segment at a time (SEEK_DATA /
SEEK_HOLE), so a large sparse file costs only what was written; a hole reads
as zero by definition and is mapped '0' without being read.  Without it every
byte is read.  The digest covers every byte of the file, holes included, so
both modes print the md5 of a full read.

Prints: IMG len=<bytes> md5=<hex> torn=<blocks> blocks=<per-block byte map>
With --wrote, the per-block map is replaced by a run-length form
(blocks_rle=<char><count>...) and a second line checks it against the
'WROTE <block>...' lines of the given writer reports:
  EXTCHK written=<n> blocks=<n> lost=<n> stray=<n> short=<0|1> first_lost=
         first_stray=
lost:  a block some writer reported written that holds neither 'a' nor 'b';
stray: a block no writer reported written that does not read zero;
short: the file ends before the highest block written.
"""
import hashlib
import os
import sys

BLK = 4096
ZERO = bytes(BLK)


def segments(fd, size):
    """(offset, length) of each data segment, in order."""
    off = 0
    while off < size:
        try:
            d = os.lseek(fd, off, os.SEEK_DATA)
        except OSError:
            break
        h = os.lseek(fd, d, os.SEEK_HOLE)
        yield d, h - d
        off = h


def main():
    path = sys.argv[1]
    wrote_files = sys.argv[3:] if len(sys.argv) > 2 and sys.argv[2] == '--wrote' else None
    fd = os.open(path, os.O_RDONLY)
    size = os.fstat(fd).st_size
    nblk = (size + BLK - 1) // BLK
    kinds = bytearray(b'0' * nblk)
    md5 = hashlib.md5()
    torn = 0
    pos = 0
    # Default mode reads every byte, as this check always has; the segment
    # walk is used only for the extending-write verdict (--wrote), whose
    # files can span gigabytes of holes.
    segs = segments(fd, size) if wrote_files is not None else [(0, size)]
    for d, ln in segs:
        # the hole before this segment reads as zeros
        while pos < d:
            n = min(d - pos, 1 << 20)
            md5.update(bytes(n))
            pos += n
        os.lseek(fd, d, os.SEEK_SET)
        left = ln
        while left > 0:
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                break
            md5.update(chunk)
            for i in range(0, len(chunk), BLK):
                blk = set(chunk[i:i + BLK])
                b = (pos + i) // BLK
                if len(blk) != 1:
                    torn += 1
                    kinds[b] = ord('?')
                else:
                    v = blk.pop()
                    kinds[b] = v if 33 <= v < 127 else ord('0')
            pos += len(chunk)
            left -= len(chunk)
    while pos < size:
        n = min(size - pos, 1 << 20)
        md5.update(bytes(n))
        pos += n
    os.close(fd)
    if wrote_files is None:
        print('IMG len=%d md5=%s torn=%d blocks=%s'
              % (size, md5.hexdigest(), torn, kinds.decode()))
        return
    rle = []
    i = 0
    while i < nblk:
        j = i
        while j < nblk and kinds[j] == kinds[i]:
            j += 1
        rle.append('%s%d' % (chr(kinds[i]), j - i))
        i = j
    print('IMG len=%d md5=%s torn=%d blocks_rle=%s'
          % (size, md5.hexdigest(), torn, ''.join(rle)))
    w = set()
    for f in wrote_files:
        for line in open(f):
            if line.startswith('WROTE'):
                w.update(int(t) for t in line.split()[1:] if t.isdigit())
    lost = [b for b in sorted(w) if b >= nblk or kinds[b] not in b'ab']
    stray = [b for b in range(nblk) if b not in w and kinds[b] != ord('0')]
    short = int(bool(w) and max(w) >= nblk)
    print('EXTCHK written=%d blocks=%d lost=%d stray=%d short=%d first_lost=%s first_stray=%s'
          % (len(w), nblk, len(lost), len(stray), short,
             lost[0] if lost else '-', stray[0] if stray else '-'))


main()
