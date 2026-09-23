#!/usr/bin/env python3
"""tests/ddtt_follow.py — follow a byte range of one inode through an ftrace dump
taken by tests/delalloc_dirty_tail_trace.sh.

    ddtt_follow.py <trace.txt> <ino> <lo_byte> <hi_byte> [anchor]

Prints, in trace order, every event of <ino> whose extent intersects
[lo, hi), starting at the ANCHOR: by default the LAST buffered write that
began at byte 0 (`iomap_iter ... pos 0x0 length 0x40000 flags WRITE`), which is
the first write of the reproducer's closing pass — the only pass whose contents
the oracle checks.  Everything before it belongs to the timed phase and was
punched away by the reproducer itself.

Event fields understood (6.8 formats):
  xfs_iomap_alloc/found        offset 0x.. count 0x..           (bytes)
  xfs_bmap_pre/post_update     fileoff 0x.. startblock .. fsbcount 0x..  (fsblocks)
  iomap_iter                   pos 0x.. length 0x.. flags ..    (bytes)
  iomap_writepage_map          pos 0x.. length 0x.. type ..     (bytes)
  iomap_writepage/invalidate/release_folio   pgoff 0x.. size 0x..  or  ofs/len (bytes)
  mm_filemap_add/delete_from_page_cache      ofs=<bytes> order=<n>
A line whose range cannot be parsed is printed only if it names the inode and
carries no range at all (a marker or an unparsed shape), flagged UNPARSED.
"""
import re
import sys

BS = 4096


def spans(line):
    out = []
    m = re.search(r'offset (0x[0-9a-f]+|\d+) count (0x[0-9a-f]+|\d+)', line)
    if m:
        out.append((int(m.group(1), 0), int(m.group(2), 0)))
    m = re.search(r'pos (0x[0-9a-f]+|\d+) length (0x[0-9a-f]+|\d+)', line)
    if m:
        out.append((int(m.group(1), 0), int(m.group(2), 0)))
    m = re.search(r'fileoff (0x[0-9a-f]+|\d+) startblock \S+ fsbcount (0x[0-9a-f]+|\d+)', line)
    if m:
        out.append((int(m.group(1), 0) * BS, int(m.group(2), 0) * BS))
    m = re.search(r'pgoff (0x[0-9a-f]+|\d+) size (0x[0-9a-f]+|\d+)', line)
    if m:
        out.append((int(m.group(1), 0), int(m.group(2), 0)))
    m = re.search(r'\bofs=(\d+) order=(\d+)', line)
    if m:
        out.append((int(m.group(1)), BS << int(m.group(2))))
    elif re.search(r'\bofs=(\d+)', line):
        m = re.search(r'\bofs=(\d+)', line)
        out.append((int(m.group(1)), BS))
    return out


def main():
    t, ino, lo, hi = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    anchor_re = re.compile(sys.argv[5]) if len(sys.argv) > 5 else \
        re.compile(r'iomap_iter: .*pos 0x0 length 0x40000 flags WRITE ')
    ino_pat = re.compile(r'\bino (0x%x|%d)\b' % (ino, ino))
    lines = open(t, errors='replace').read().splitlines()
    anchor = None
    for i, line in enumerate(lines):
        if anchor_re.search(line) and ino_pat.search(line):
            anchor = i
    if anchor is None:
        print('NO_ANCHOR')
        return 2
    print('ANCHOR line=%d: %s' % (anchor + 1, lines[anchor].strip()))
    n = 0
    for line in lines[anchor:]:
        if 'tracing_mark_write' in line:
            print(line.rstrip())
            continue
        if not ino_pat.search(line):
            continue
        sp = spans(line)
        if not sp:
            print('UNPARSED ' + line.rstrip())
            continue
        if any(s < hi and s + l > lo for (s, l) in sp):
            print(line.rstrip())
            n += 1
    print('FOLLOWED=%d' % n)
    return 0


if __name__ == '__main__':
    sys.exit(main())
