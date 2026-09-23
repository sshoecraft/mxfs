#!/usr/bin/env python3
"""tests/ddtk_story_summary.py — condense a story.txt written by
tests/delalloc_dirty_tail_kprobe.sh into the interleaving that matters:

    ddtk_story_summary.py <story.txt> [--all]

For the first folio (index 0) of the closing pass it prints, in order:
  * the writer's writes:   W pos=<page>          (write_end with copied>0)
  * reads of the folio:    R U=<uptodate bitmap>  (ifs_alloc from the read
                           path, iflags=0, grouped)
  * write faults:          F                      (iomap_page_mkwrite entries)
  * dirtying via the aops: M D=<bitmap before>    (dirty_folio, grouped per fault)
  * delalloc punch scans:  P start=..end=..
  * the writeback:         WB clear_for_io / writepage_map / add_to_ioend range / end_writeback
Each line carries the task and the timestamp.  Runs of identical events are
collapsed to one line with a count unless --all is given.
"""
import re
import sys


def main():
    path = sys.argv[1]
    show_all = '--all' in sys.argv
    rows = []
    for line in open(path, errors='replace'):
        m = re.match(r'([\d.]+) (\d+) (\S+)\s+(.*)', line.rstrip())
        if not m:
            continue
        ts, pid, ev, rest = m.groups()
        tag = None
        if ev == 'write_end':
            mm = re.search(r'pos=(\d+) len=(\d+) copied=(\d+)', rest)
            if mm and int(mm.group(3)) > 0 and int(mm.group(3)) == 4096:
                tag = 'W page=%d' % (int(mm.group(1)) // 4096)
            elif mm and int(mm.group(3)) > 0:
                tag = 'W pos=%s len=%s copied=%s' % mm.groups()
        elif ev == 'ifs_alloc' and 'iflags=0x0' in rest and 'dirty_folio' not in rest:
            tag = 'R'  # read path (iomap_readpage_iter) — grouped below
        elif ev == 'mkwrite':
            tag = 'F'
        elif ev == 'dirty_folio':
            mm = re.search(r'D=([0-9a-f]+)', rest)
            tag = 'M D=%s' % (mm.group(1) if mm else '?')
        elif ev == 'delalloc_release':
            tag = 'P ' + rest
        elif ev in ('clear_for_io', 'do_writepage', 'writepage_map', 'end_writeback', 'ifs_clear_dirty', 'discard_folio'):
            mm = re.search(r'flags=(\S+).*D=([0-9a-f]+)', rest)
            tag = 'WB %s %s' % (ev, ('flags=%s D=%s' % mm.groups()) if mm else rest)
        elif ev == 'add_to_ioend':
            mm = re.search(r'pos=(\d+)', rest)
            tag = 'WB add_to_ioend page=%d' % (int(mm.group(1)) // 4096)
        elif ev == 'tracing_mark_write':
            tag = 'MARK ' + rest
        elif ev == 'write_begin':
            mm = re.search(r'U=([0-9a-f]+) D=([0-9a-f]+) pos=(\d+) len=(\d+)', rest)
            if mm:
                tag = 'B page=%d len=%s U=%s' % (int(mm.group(3)) // 4096, mm.group(4), mm.group(1))
        if tag is None:
            continue
        # the read path's ifs_alloc lines carry the uptodate bitmap as it grows
        if tag == 'R':
            mm = re.search(r'U=([0-9a-f]+)', rest)
            tag = 'R U=%s' % (mm.group(1) if mm else '?')
        rows.append((ts, pid, tag))

    out = []
    for ts, pid, tag in rows:
        key = tag.split(' ')[0]
        if out and not show_all and out[-1][1] == pid and out[-1][2].split(' ')[0] == key and key in ('R', 'M', 'F', 'WB') and 'add_to_ioend' in tag == 'add_to_ioend' in out[-1][2]:
            out[-1][3] += 1
            out[-1][4] = tag
            out[-1][5] = ts
            continue
        out.append([ts, pid, tag, 1, tag, ts])
    for ts, pid, tag, n, last, tend in out:
        if n > 1:
            print('%s %s %-40s x%d (last: %s at %s)' % (ts, pid, tag, n, last, tend))
        else:
            print('%s %s %s' % (ts, pid, tag))


if __name__ == '__main__':
    main()
