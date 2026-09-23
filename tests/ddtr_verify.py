#!/usr/bin/env python3
"""tests/ddtr_verify.py — the post-remount check for tests/delalloc_dirty_tail_race.c.

    ddtr_verify.py <path> <verify_hi_bytes> [max_bad_listed]

Runs on the node, against a FRESH mount (the harness unmounts and remounts
first; a read from the live page cache would pass whether or not anything
reached the platter).  Reads the first byte of every page below verify_hi and
the manifest <path>.touched the reproducer wrote (one byte per page, 1 = the
toucher stored to it during the closing pass):

  even page i            expected (i & 0xff) always — the closing pass writes it
  odd page i, marked     expected (i & 0xff) — the toucher stored it
  odd page i, unmarked   not checked; counted as UNTOUCHED.  The toucher does
                         not cover every odd page (it lags the writer at the
                         start of the pass and can skip one mid-file), and an
                         unmarked page is a hole the punch left, not lost data.

Prints one line the harness parses, then up to max_bad_listed offending pages:
  CHECKED=<n> BAD=<n> BAD_WRITER=<n> BAD_TOUCHER=<n> TOUCHED=<n> UNTOUCHED=<n>
Exits 2 when the manifest is missing or short, because a verdict read without
it is the pre-manifest oracle that graded holes as loss.
"""
import sys

PAGE = 4096


def main():
    path = sys.argv[1]
    hi = int(sys.argv[2])
    max_listed = int(sys.argv[3]) if len(sys.argv) > 3 else 12
    npages = hi // PAGE
    try:
        with open(path + '.touched', 'rb') as m:
            touched = m.read()
    except OSError as e:
        print('ABORT: manifest %s.touched unreadable: %s' % (path, e))
        return 2
    if len(touched) < npages:
        print('ABORT: manifest %s.touched holds %d pages, %d needed' % (path, len(touched), npages))
        return 2
    bad = []
    badw = badt = ntouched = untouched = 0
    with open(path, 'rb') as f:
        for i in range(npages):
            if i % 2 == 1:
                if not touched[i]:
                    untouched += 1
                    continue
                ntouched += 1
            f.seek(i * PAGE)
            b = f.read(1)
            if not b or b[0] != (i & 0xff):
                if i % 2 == 0:
                    badw += 1
                else:
                    badt += 1
                if len(bad) < max_listed:
                    bad.append((i, 'hole/eof' if not b else b[0], i & 0xff))
    print('CHECKED=%d BAD=%d BAD_WRITER=%d BAD_TOUCHER=%d TOUCHED=%d UNTOUCHED=%d'
          % (npages - untouched, badw + badt, badw, badt, ntouched, untouched))
    for i, g, w in bad:
        print('  page=%d kind=%s got=%s want=%d' % (i, 'writer' if i % 2 == 0 else 'toucher', g, w))
    return 0


if __name__ == '__main__':
    sys.exit(main())
