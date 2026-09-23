#!/usr/bin/env python3
"""tests/dwcd_prefill.py <file> <span_blocks> <count> <byte>

Fragment <file> before tests/dio_write_conversion_deadlock.sh's two-node
phase: <count> aligned 4 KiB O_DIRECT writes of <byte> at random block
offsets in [0, span_blocks), from one node, so the data fork becomes a
multi-leaf, multi-level extent btree far faster than the contended phase
can build one.  Prints 'WROTE <block>...' (the blocks written, in the form
the harness's image check reads) and 'PREFILL n=<writes> blocks=<distinct>
secs=<wall>'.
"""
import mmap
import os
import random
import sys
import time

path, span, count, byte = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
buf = mmap.mmap(-1, 4096)
buf.write(byte.encode()[:1] * 4096)
fd = os.open(path, os.O_WRONLY | os.O_DIRECT)
done = set()
t0 = time.time()
for _ in range(count):
    b = random.randrange(span)
    os.pwrite(fd, buf, b * 4096)
    done.add(b)
os.close(fd)
print('WROTE ' + ' '.join(str(b) for b in sorted(done)))
print('PREFILL n=%d blocks=%d secs=%.1f' % (count, len(done), time.time() - t0))
