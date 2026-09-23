#!/usr/bin/env python3
"""Collision histogram of xfs_da_hashname over a set of directory names.

Reads names from stdin (one per line) or generates the crash_consistency set
(node{R}_f{i} and node{R}_f{i}.md5, R=1..T, i=1..N) with --cc T N.
Prints the distribution of hash-bucket sizes, i.e. how many leaf entries share
one hashval, which is exactly how many data blocks a node-format directory
lookup may have to read for one name.
"""
import sys

def rol32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xffffffff

def dahash(name):
    b = name.encode()
    h = 0
    n = len(b)
    i = 0
    while n >= 4:
        h = ((b[i] << 21) ^ (b[i+1] << 14) ^ (b[i+2] << 7) ^ b[i+3] ^ rol32(h, 28)) & 0xffffffff
        i += 4; n -= 4
    if n == 3:
        h = ((b[i] << 14) ^ (b[i+1] << 7) ^ b[i+2] ^ rol32(h, 21)) & 0xffffffff
    elif n == 2:
        h = ((b[i] << 7) ^ b[i+1] ^ rol32(h, 14)) & 0xffffffff
    elif n == 1:
        h = (b[i] ^ rol32(h, 7)) & 0xffffffff
    return h

def main():
    if len(sys.argv) >= 4 and sys.argv[1] == '--cc':
        T, N = int(sys.argv[2]), int(sys.argv[3])
        names = []
        for r in range(1, T + 1):
            for i in range(1, N + 1):
                names.append('node%d_f%d' % (r, i))
                names.append('node%d_f%d.md5' % (r, i))
    else:
        names = [l.strip() for l in sys.stdin if l.strip()]
    buckets = {}
    for nm in names:
        buckets.setdefault(dahash(nm), []).append(nm)
    sizes = {}
    for h, lst in buckets.items():
        sizes[len(lst)] = sizes.get(len(lst), 0) + 1
    print('names=%d distinct_hashes=%d' % (len(names), len(buckets)))
    print('bucket-size histogram (size: how many hashvals have that many names):')
    for s in sorted(sizes):
        print('  %3d: %d' % (s, sizes[s]))
    # names weighted: what fraction of names live in a bucket of size >= k
    total = len(names)
    for k in (2, 5, 10, 20):
        n = sum(len(l) for l in buckets.values() if len(l) >= k)
        print('names in buckets of size >= %d: %d (%.1f%%)' % (k, n, 100.0 * n / total))
    big = sorted(buckets.values(), key=len, reverse=True)[:3]
    for lst in big:
        print('largest bucket size=%d e.g. %s' % (len(lst), ' '.join(lst[:8])))

if __name__ == '__main__':
    main()
