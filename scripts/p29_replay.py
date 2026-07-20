#!/usr/bin/env python3
"""P29-DATAWRITE ledger replay (sess4, ccloop a16ec5f2).

Merges P29-DATAWRITE lines from N nodes' dmesg captures into one global
per-daddr timeline (ordered by realns, the wall-clock ns stamp taken at
submit) and verifies the write CHAIN: for consecutive writes W[i], W[i+1]
of the same daddr, W[i+1]'s disk fingerprint (dsum/dxor/disk_cnt — a plain
re-read done at submit time) must equal W[i]'s buffer fingerprint
(bsum/bxor/buf_cnt — the image submitted).

  chain OK     -> every submitted image was the base of the next RMW.
  chain BREAK  -> W[i]'s image was NOT what W[i+1] found on disk:
                  either W[i] never landed / was clobbered outside P29's
                  view, or W[i+1]'s re-read was stale.  If W[i+1].disk
                  matches an OLDER write's buf, the rollback depth names
                  exactly how many committed writes were lost.

Usage: p29_replay.py <dmesg-file>... [--daddr N] [--tmin S] [--tmax S]
Node name is derived from each filename (testN).
"""
import re, sys, argparse

LINE = re.compile(
    r'\[\s*(\d+\.\d+)\] mxfs: P29-DATAWRITE tag=(\S+) owner=(\d+) '
    r'daddr=(\d+) bblk=(\d) dblk=(\d) buf_cnt=(\d+) disk_cnt=(\d+) '
    r'bufgen=(\d+) bufincarn=(\d+) bsum=0x([0-9a-f]+) dsum=0x([0-9a-f]+) '
    r'bxor=0x([0-9a-f]+) dxor=0x([0-9a-f]+) comm=(\S+) realns=(\d+)')


def parse(paths):
    recs = []
    for path in paths:
        node = re.search(r'(test\d+)', path)
        node = node.group(1) if node else path
        with open(path, errors='replace') as f:
            for ln in f:
                m = LINE.search(ln)
                if not m:
                    continue
                (lts, tag, owner, daddr, bblk, dblk, bc, dc, bgen, binc,
                 bsum, dsum, bxor, dxor, comm, realns) = m.groups()
                recs.append(dict(
                    node=node, lts=float(lts), owner=int(owner),
                    daddr=int(daddr), bblk=int(bblk), dblk=int(dblk),
                    bc=int(bc), dc=int(dc), bgen=int(bgen), binc=int(binc),
                    bsum=int(bsum, 16), dsum=int(dsum, 16),
                    bxor=int(bxor, 16), dxor=int(dxor, 16),
                    comm=comm, realns=int(realns)))
    recs.sort(key=lambda r: r['realns'])
    return recs


def fmt(r, t0):
    return ('%9.3f %-6s %-14s daddr=%-4d cnt=%3d/%3d gen=%-4d inc=%-10u '
            'bsum=%08x dsum=%08x bxor=%08x dxor=%08x' %
            ((r['realns'] - t0) / 1e9, r['node'], r['comm'], r['daddr'],
             r['bc'], r['dc'], r['bgen'], r['binc'],
             r['bsum'], r['dsum'], r['bxor'], r['dxor']))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('files', nargs='+')
    ap.add_argument('--daddr', type=int, default=None)
    ap.add_argument('--tmin', type=float, default=None,
                    help='window start, seconds since first record (global)')
    ap.add_argument('--tmax', type=float, default=None)
    ap.add_argument('--dump', action='store_true',
                    help='dump every write in the window, not just breaks')
    args = ap.parse_args()

    recs = parse(args.files)
    if not recs:
        print('no P29 records'); return
    t0 = recs[0]['realns']

    bydaddr = {}
    for r in recs:
        bydaddr.setdefault(r['daddr'], []).append(r)

    print('records=%d daddrs=%s  t0(realns)=%d' %
          (len(recs), sorted(bydaddr), t0))

    for daddr, seq in sorted(bydaddr.items()):
        if args.daddr is not None and daddr != args.daddr:
            continue
        breaks = 0
        for i in range(len(seq)):
            r = seq[i]
            ts = (r['realns'] - t0) / 1e9
            if args.tmin is not None and ts < args.tmin:
                continue
            if args.tmax is not None and ts > args.tmax:
                continue
            if args.dump:
                print(fmt(r, t0))
            if i == 0:
                continue
            p = seq[i - 1]
            if (r['dsum'] == p['bsum'] and r['dxor'] == p['bxor'] and
                    r['dc'] == p['bc']):
                continue
            # chain break: whose image did W[i] actually read?
            depth = None
            for k in range(i - 2, -1, -1):
                q = seq[k]
                if (r['dsum'] == q['bsum'] and r['dxor'] == q['bxor'] and
                        r['dc'] == q['bc']):
                    depth = i - 1 - k
                    break
            breaks += 1
            print('BREAK daddr=%d idx=%d rollback=%s' %
                  (daddr, i, depth if depth is not None else 'NO-MATCH'))
            print('  prev: ' + fmt(p, t0))
            print('  this: ' + fmt(r, t0))
        tot = len(seq)
        print('daddr=%-4d writes=%-4d breaks=%d  span=%.3f..%.3f' %
              (daddr, tot, breaks,
               (seq[0]['realns'] - t0) / 1e9, (seq[-1]['realns'] - t0) / 1e9))


if __name__ == '__main__':
    main()
