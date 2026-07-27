#!/usr/bin/env python3
# d3_ring_analyze.py — merge P172-WRTR write-provenance rings harvested from
# all nodes (tests/d3_dirring.sh) into per-daddr cross-node timelines and
# flag clobber signatures (ccloop c7ee71c6 sess14, D3 hunt).
#
#   tests/d3_ring_analyze.py <harvest_dir> [--daddr N] [--slot S] [--all]
#
# Record source (pal/linux/xfs_buf.c):
#   mxfs: P172-WRTR t=T daddr=D owner=O cnt=C mask=M crc=X gm=G fl=F
#         comm=CM pid=P ns=NS
#   t: 0=ino-cluster 1=dir3_block 2=dir3_data 3=leaf1 4=leafn 5=da3_node
#   mask: t=0 -> dirmask<<32|allocmask (bit per inode slot, mode!=0);
#         t=1/2 -> inumber-sum<<32|xor of live dirents
#   crc:  content lineage (equal bytes -> equal crc across nodes/commits)
#   gm:   DLM granted mode of the owner dir at submit (255 = n/a)
#   fl:   bit0 delwri 1 fua_fresh 2 in_ail 3 dirty 4 pin 5 done 6 stale 7 async
#
# Flaggers (signals, not verdicts — read the timeline):
#   SLOT-REVERT   cluster write SETS an alloc bit a prior write CLEARED
#   CRC-REVERT    a daddr's content crc returns to an older value after
#                 intervening different content (ABA / stale-base resurface)
#   NONEX-WRITE   dir-metadata write submitted while owner NOT EX-granted

import os, re, sys, glob

LINE = re.compile(
    r'P172-WRTR t=(\d+) daddr=(\d+) owner=(\d+) cnt=(-?\d+) mask=([0-9a-f]+) '
    r'crc=([0-9a-f]+) gm=(\d+) fl=([0-9a-f]+) comm=(\S+) pid=(\d+) ns=(\d+)')
P26 = re.compile(r'P26-IGET-FAIL dp=(\d+) name="([^"]*)" inum=(\d+) err=(-?\d+)')
TYPES = {0: 'clust', 1: 'block', 2: 'data', 3: 'leaf1', 4: 'leafn', 5: 'danod'}

def parse(harvest_dir):
    recs, p26s = [], []
    for path in sorted(glob.glob(os.path.join(harvest_dir, 'test*.dmesg'))):
        node = os.path.basename(path).split('.')[0]
        with open(path, errors='replace') as f:
            for ln in f:
                m = LINE.search(ln)
                if m:
                    recs.append({
                        'node': node, 't': int(m.group(1)),
                        'daddr': int(m.group(2)), 'owner': int(m.group(3)),
                        'cnt': int(m.group(4)), 'mask': int(m.group(5), 16),
                        'crc': int(m.group(6), 16), 'gm': int(m.group(7)),
                        'fl': int(m.group(8), 16), 'comm': m.group(9),
                        'pid': int(m.group(10)), 'ns': int(m.group(11))})
                    continue
                m = P26.search(ln)
                if m:
                    p26s.append((node, int(m.group(1)), m.group(2),
                                 int(m.group(3)), int(m.group(4))))
    return recs, p26s

def fmt(r, extra=''):
    fl = r['fl']
    bits = ''.join(n for b, n in
                   [(1, 'q'), (2, 'F'), (4, 'a'), (8, 'd'),
                    (16, 'p'), (32, 'D'), (64, 's'), (128, 'y')] if fl & b)
    return ('%-7s %s ns=%d cnt=%-4d mask=%016x crc=%08x gm=%-3d fl=%-8s '
            'comm=%s/%d owner=%d%s' %
            (r['node'], TYPES.get(r['t'], '?'), r['ns'], r['cnt'], r['mask'],
             r['crc'], r['gm'], bits or '-', r['comm'], r['pid'], r['owner'],
             extra))

def analyze_daddr(recs, daddr, slot=None):
    tl = sorted((r for r in recs if r['daddr'] == daddr), key=lambda r: r['ns'])
    if not tl:
        print('daddr %d: no writes recorded' % daddr)
        return
    print('=== daddr %d — %d writes across %d nodes ===' %
          (daddr, len(tl), len({r['node'] for r in tl})))
    prev_alloc = None
    seen_crc = {}          # crc -> first index
    last_crc = None
    for i, r in enumerate(tl):
        notes = []
        if r['t'] == 0:
            alloc = r['mask'] & 0xffffffff
            if prev_alloc is not None:
                set_again = alloc & ~prev_alloc
                cleared = prev_alloc & ~alloc
                if set_again:
                    notes.append('SETS slots %s' % bits_of(set_again))
                if cleared:
                    notes.append('CLEARS slots %s' % bits_of(cleared))
                if slot is not None:
                    was, now = (prev_alloc >> slot) & 1, (alloc >> slot) & 1
                    if was != now:
                        notes.append('SLOT %d %s' %
                                     (slot, 'FREED' if was else '**REALLOC**'))
            prev_alloc = alloc
        if r['crc'] in seen_crc and last_crc is not None and \
           last_crc != r['crc'] and seen_crc[r['crc']] < i - 1:
            notes.append('**CRC-REVERT to write #%d**' % seen_crc[r['crc']])
        if r['crc'] not in seen_crc:
            seen_crc[r['crc']] = i
        last_crc = r['crc']
        if r['t'] != 0 and r['gm'] == 0:
            notes.append('**NONEX-WRITE (gm=NL)**')
        print('#%-4d %s%s' % (i, fmt(r), ('   ' + '; '.join(notes)) if notes else ''))

def bits_of(v):
    return ','.join(str(i) for i in range(64) if v >> i & 1)

def auto_scan(recs, p26s, show_all):
    print('%d ring records, %d daddrs, %d nodes' %
          (len(recs), len({r['daddr'] for r in recs}),
           len({r['node'] for r in recs})))
    if p26s:
        print('\n--- P26-IGET-FAIL detections (dp/name/inum -> the loss sites):')
        seen = set()
        for node, dp, name, inum, err in p26s:
            k = (dp, name, inum)
            if k in seen:
                continue
            seen.add(k)
            print('  %s dp=%d name=%s inum=%d err=%d' % (node, dp, name, inum, err))
    by_daddr = {}
    for r in recs:
        by_daddr.setdefault(r['daddr'], []).append(r)
    hits = []
    for daddr, tl in by_daddr.items():
        tl.sort(key=lambda r: r['ns'])
        crcs, seen_crc, last = 0, {}, None
        prev_alloc = None
        flags = set()
        for i, r in enumerate(tl):
            if r['t'] == 0:
                alloc = r['mask'] & 0xffffffff
                if prev_alloc is not None and (alloc & ~prev_alloc):
                    # realloc of a freed slot by a DIFFERENT node than the
                    # freer is the co-resident signature worth reading
                    flags.add('slot-set-after-clear')
                prev_alloc = alloc
            if r['crc'] in seen_crc and last is not None and last != r['crc'] \
               and seen_crc[r['crc']] < i - 1:
                flags.add('CRC-REVERT')
            if r['crc'] not in seen_crc:
                seen_crc[r['crc']] = i
            last = r['crc']
            if r['t'] != 0 and r['gm'] == 0:
                flags.add('NONEX-WRITE')
        multi = len({r['node'] for r in tl}) > 1
        if flags and (multi or show_all):
            hits.append((daddr, len(tl), multi, flags))
    print('\n--- flagged daddrs (%s):' %
          ('all' if show_all else 'multi-node writers only'))
    for daddr, n, multi, flags in sorted(hits, key=lambda h: -h[1]):
        print('  daddr=%-12d writes=%-5d multi_node=%d  %s' %
              (daddr, n, multi, ','.join(sorted(flags))))
    if hits:
        print('\nrun with --daddr <N> (and --slot <S> for clusters) for the '
              'full merged timeline')

def main():
    args = sys.argv[1:]
    if not args:
        sys.exit(__doc__ or 'usage: d3_ring_analyze.py <harvest_dir> [--daddr N]')
    hdir, daddr, slot, show_all = args[0], None, None, False
    i = 1
    while i < len(args):
        if args[i] == '--daddr':
            daddr = int(args[i + 1]); i += 2
        elif args[i] == '--slot':
            slot = int(args[i + 1]); i += 2
        elif args[i] == '--all':
            show_all = True; i += 1
        else:
            sys.exit('unknown arg %s' % args[i])
    recs, p26s = parse(hdir)
    if daddr is not None:
        analyze_daddr(recs, daddr, slot)
    else:
        auto_scan(recs, p26s, show_all)

if __name__ == '__main__':
    main()
