#!/bin/bash
# inode_cluster_clobber_capture.sh — build the CLUSTER-WIDE, realns-ordered
# write timeline for one inode's 16KB inode-cluster buffer.
#
# WHY (ccloop c7ee71c6 sess27, D-DIRENT-INODE-TYPE-MISMATCH)
#   P170-CLWR prints, on every inode-cluster writeback, the whole cluster as
#   `ino:mode:gen` triples plus comm and realns.  realns is CLOCK-REAL and every
#   node is NTP-synced, so triples from all 32 nodes sort into one true total
#   order.  That makes "who published which incarnation of this inode, when"
#   directly readable — which is the only way to tell a stale-image CLOBBER
#   (an older gen landing after a newer one) from a legitimate reuse.
#
#   The measurement that motivated this: ino 10485888 was a DIRECTORY with
#   gen 2697616535, was FREED by test15 (EVICT-RING-FLAG freed_gen=2697616536,
#   so the free itself advanced the generation), and was then REUSED by test15
#   for a REGULAR FILE create (P9-NLEDGE reset4create).  The coherent platter
#   (P207-COHERENT-TRUTH, plain-bio read) nevertheless kept reporting
#   mode=040755 gen=2697616535 — an incarnation OLDER than its own free, which
#   a correct filesystem can never expose.  So the on-disk dinode, not the
#   dirent, is the corrupt side, and something wrote the pre-free image back.
#
# USAGE
#   tests/inode_cluster_clobber_capture.sh <ino> [nodecount]
#
# Scoping: per node, take dmesg from AFTER THE LAST MXFS_DIRENT_WINDOW marker.
# Never concatenate dmesg with journalctl to scope (the marker gets found in one
# source and the tail taken from both) — see state.md.
set -u
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO"

INO="${1:?usage: inode_cluster_clobber_capture.sh <ino> [nodecount]}"
N="${2:-32}"
OUT=$(mktemp -d)
echo "=== inode-cluster clobber timeline for ino=$INO across $N nodes ==="
echo "    scratch: $OUT"

for i in $(seq 1 "$N"); do
    n="test$i"
    timeout 90 tools/mxfs_sshpass.sh "$n" "
        L=\$(dmesg | grep -n MXFS_DIRENT_WINDOW | tail -1 | cut -d: -f1)
        if [ -n \"\$L\" ]; then dmesg | tail -n +\$((L+1)); else dmesg; fi \
        | grep -E 'P170-CLWR|EVICT-RING-FLAG|reset4create|P-DIRDW' \
        | grep -E '(^|[^0-9])$INO([^0-9]|\$)'
    " 2>/dev/null | grep -v -E 'Warning:|Unauthorized|authorized user' \
      > "$OUT/$n.raw" &
    # bound concurrency so 32 ssh sessions do not swamp the host
    while [ "$(jobs -rp | wc -l)" -ge 8 ]; do wait -n; done
done
wait

# Reduce to: realns  node  event  <ino>:mode:gen  comm
python3 - "$OUT" "$INO" <<'PY'
import sys, os, re, glob
d, ino = sys.argv[1], sys.argv[2]
rows = []
for f in sorted(glob.glob(os.path.join(d, '*.raw'))):
    node = os.path.basename(f)[:-4]
    for line in open(f, errors='replace'):
        m = re.search(r'realns=(\d+)', line)
        realns = int(m.group(1)) if m else None
        tok = ''
        mt = re.search(r'(?<![0-9])' + ino + r':(\d+):(\d+)', line)
        if mt:
            # P170-CLWR already prints di_mode in OCTAL text ("40755"), so
            # re-formatting it with :o double-converts (40755 -> 0117463) and
            # makes every mode unreadable.  Keep the field verbatim.
            tok = f'mode=0{mt.group(1)} gen=..{mt.group(2)}'
        else:
            mt = re.search(r'(incore_gen|freed_gen|gen)=(\d+)', line)
            if mt:
                tok = f'{mt.group(1)}={mt.group(2)}'
        cm = re.search(r'comm=(\S+)', line)
        ev = ('CLWR' if 'P170-CLWR' in line else
              'EVICT' if 'EVICT-RING-FLAG' in line else
              'CREATE' if 'reset4create' in line else
              'DIRDW' if 'P-DIRDW' in line else '?')
        # a CLWR that does not carry this ino's triple is noise
        if ev == 'CLWR' and not tok.startswith('mode='):
            continue
        rows.append((realns if realns is not None else 0, node, ev, tok,
                     cm.group(1) if cm else '-', line.rstrip()[:0]))
rows.sort(key=lambda r: r[0])
print(f'{"realns":>20} {"node":8} {"event":7} {"image":28} comm')
for realns, node, ev, tok, comm, _ in rows:
    print(f'{realns:>20} {node:8} {ev:7} {tok:28} {comm}')
print()
# Verdict: does an older gen land after a newer one?
seq = [(r[0], r[1], r[3]) for r in rows if r[3].startswith('mode=')]
gens = []
for realns, node, tok in seq:
    g = re.search(r'gen=\.\.(\d+)', tok)
    if g:
        gens.append((realns, node, int(g.group(1)), tok))
worst = None
for i in range(1, len(gens)):
    prev_max = max(g[2] for g in gens[:i])
    if gens[i][2] < prev_max:
        worst = (gens[i], prev_max)
        break
if worst:
    (realns, node, g, tok), pmax = worst
    print(f'VERDICT: CLOBBER — {node} published {tok} at realns={realns} '
          f'after gen ..{pmax} was already durable.  A live inode cannot '
          f'regress its generation.')
else:
    print('VERDICT: no generation regression among the captured cluster '
          'writes (either the clobber is outside the window, or the writes '
          'came from a source with no P170-CLWR).')
PY
