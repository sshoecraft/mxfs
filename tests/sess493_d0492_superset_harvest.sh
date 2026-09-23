#!/bin/bash
# sess493: harvest of the D-0492 superset discriminator
# (D-NEWTENURE-RETIRE-DROPS-INAIL-LOGITEM-OF-COMMITTED-UNWRITTEN-DIR-BLOCK-WITHOUT-WRITE-0492)
#
# The 0.70.9 probe P491-NEWTENURE-RETIRE-UNDEST carries, per retire of a
# committed-unwritten directory block, disk_match= (byte equality with a plain
# read of the LUN), superset= (every live entry of the in-core block present by
# name on the platter: 1 yes, 0 no, -1 not a data/block-format dir block or not
# compared) and missing= (how many are absent).  A retire with superset=0 is an
# obligation dropped: committed entries the LUN has never seen lose their log
# item without a write.  Split by new_tenure and by wseq=0 (never written in
# this tenure) because those are the two arms the retire's argument rests on.
#
# Usage: tests/sess493_d0492_superset_harvest.sh tests/evidence/sess491_evict_undest_s493a
set -u
O=${1:?usage: $0 <evidence dir with ctx_*.gz>}
[ -d "$O" ] || { echo "no such dir: $O"; exit 1; }
zcat "$O"/ctx_*.gz 2>/dev/null | grep -a 'P491-NEWTENURE-RETIRE-UNDEST' > "$O/newtenure_lines.txt"
nwith=0; for f in "$O"/ctx_*.gz; do zcat "$f" 2>/dev/null | grep -aq 'P491-NEWTENURE-RETIRE-UNDEST' && nwith=$((nwith + 1)); done
echo "lines=$(wc -l < "$O/newtenure_lines.txt") nodes_with_lines=$nwith cc_fail=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -ac 'mxfs-cc-FAIL') shutdown=$(zcat "$O"/ctx_*.gz 2>/dev/null | grep -aci 'shut down')"
python3 - "$O/newtenure_lines.txt" <<'EOF'
import re, sys, collections
fields = re.compile(r'(\w+)=(-?\d+|[^\s]+)')
rows = []
for line in open(sys.argv[1], errors='replace'):
    d = dict(fields.findall(line))
    if 'superset' not in d:
        continue
    rows.append(d)
print(f"parsed={len(rows)}")
def hist(key, rows):
    c = collections.Counter(key(r) for r in rows)
    return ' '.join(f"{k}:{v}" for k, v in sorted(c.items()))
print("superset histogram (all):", hist(lambda r: r['superset'], rows))
print("disk_match histogram (all):", hist(lambda r: r['disk_match'], rows))
print("by new_tenure -> superset:", hist(lambda r: (r['new_tenure'], r['superset']), rows))
print("by wseq==0 -> superset:", hist(lambda r: ('wseq0' if r['wseq'] == '0' else 'wseq>0', r['superset']), rows))
print("by ops -> superset:", hist(lambda r: (r.get('ops', '?'), r['superset']), rows))
print("by in_ail,pin -> superset:", hist(lambda r: (r['in_ail'], r['pin'], r['superset']), rows))
# Which arm justified the retire?  new_tenure, or the block's dir epoch behind
# the current master epoch, or the grant-gen stamp behind the cached grant gen.
# A block whose b_epoch == cur_mep was logged IN this tenure: nothing prior
# could have drained it.
def arm(r):
    cur = r['b_epoch'] == r['cur_mep']
    return ('b_epoch==cur_mep' if cur else 'b_epoch<cur_mep',
            'ggen==' if r['b_grant_gen'] == r['cached_grant_gen'] else 'ggen!=')
print("by (epoch arm, grant-gen arm) -> superset:", hist(lambda r: arm(r) + (r['superset'],), rows))
print("by (epoch arm, grant-gen arm, new_tenure) -> superset (data blocks only):",
      hist(lambda r: arm(r) + (r['new_tenure'], r['superset']), [r for r in rows if r.get('ops') == 'xfs_dir3_data']))
bad = [r for r in rows if r['superset'] == '0']
print(f"superset=0 rows={len(bad)} missing histogram:", hist(lambda r: r['missing'], bad))
print("superset=0 by (new_tenure, wseq0, mode, gmode):", hist(lambda r: (r['new_tenure'], 'wseq0' if r['wseq'] == '0' else 'wseq>0', r['mode'], r['gmode']), bad))
print("superset=0 distinct inodes:", len({r['ino'] for r in bad}), "distinct daddr:", len({r['daddr'] for r in bad}))
print("superset=0 by comm:", hist(lambda r: r.get('comm', '?'), bad))
EOF
echo "--- sample superset=0 lines (first 6) ---"
grep -a 'superset=0 ' "$O/newtenure_lines.txt" | cut -c1-330 | head -6
echo "--- sample superset=1 lines (first 3) ---"
grep -a 'superset=1 ' "$O/newtenure_lines.txt" | cut -c1-330 | head -3
