#!/bin/bash
# mount_degrade_probe.sh — quantify D-MOUNT-DEGRADES-WITH-USE per node.
#
# sess25 REPRODUCED the defect with a clean paired measurement: on the SAME
# build and cluster, cache_coherency and dlm_fairness PASS on a fresh prep
# (35s/60s, 26s/30s) and both TIME OUT at their budget after ONE
# dirent_durability storm on that mount.  A second run on the same prep is
# still fast, so it is not cumulative age and not "any prior work" — it is a
# heavy storm specifically.  (That also explains why sustained_load was refuted
# as the detector in sess22: sustained_load is not a storm.)
#
# What this adds: the criteria only say "nobody reached the barrier", which
# cannot distinguish EVERY node being slower from ONE straggler holding the
# barrier.  This times the same three primitive operations on every node
# independently, with no barrier and no coordination, so the per-node
# distribution is visible.
#
#   private  — mkdir/rmdir in this node's OWN directory (no cross-node
#              contention at all; isolates node-local cost)
#   shared   — mkdir/rmdir in ONE directory all nodes share (adds the
#              contended-parent cost, cf. D-32NODE-SHARED-DIR-CREATE-PACE)
#   statfs   — pure filesystem service call, no namespace mutation
#
# Run it on a fresh prep, then after a storm, and compare.
#
# Usage: tests/mount_degrade_probe.sh <N> [label] [iters] [mnt]
set -u
N="${1:?node count}"; LABEL="${2:-probe}"; IT="${3:-20}"; MNT="${4:-/mnt/shared}"
REPO=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
SSH="$REPO/tools/mxfs_sshpass.sh"
SH="$MNT/.degrade_shared"
OUT=$(mktemp -d)

timeout 40 "$SSH" test1 "mkdir -p $SH" >/dev/null 2>&1

for i in $(seq 1 "$N"); do
  (
    r=$(timeout 90 "$SSH" "test$i" "
      P=$MNT/.degrade_priv_\$(hostname); mkdir -p \$P
      ms() { echo \"scale=1; (\$2 - \$1) / 1000000\" | bc; }
      # private
      a=\$(date +%s%N); for k in \$(seq 1 $IT); do mkdir -p \$P/d\$k 2>/dev/null; rmdir \$P/d\$k 2>/dev/null; done; b=\$(date +%s%N)
      priv=\$(ms \$a \$b)
      # shared parent
      a=\$(date +%s%N); for k in \$(seq 1 $IT); do mkdir -p $SH/\$(hostname)_\$k 2>/dev/null; rmdir $SH/\$(hostname)_\$k 2>/dev/null; done; b=\$(date +%s%N)
      shr=\$(ms \$a \$b)
      # statfs only
      a=\$(date +%s%N); for k in \$(seq 1 $IT); do stat -f $MNT >/dev/null 2>&1; done; b=\$(date +%s%N)
      sf=\$(ms \$a \$b)
      echo \"\$priv \$shr \$sf\"" 2>/dev/null)
    printf '%s %s\n' "test$i" "${r:-NA NA NA}" > "$OUT/n$i"
  ) &
done
wait

echo "=== mount_degrade_probe label=$LABEL nodes=$N iters=$IT (ms for $IT mkdir+rmdir pairs) ==="
cat "$OUT"/n* 2>/dev/null | sort -k2 -g > "$OUT/all"
while read -r nm a b c; do printf '  %-8s private=%-9s shared=%-9s statfs=%s\n' "$nm" "$a" "$b" "$c"; done < "$OUT/all"
python3 - "$OUT/all" <<'PYEOF'
import sys
rows=[l.split() for l in open(sys.argv[1]) if l.strip()]
cols={'private':1,'shared':2,'statfs':3}
print()
print("  %-8s %8s %8s %8s %8s" % ("metric","min","median","max","max/min"))
for nm,i in cols.items():
    v=sorted(float(r[i]) for r in rows if len(r)>i and r[i] not in ('NA',''))
    if not v: continue
    lo,hi,med=v[0],v[-1],v[len(v)//2]
    print("  %-8s %8.1f %8.1f %8.1f %8.1f" % (nm,lo,med,hi,(hi/lo if lo else 0)))
PYEOF
echo "raw: $OUT"
