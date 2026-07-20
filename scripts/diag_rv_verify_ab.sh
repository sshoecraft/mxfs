#!/bin/bash
# diag_rv_verify_ab.sh — A/B probe for the cache_coherency@N rv_verify
# slowness (ccloop 12e0d157 sess8): replay the test's rename_visibility
# verify loop on ALL nodes concurrently against the residue left in
# $MNT/.cache_coherency/rename_visibility by a (failed) run, with the read
# primitive switchable:
#   noatime : dd iflag=noatime  — no relatime atime-update transactions
#   cat     : cat               — relatime fires an atime write per file
#             whose atime < ctime (every file right after a rename)
# If 'noatime' completes fast and 'cat' is slow, the verify wall is the
# cluster-wide inode-EX storm from read-triggered atime updates.
#
# Usage: diag_rv_verify_ab.sh <N> <noatime|cat> <cap_seconds>
# Output: per-node wall seconds (or TIMEOUT) + test1 per-op max/histogram.
set -u
N="${1:?usage: diag_rv_verify_ab.sh <N> <noatime|cat> <cap>}"
MODE="${2:?mode: noatime|cat}"
CAP="${3:-240}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared
D="$MNT/.cache_coherency/rename_visibility"
START=$(( $(date +%s) + 12 ))   # common start moment for all nodes

case "$MODE" in
    noatime) READ='dd if=FILE iflag=noatime of=/dev/null bs=64k status=none' ;;
    cat)     READ='cat FILE >/dev/null' ;;
    *) echo "bad mode $MODE"; exit 2 ;;
esac

body() {  # emitted per node; RANK substituted
    cat <<EOS
sync; echo 3 > /proc/sys/vm/drop_caches
while [ \$(date +%s) -lt $START ]; do sleep 0.2; done
t0=\$(date +%s.%N)
ops=0
for n in \$(seq 1 $N); do
  for i in \$(seq 1 20); do
    test ! -e $D/node\${n}_before_\${i}
    test -f $D/node\${n}_after_\${i}
    ${READ//FILE/$D/node\${n}_after_\${i}}
    ops=\$((ops+3))
  done
done
t1=\$(date +%s.%N)
echo "RANK=RANKSUB wall=\$(awk "BEGIN{printf \"%.1f\", \$t1-\$t0}") ops=\$ops"
EOS
}

echo "=== rv_verify A/B mode=$MODE N=$N cap=${CAP}s start=+12s ==="
tmpd=$(mktemp -d)
for r in $(seq 1 "$N"); do
    ( timeout "$CAP" "$SSH" "test$r" "$PF" "$(body | sed "s/RANKSUB/$r/")" \
        2>/dev/null | grep -E '^RANK=' > "$tmpd/$r" ) &
done
wait
done_n=0; sum=0; max=0
for r in $(seq 1 "$N"); do
    line=$(cat "$tmpd/$r" 2>/dev/null)
    if [ -n "$line" ]; then
        w=$(sed 's/.*wall=\([0-9.]*\).*/\1/' <<<"$line")
        done_n=$((done_n+1))
        awk "BEGIN{exit !($w > $max)}" && max="$w"
        sum=$(awk "BEGIN{printf \"%.1f\", $sum+$w}")
        echo "  test$r: ${w}s"
    else
        echo "  test$r: TIMEOUT(>${CAP}s)"
    fi
done
echo "=== mode=$MODE done=$done_n/$N max=${max}s mean=$(awk "BEGIN{if($done_n)printf \"%.1f\", $sum/$done_n; else print \"n/a\"}")s ==="
rm -rf "$tmpd"
