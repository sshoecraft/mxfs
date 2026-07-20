#!/bin/bash
# diag_rv_replay.sh — decomposed replay of cache_coherency's rename_visibility
# subtest outside run.sh (ccloop 12e0d157 sess8).  Each invocation runs ONE
# phase on all N nodes in parallel (common +8s start), with:
#   * per-node walls + per-op timings written NODE-LOCALLY to /tmp/rv_phase.log
#     and /tmp/rv_slow.log (survive driver-side ssh timeouts)
#   * create/rename phases time their trailing sync SEPARATELY
#   * verify times each sub-op class separately (neg-lookup / stat / read) and
#     splits the read primitive BY RANK PARITY: odd ranks use cat (relatime
#     atime-update transactions fire), even ranks use dd iflag=noatime — a
#     same-run A/B of the atime-EX effect in the hot window.
#   * 'harvest' phase pulls both logs from every node.
#
# Usage: diag_rv_replay.sh <N> <create|rename|verify|harvest|clean> <tag> [cap]
set -u
N="${1:?usage: diag_rv_replay.sh <N> <phase> <tag> [cap]}"
PHASE="${2:?phase}"
TAG="${3:?dir tag}"
CAP="${4:-240}"
REPO=/src/mxfs
SSH="$REPO/tools/mxfs_sshpass.sh"; PF=/tmp/.mxfs_pass
MNT=/mnt/shared
D="$MNT/.rv_replay_$TAG"
START=$(( $(date +%s) + 8 ))
NF=20

body_create() { cat <<EOS
mkdir -p $D 2>/dev/null
: > /tmp/rv_slow.log
while [ \$(date +%s) -lt $START ]; do sleep 0.2; done
t0=\$(date +%s.%N)
for i in \$(seq 1 $NF); do
  o0=\$(date +%s.%N)
  echo "content_RANK_\${i}" > $D/nodeRANK_before_\${i}
  o1=\$(date +%s.%N)
  d=\$(awk "BEGIN{printf \"%.3f\", \$o1-\$o0}")
  awk "BEGIN{exit !(\$d>0.2)}" && echo "SLOW create i=\${i} \${d}s" >> /tmp/rv_slow.log
done
t1=\$(date +%s.%N)
# NOTE: no sync here — the real test's rv_create phase has none; the rename
# phase measures the post-burst sync separately.
echo "phase=create rank=RANK creates=\$(awk "BEGIN{printf \"%.1f\", \$t1-\$t0}")" >> /tmp/rv_phase.log
tail -1 /tmp/rv_phase.log
EOS
}
body_rename() { cat <<EOS
while [ \$(date +%s) -lt $START ]; do sleep 0.2; done
t0=\$(date +%s.%N)
for i in \$(seq 1 $NF); do
  o0=\$(date +%s.%N)
  mv $D/nodeRANK_before_\${i} $D/nodeRANK_after_\${i}
  o1=\$(date +%s.%N)
  d=\$(awk "BEGIN{printf \"%.3f\", \$o1-\$o0}")
  awk "BEGIN{exit !(\$d>0.2)}" && echo "SLOW rename i=\${i} \${d}s" >> /tmp/rv_slow.log
done
t1=\$(date +%s.%N)
sync
t2=\$(date +%s.%N)
echo "phase=rename rank=RANK renames=\$(awk "BEGIN{printf \"%.1f\", \$t1-\$t0}") sync=\$(awk "BEGIN{printf \"%.1f\", \$t2-\$t1}")" >> /tmp/rv_phase.log
tail -1 /tmp/rv_phase.log
EOS
}
body_verify() { cat <<EOS
if [ \$(( RANK % 2 )) -eq 1 ]; then RMODE=cat; else RMODE=noatime; fi
while [ \$(date +%s) -lt $START ]; do sleep 0.2; done
t0=\$(date +%s.%N)
tneg=0; tstat=0; tread=0
for n in \$(seq 1 $N); do
  for i in \$(seq 1 $NF); do
    a=\$(date +%s.%N)
    test ! -e $D/node\${n}_before_\${i}
    b=\$(date +%s.%N)
    test -f $D/node\${n}_after_\${i}
    c=\$(date +%s.%N)
    if [ "\$RMODE" = cat ]; then
      cat $D/node\${n}_after_\${i} >/dev/null 2>&1
    else
      dd if=$D/node\${n}_after_\${i} iflag=noatime of=/dev/null bs=64k status=none 2>/dev/null
    fi
    e=\$(date +%s.%N)
    read dn ds dr <<<\$(awk "BEGIN{printf \"%.3f %.3f %.3f\", \$b-\$a, \$c-\$b, \$e-\$c}")
    tneg=\$(awk "BEGIN{printf \"%.3f\", \$tneg+\$dn}")
    tstat=\$(awk "BEGIN{printf \"%.3f\", \$tstat+\$ds}")
    tread=\$(awk "BEGIN{printf \"%.3f\", \$tread+\$dr}")
    awk "BEGIN{exit !(\$dn>0.2 || \$ds>0.2 || \$dr>0.2)}" && \
      echo "SLOW verify n=\${n} i=\${i} neg=\${dn} stat=\${ds} read=\${dr} mode=\$RMODE" >> /tmp/rv_slow.log
  done
done
t1=\$(date +%s.%N)
echo "phase=verify rank=RANK mode=\$RMODE wall=\$(awk "BEGIN{printf \"%.1f\", \$t1-\$t0}") neg=\$tneg stat=\$tstat read=\$tread" >> /tmp/rv_phase.log
tail -1 /tmp/rv_phase.log
EOS
}

case "$PHASE" in
    create) B=$(body_create) ;;
    rename) B=$(body_rename) ;;
    verify) B=$(body_verify) ;;
    harvest)
        for r in $(seq 1 "$N"); do
            echo "--- test$r ---"
            timeout 20 "$SSH" "test$r" "$PF" "cat /tmp/rv_phase.log 2>/dev/null; grep -c SLOW /tmp/rv_slow.log 2>/dev/null | sed 's/^/slow_ops=/'" 2>/dev/null
        done
        exit 0 ;;
    clean)
        timeout "$CAP" "$SSH" test1 "$PF" "rm -rf $D; sync; echo CLEANED" 2>/dev/null | grep CLEANED
        exit 0 ;;
    *) echo "bad phase"; exit 2 ;;
esac

echo "=== rv_replay phase=$PHASE N=$N dir=$D cap=${CAP}s ==="
tmpd=$(mktemp -d)
for r in $(seq 1 "$N"); do
    ( timeout "$CAP" "$SSH" "test$r" "$PF" "${B//RANK/$r}" \
        2>/dev/null | grep -E '^phase=' > "$tmpd/$r" ) &
done
wait
done_n=0
for r in $(seq 1 "$N"); do
    line=$(cat "$tmpd/$r" 2>/dev/null)
    if [ -n "$line" ]; then done_n=$((done_n+1)); echo "  $line"
    else echo "  test$r: NO-REPORT(>${CAP}s — still running node-side; see harvest)"
    fi
done
echo "=== phase=$PHASE reported=$done_n/$N (node-local logs authoritative: run harvest) ==="
rm -rf "$tmpd"
