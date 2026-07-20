#!/bin/bash
# repro_tds.sh — tight reproducer for the tcp_dlm_scaling shared-dir lost-update
# residual.  Two nodes concurrently create->rename->remove their OWN entries in
# a SHARED dir; after both drain, the dir MUST be empty on BOTH nodes.
#
# Reports, per failing iter, the n1/n2 split (read-side staleness shows as one
# node non-zero while the other is zero) and which entries leaked.
#
# Usage: repro_tds.sh [ITERS] [ROUNDS]
set -u
SSH=/src/mxfs/tools/mxfs_sshpass.sh
P=/tmp/.mxfs_pass
MNT=/mnt/shared
D="$MNT/.tds_repro"
ITERS="${1:-20}"
ROUNDS="${2:-300}"

run() { "$SSH" "$1" "$P" "$2" 2>&1 | grep -vE '^Warning:|^Unauthorized|^If you'; }

cat > /tmp/tds_churn.sh <<'EOF'
D=/mnt/shared/.tds_repro; R=$1; N=$2
for r in $(seq 1 $N); do
  f="$D/n${R}_r${r}"
  echo $r > "$f" 2>/dev/null && mv "$f" "$f.done" 2>/dev/null && rm -f "$f.done" 2>/dev/null
done
sync
EOF
for n in test1 test2; do "$SSH" "$n" "$P" 'cat > /tmp/tds_churn.sh' < /tmp/tds_churn.sh 2>/dev/null; done

pass=0; fail=0
for it in $(seq 1 "$ITERS"); do
  # Clean from BOTH nodes (a durable split-brain entry is only visible/
  # deletable from the node that holds it) so each iter starts truly empty.
  run test1 "mkdir -p $D; find $D -mindepth 1 -delete 2>/dev/null; sync" >/dev/null
  run test2 "find $D -mindepth 1 -delete 2>/dev/null; sync" >/dev/null
  run test1 "find $D -mindepth 1 -delete 2>/dev/null; sync; echo 3 > /proc/sys/vm/drop_caches" >/dev/null
  run test2 "echo 3 > /proc/sys/vm/drop_caches" >/dev/null
  run test1 "bash /tmp/tds_churn.sh 1 $ROUNDS" >/dev/null &
  run test2 "bash /tmp/tds_churn.sh 2 $ROUNDS" >/dev/null &
  wait
  n1=$(run test1 "sync; echo 3 > /proc/sys/vm/drop_caches; echo CNT=\$(ls -A $D 2>/dev/null | wc -l)" | sed -n 's/.*CNT=\([0-9]*\).*/\1/p')
  n2=$(run test2 "sync; echo 3 > /proc/sys/vm/drop_caches; echo CNT=\$(ls -A $D 2>/dev/null | wc -l)" | sed -n 's/.*CNT=\([0-9]*\).*/\1/p')
  if [ "${n1:-x}" = 0 ] && [ "${n2:-x}" = 0 ]; then
    pass=$((pass+1)); echo "iter $it: PASS"
  else
    fail=$((fail+1)); echo "iter $it: FAIL n1=$n1 n2=$n2"
    echo "  n1 leaked: $(run test1 "ls -A $D 2>/dev/null | sort | tr '\n' ' ' | cut -c1-160")"
    echo "  n2 leaked: $(run test2 "ls -A $D 2>/dev/null | sort | tr '\n' ' ' | cut -c1-160")"
    # settle re-check (does it self-heal?)
    n1b=$(run test1 "sync; echo 3 > /proc/sys/vm/drop_caches; echo CNT=\$(ls -A $D 2>/dev/null | wc -l)" | sed -n 's/.*CNT=\([0-9]*\).*/\1/p')
    echo "  n1 after re-read: $n1b"
    # Force a cross-node BAST: node1 does an EX op on D (create+remove a probe),
    # which should demote node2 and force it to reload on its next read.
    run test1 "touch $D/.probe_bast 2>/dev/null; rm -f $D/.probe_bast 2>/dev/null; sync" >/dev/null
    n2c=$(run test2 "sync; echo 3 > /proc/sys/vm/drop_caches; echo CNT=\$(ls -A $D 2>/dev/null | wc -l)" | sed -n 's/.*CNT=\([0-9]*\).*/\1/p')
    echo "  n2 after node1-BAST reload: $n2c  (>0 => DURABLE on disk; 0 => node2 in-core stale)"
  fi
done
echo "=== TALLY pass=$pass fail=$fail / $ITERS (rounds=$ROUNDS) ==="
