#!/bin/bash
# fairness_optime.sh — WHERE does dlm_fairness's time go? (sess6 ccloop 72513a13)
#
# Reproduces the dlm_fairness churn shape (create+mv+rm of per-node entries in
# ONE shared dir, all nodes concurrent) with PER-OP microsecond timing, for a
# fixed wall window.  Reports per-node op counts, per-op-type latency
# percentiles, the slowest individual ops, and dmesg probe deltas in the
# window.  Distinguishes "every handoff uniformly slow" from "bimodal: mostly
# fast + convoy stalls".
#
# Usage: tests/fairness_optime.sh [NNODES=8] [WINDOW_S=25]
set -u
cd "$(dirname "$0")/.."
PASS=/tmp/.mxfs_pass; SSH=tools/mxfs_sshpass.sh
N=${1:-8}; W=${2:-25}
D=/mnt/shared/.fair_diag
OUT=/tmp/fair_optime_agg; rm -rf "$OUT"; mkdir -p "$OUT"

s(){ timeout $((W+90)) "$SSH" "$1" "$PASS" "$2" 2>&1 | grep -vE 'Warning|Unauthorized|authorized user|disconnect immediately'; }

s test1 "rm -rf $D; mkdir -p $D; sync; stat -c 'DIRINO=%i' $D"
echo "== launching $N-node churn, ${W}s window =="
for r in $(seq 1 "$N"); do
  (
    s "test$r" "
      echo FAIR_OPTIME_START > /dev/kmsg
      exec 9>/tmp/fair_optime.log
      endus=\$(( \${EPOCHREALTIME/./} + $W*1000000 ))
      i=0
      while [ \${EPOCHREALTIME/./} -lt \$endus ]; do
        i=\$((i+1)); f=$D/n${r}_\$i
        t0=\${EPOCHREALTIME/./}; echo \$i > \$f; t1=\${EPOCHREALTIME/./}
        mv \$f \$f.d 2>/dev/null; t2=\${EPOCHREALTIME/./}
        rm -f \$f.d; t3=\${EPOCHREALTIME/./}
        echo \"\$i c \$t0 \$((t1-t0))\" >&9
        echo \"\$i m \$t1 \$((t2-t1))\" >&9
        echo \"\$i r \$t2 \$((t3-t2))\" >&9
      done
      echo FAIR_OPTIME_END rounds=\$i > /dev/kmsg
      echo NODE${r}_ROUNDS=\$i
      cat /tmp/fair_optime.log
    " > "$OUT/n$r.raw"
  ) &
done
wait
echo "== per-node summary =="
for r in $(seq 1 "$N"); do
  grep "^NODE${r}_ROUNDS" "$OUT/n$r.raw"
  grep -E '^[0-9]+ [cmr] ' "$OUT/n$r.raw" > "$OUT/n$r.ops"
done
echo "== latency percentiles (us) by op type, ALL nodes combined =="
for op in c m r; do
  awk -v op=$op '$2==op{print $4}' "$OUT"/n*.ops | sort -n > "$OUT/lat_$op"
  awk -v op=$op 'BEGIN{c=0} {v[c++]=$1; s+=$1}
    END{ if(!c){print op": none"; exit}
      printf "%s: n=%d p50=%d p90=%d p99=%d max=%d mean=%d total_s=%.1f\n",
        op, c, v[int(c*0.50)], v[int(c*0.90)], v[int(c*0.99)], v[c-1], s/c, s/1000000 }' "$OUT/lat_$op"
done
echo "== slowest 12 ops overall (node op start_us dur_us) =="
for r in $(seq 1 "$N"); do awk -v n=$r '{print n, $2, $3, $4}' "$OUT/n$r.ops"; done \
  | sort -k4 -n -r | head -12
echo "== stall census: ops >100ms per node/type =="
for r in $(seq 1 "$N"); do
  awk -v n=$r '$4>100000{t[$2]++; tot++} END{if(tot) printf "node%d: tot=%d c=%d m=%d r=%d\n", n, tot, t["c"], t["m"], t["r"]}' "$OUT/n$r.ops"
done
echo "== dmesg probe deltas in window (per node) =="
for r in $(seq 1 "$N"); do
  s "test$r" "dmesg | awk '/FAIR_OPTIME_START/{found=NR} found&&NR>=found' | grep -c 'P70-BP ENTRY' | xargs echo node$r P70_ENTRY=;
     dmesg | awk '/FAIR_OPTIME_START/{found=NR} found&&NR>=found' | grep -cE 'P15-REL-ABORT' | xargs echo node$r P15_ABORT=;
     dmesg | awk '/FAIR_OPTIME_START/{found=NR} found&&NR>=found' | grep -cE 'P15-ORPH-PROCEED' | xargs echo node$r P15_PROCEED=;
     dmesg | awk '/FAIR_OPTIME_START/{found=NR} found&&NR>=found' | grep -cE 'P-WAIT-EXTEND' | xargs echo node$r WAIT_EXTEND=" &
done
wait
s test1 "rm -rf $D; sync"
echo "raw per-op logs: $OUT/n*.ops"
