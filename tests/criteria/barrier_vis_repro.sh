#!/bin/bash
# barrier_vis_repro.sh — minimal reproducer for the 16-node "all-done"
# barrier-visibility gap that makes posix_semantics(16) blow its budget.
#
# Mirrors tests/lib/cluster.sh barrier_signal/barrier_wait exactly:
# every node touches $BAR/node$i in a SHARED directory, then polls
# `find $BAR -name 'node*' | wc -l` once a second until it sees all N
# or times out.  Reports, per node, the time-to-see-all and (on
# timeout) WHICH node numbers are missing from its view.  This pins
# down whether a specific creator's dirent never propagates, and to
# whom — without the 32-test suite around it.
#
# Assumes the cluster is already mounted on test1..testN at $MXFS_MOUNT
# (run tests/reset4.sh N first).  Pass N as $1 (default 16).
set -u
SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
source "$SCRIPT_DIR/lib.sh"

N=${1:-16}
ROUNDS=${2:-1}
NODES=("${DEFAULT_NODES[@]:0:$N}")
W="$MXFS_SSH"; P="$MXFS_PASS"
TO=${BARRIER_TIMEOUT:-30}

for r in $(seq 1 "$ROUNDS"); do
  BAR="$MXFS_MOUNT/.bvr/round${r}"
  echo "=== round $r: barrier dir $BAR, N=$N, timeout=${TO}s precreate=${PRECREATE:-0} $(date -u +%T) ==="
  # clean the barrier dir from node1.  PRECREATE=1 => node1 also mkdirs it
  # (decouples the race).  PRECREATE=0 (default) => each node mkdir -p's it
  # concurrently, exactly like cluster.sh barrier_signal.
  if [ "${PRECREATE:-0}" = "1" ]; then
    timeout 15 "$W" "${NODES[0]}.vm.localdomain" "$P" \
      "rm -rf $MXFS_MOUNT/.bvr/round${r}; mkdir -p $BAR; sync" >/dev/null 2>&1
  else
    timeout 15 "$W" "${NODES[0]}.vm.localdomain" "$P" \
      "rm -rf $MXFS_MOUNT/.bvr/round${r}; mkdir -p $MXFS_MOUNT/.bvr; sync" >/dev/null 2>&1
  fi

  # Optional create-burst phase BEFORE the barrier, to replicate the real
  # test sequence (concurrent_touch: ready-barrier, BURST 100 files/node in
  # one shared data dir, THEN the create_done barrier that times out).
  BURST=${BURST:-0}
  DATADIR="$MXFS_MOUNT/.bvr/data${r}"
  if [ "$BURST" -gt 0 ]; then
    timeout 15 "$W" "${NODES[0]}.vm.localdomain" "$P" \
      "rm -rf $DATADIR; mkdir -p $DATADIR; sync" >/dev/null 2>&1
    echo "--- burst: $BURST files/node into shared $DATADIR $(date -u +%T) ---"
    bpids=()
    for idx in "${!NODES[@]}"; do
      i=$((idx+1)); h="${NODES[$idx]}.vm.localdomain"
      timeout 200 "$W" "$h" "$P" "
        t0=\$(date +%s%N)
        for k in \$(seq 1 $BURST); do touch $DATADIR/node${i}_f\$k; done
        echo \"node$i burst_done \$(( (\$(date +%s%N)-t0)/1000000 ))ms\"
      " > "/tmp/bvr_burst_${r}_node${i}.out" 2>&1 &
      bpids+=($!)
    done
    for pid in "${bpids[@]}"; do wait "$pid" 2>/dev/null; done
    for i in $(seq 1 "$N"); do grep -h burst_done "/tmp/bvr_burst_${r}_node${i}.out" 2>/dev/null; done
  fi

  pids=(); declare -A LOG
  for idx in "${!NODES[@]}"; do
    i=$((idx+1)); h="${NODES[$idx]}.vm.localdomain"; lf="/tmp/bvr_${r}_node${i}.out"
    LOG[$i]="$lf"
    # each node: barrier_signal (mkdir -p + touch, exactly like cluster.sh)
    # then barrier_wait, logging missing set on timeout
    timeout $((TO+20)) "$W" "$h" "$P" "
      mkdir -p $BAR 2>/dev/null
      touch $BAR/node$i
      t0=\$(date +%s%N)
      el=0
      while [ \$el -lt $TO ]; do
        c=\$(find $BAR -maxdepth 1 -name 'node*' 2>/dev/null | wc -l)
        if [ \$c -ge $N ]; then
          ms=\$(( (\$(date +%s%N)-t0)/1000000 ))
          echo \"node$i SAW_ALL in \${ms}ms\"; exit 0
        fi
        sleep 1; el=\$((el+1))
      done
      have=\$(find $BAR -maxdepth 1 -name 'node*' -printf '%f\n' 2>/dev/null | sed 's/node//' | sort -n | tr '\n' ',')
      echo \"node$i TIMEOUT after ${TO}s saw=\$(find $BAR -name 'node*'|wc -l)/$N have=[\$have]\"
    " > "$lf" 2>&1 &
    pids+=($!)
  done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
  echo "--- results round $r ---"
  for i in $(seq 1 "$N"); do grep -hE 'SAW_ALL|TIMEOUT' "${LOG[$i]}" 2>/dev/null; done
  echo "--- ground truth: actual dirents on disk (from node1, fresh) ---"
  timeout 15 "$W" "${NODES[0]}.vm.localdomain" "$P" \
    "find $BAR -maxdepth 1 -name 'node*' -printf '%f\n' 2>/dev/null | sed 's/node//' | sort -n | tr '\n' ',' ; echo" 2>&1 | grep -v 'Warning\|Unauthorized\|disconnect'
done
