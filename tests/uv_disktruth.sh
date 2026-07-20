#!/bin/bash
# uv_disktruth.sh — decisive RULE-4 probe for the unlink_visibility blocker.
#
# Loops concurrent create+delete-own on a shared BLOCK-format dir until the
# per-node views DIVERGE (an outlier sees survivors the deleters don't).  Then,
# WITHOUT unmounting (which would flush the outlier's cache and contaminate the
# measurement), it forces a coherent re-read via a PEER POKE: a peer takes EX on
# the dir (touch + sync), which must BAST the outlier and the peer; both then
# re-read.  This fully disambiguates:
#
#   outlier=0 after poke            => READ-SIDE STALE (C): store is clean; the
#                                      outlier's pre-poke view was a stale cache
#                                      that the BAST refreshed.
#   outlier>0 AND poker(EX)=0        => REREAD STALE (B): even a fresh BAST+read
#                                      returns stale on the outlier (deep
#                                      SCST/initiator read-coherency gap).
#   outlier>0 AND poker(EX)>0        => DURABLE CLOBBER: a stale base was durably
#                                      written into the coherent store.
#
# Lives in the source tree per RULE 3.  Assumes the 4-node cluster is mounted.
set -u
cd "$(dirname "$0")/.."
NODES=(test1 test2 test3 test4)
PASS=/tmp/.mxfs_pass
SSH="bash tools/mxfs_sshpass.sh"
MNT=/mnt/shared
DIR=$MNT/.mxfs_test/uvdt
NPER=30
ITERS=${1:-6}

ssh_node() { timeout "${3:-40}" $SSH "$1" "$PASS" "$2" 2>/dev/null | grep -avE 'Warning|Unauthorized|authorized user'; }

count_on() { ssh_node "$1" "ls $DIR 2>/dev/null | grep -cE '^node[0-9]+_file'" 15 | tr -d ' '; }
surv_on()  { ssh_node "$1" "ls $DIR 2>/dev/null | grep -E '^node[0-9]+_file' | sort | tr '\n' ','" 15; }

for it in $(seq 1 "$ITERS"); do
  echo "===== ITER $it ====="
  ssh_node test1 "rm -rf $DIR; mkdir -p $DIR; sync" 25

  # concurrent create (host barrier)
  pids=()
  for idx in 0 1 2 3; do n=${NODES[$idx]}; id=$((idx+1))
    ssh_node "$n" "for i in \$(seq 1 $NPER); do echo x > $DIR/node${id}_file\$i; done; sync" 60 & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p"; done

  # concurrent delete-own (host barrier) — the contended phase
  pids=()
  for idx in 0 1 2 3; do n=${NODES[$idx]}; id=$((idx+1))
    ssh_node "$n" "for i in \$(seq 1 $NPER); do rm -f $DIR/node${id}_file\$i; done; sync" 60 & pids+=($!); done
  for p in "${pids[@]}"; do wait "$p"; done
  sleep 2

  # per-node view
  declare -A C
  div=""
  for n in "${NODES[@]}"; do C[$n]=$(count_on "$n"); done
  echo "  views: t1=${C[test1]} t2=${C[test2]} t3=${C[test3]} t4=${C[test4]}"
  # outlier = the node with the max count, if > min
  mx=test1; for n in "${NODES[@]}"; do [ "${C[$n]:-0}" -gt "${C[$mx]:-0}" ] && mx=$n; done
  mn=test1; for n in "${NODES[@]}"; do [ "${C[$n]:-0}" -lt "${C[$mn]:-0}" ] && mn=$n; done
  if [ "${C[$mx]:-0}" -gt "${C[$mn]:-0}" ]; then div=1; fi

  if [ -z "$div" ]; then echo "  (no divergence this iter)"; continue; fi

  OUT=$mx
  echo "  *** DIVERGENCE: outlier=$OUT count=${C[$OUT]} survivors=[$(surv_on "$OUT")]"
  # pick a poker peer != outlier
  POKE=test2; [ "$POKE" = "$OUT" ] && POKE=test3
  echo "  -- peer poke: $POKE takes EX (touch+sync) to force BAST on $OUT --"
  ssh_node "$POKE" "touch $DIR/.poke_$it; sync" 25
  sleep 2
  oc=$(count_on "$OUT"); pc=$(count_on "$POKE")
  echo "  -- after poke: outlier($OUT)=$oc  poker($POKE,EX)=$pc"
  echo
  echo "  ===== VERDICT ====="
  if [ "${oc:-x}" = "0" ]; then
    echo "  READ-SIDE STALE (C): store clean; BAST refreshed the outlier. Fix = invalidate the outlier's cached dir block when a peer modifies (the missing cross-node BAST/gen-bump)."
  elif [ "${pc:-x}" = "0" ]; then
    echo "  REREAD STALE (B): outlier still $oc after a fresh BAST+read while authoritative EX peer sees 0 => deep SCST/initiator read-coherency gap on the outlier."
  else
    echo "  DURABLE CLOBBER: poker(EX)=$pc => a stale base was durably written into the store."
  fi
  exit 0
done
echo "No divergence in $ITERS iters — race not hit (try more iters or the real harness)."
